"""阿里云云解析（Alidns）实现 —— 只覆盖 DNS-01 需要的那几个动作。

为什么不用官方 SDK：
签发链路原本只依赖 cryptography，为了加一条 TXT 记录装一整套 SDK 并不划算。
云解析是 RPC 风格接口，签名是 HMAC-SHA1，标准库足够，签名算法已在
_RPC 部分按官方文档实现并用官方示例向量校验过。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

from . import DnsError, DnsProvider

API_VERSION = "2015-01-09"
DEFAULT_ENDPOINT = "https://alidns.aliyuncs.com/"
USER_AGENT = "LetsEncryptTool/1.0 (dns-aliyun)"

# 常见错误码 → 可执行的提示
_ERROR_HINTS = {
    "InvalidAccessKeyId.NotFound": "AccessKey ID 不存在，请确认没有多余空格、且是当前账号的 AK",
    "InvalidAccessKeyId.Inactive": "该 AccessKey 已被禁用，请在 RAM 控制台启用或换一个",
    "SignatureDoesNotMatch": "AccessKey Secret 不正确，请重新粘贴（注意首尾空格）",
    "Forbidden.RAM": "这个 RAM 用户没有云解析权限，请按文档附加最小权限策略",
    "Forbidden": "权限不足，请确认 RAM 策略包含 alidns 的 Add/Delete/Describe 动作",
    "NoPermission": "当前账号无权操作该域名，请确认域名在本账号下且策略已授权",
    "DomainNotExist": "该域名不在当前账号的云解析中",
    "DomainRecordDuplicate": "已存在相同的解析记录",
    "DomainRecordLimit": "该主机记录下的记录数达到上限（免费版同一名称同类型最多 10 条）",
    "Throttling.User": "调用频率超出限制，稍后重试即可",
    "Throttling": "调用频率超出限制，稍后重试即可",
    "ServiceUnavailable": "云解析服务暂时不可用，请稍后重试",
}


def _ssl_context():
    try:
        import certifi
        import ssl

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        import ssl

        return ssl.create_default_context()


_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ssl_context())
)


def _pe(value) -> str:
    """RFC3986 百分号编码（阿里云签名要求）。"""
    return urllib.parse.quote(str(value), safe="~")


def sign_params(params: dict, secret: str, method: str = "GET") -> str:
    """按 RPC 签名机制计算 Signature（HMAC-SHA1）。"""
    canonical = "&".join(
        f"{_pe(k)}={_pe(v)}" for k, v in sorted(params.items()) if k != "Signature"
    )
    string_to_sign = f"{method}&%2F&{_pe(canonical)}"
    digest = hmac.new(
        (secret + "&").encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


class AliyunDns(DnsProvider):
    name = "aliyun"
    label = "阿里云云解析"

    def __init__(self, access_key_id: str, access_key_secret: str,
                 endpoint: str | None = None, timeout: int = 15, **kwargs):
        super().__init__(access_key_id, access_key_secret, **kwargs)
        self.endpoint = (endpoint or DEFAULT_ENDPOINT).rstrip("/") + "/"
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    # RPC 调用
    # ------------------------------------------------------------------ #

    def _call(self, action: str, **params) -> dict:
        common = {
            "Action": action,
            "Version": API_VERSION,
            "Format": "JSON",
            "AccessKeyId": self.access_key_id,
            "SignatureMethod": "HMAC-SHA1",
            "SignatureVersion": "1.0",
            "SignatureNonce": uuid.uuid4().hex,
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        common.update({k: v for k, v in params.items() if v is not None})

        last_error: DnsError | None = None
        for attempt in range(3):
            payload = dict(common)
            payload["SignatureNonce"] = uuid.uuid4().hex
            payload["Signature"] = sign_params(payload, self.access_key_secret)
            query = "&".join(f"{_pe(k)}={_pe(v)}" for k, v in sorted(payload.items()))
            req = urllib.request.Request(
                self.endpoint + "?" + query,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            try:
                with _OPENER.open(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                data = json.loads(raw or b"{}")
                return data
            except urllib.error.HTTPError as exc:
                raw = exc.read()
                try:
                    data = json.loads(raw or b"{}")
                except Exception:
                    data = {}
                code = str(data.get("Code") or "")
                message = str(data.get("Message") or f"HTTP {exc.code}")
                hint = _ERROR_HINTS.get(code, "")
                if not hint and code.startswith("Throttling"):
                    hint = _ERROR_HINTS["Throttling"]
                last_error = DnsError(
                    f"云解析接口 {action} 失败：{message}", code, hint
                )
                if exc.code >= 500 or code.startswith("Throttling"):
                    time.sleep(1.2 * (attempt + 1))
                    continue
                raise last_error from exc
            except urllib.error.URLError as exc:
                last_error = DnsError(
                    f"无法连接云解析接口（{self.endpoint}）：{exc.reason}",
                    "Network",
                    "请检查网络、代理与防火墙；接口地址是全局的 alidns.aliyuncs.com",
                )
                time.sleep(1.2 * (attempt + 1))
            except Exception as exc:
                last_error = DnsError(f"云解析接口异常：{exc}", "Unknown")
                time.sleep(1.0 * (attempt + 1))
        raise last_error or DnsError(f"云解析接口 {action} 失败", "Unknown")

    # ------------------------------------------------------------------ #
    # 具体动作
    # ------------------------------------------------------------------ #

    def list_zones(self) -> list[dict]:
        zones: list[dict] = []
        page = 1
        while True:
            data = self._call("DescribeDomains", PageNumber=page, PageSize=100)
            block = data.get("Domains") or {}
            items = block.get("Domain") or []
            if isinstance(items, dict):  # 单条时个别版本返回对象
                items = [items]
            for item in items:
                zones.append({
                    "name": (item.get("DomainName") or "").strip().lower(),
                    "id": item.get("DomainId") or "",
                })
            total = int(data.get("TotalCount") or 0)
            if len(items) < 100 or len(zones) >= total:
                break
            page += 1
        return zones

    def list_txt(self, zone: str, rr: str) -> list[dict]:
        records: list[dict] = []
        page = 1
        while True:
            data = self._call(
                "DescribeDomainRecords",
                DomainName=zone,
                RRKeyWord=rr,
                TypeKeyWord="TXT",
                SearchMode="EXACT",
                PageNumber=page,
                PageSize=100,
            )
            block = data.get("DomainRecords") or {}
            items = block.get("Record") or []
            if isinstance(items, dict):
                items = [items]
            for item in items:
                if (item.get("RR") or "").strip().lower() != rr.lower():
                    continue
                if (item.get("Type") or "").upper() != "TXT":
                    continue
                records.append({
                    "id": item.get("RecordId") or "",
                    "value": (item.get("Value") or ""),
                    "ttl": item.get("TTL"),
                })
            total = int(data.get("TotalCount") or 0)
            if len(items) < 100 or len(records) >= total:
                break
            page += 1
        return records

    def add_txt(self, zone: str, rr: str, value: str, ttl: int = 600) -> dict:
        try:
            data = self._call(
                "AddDomainRecord",
                DomainName=zone,
                RR=rr,
                Type="TXT",
                Value=value,
                TTL=max(600, int(ttl)),
            )
        except DnsError as exc:
            # 相同值重复添加：视为已存在，回查一次拿 RecordId
            if "Duplicate" in (exc.code or ""):
                for item in self.list_txt(zone, rr):
                    if (item.get("value") or "").strip() == value.strip():
                        return {"id": item.get("id", ""), "reused": True}
            raise
        return {"id": data.get("RecordId") or "", "reused": False}

    def delete_record(self, record_id: str) -> None:
        if not record_id:
            return
        try:
            self._call("DeleteDomainRecord", RecordId=record_id)
        except DnsError as exc:
            # 已经不存在按成功处理，保证清理是幂等的
            if "DomainRecordNotBelongToUser" in (exc.code or "") or "InvalidRecordId" in (exc.code or ""):
                return
            raise

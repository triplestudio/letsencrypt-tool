"""DNS 记录写入的 provider 抽象。

设计原则：
- 签发链路默认零云厂商依赖，只有显式开启「自动写 TXT」时才会用到这里的实现；
- 每个 provider 只需要实现三个动作：列出托管域名、查同名记录、增删记录，
  其余（定位域名、幂等判断）由基类统一处理。
"""

from __future__ import annotations

import re
from typing import Any


class DnsError(Exception):
    """provider 层错误，message 直接面向使用者。"""

    def __init__(self, message: str, code: str = "", hint: str = ""):
        super().__init__(message)
        self.message = message
        self.code = code
        self.hint = hint

    def readable(self) -> str:
        return f"{self.message}（{self.hint}）" if self.hint else self.message


class DnsProvider:
    """所有 provider 的基类。"""

    name = "base"
    label = ""

    def __init__(self, access_key_id: str, access_key_secret: str, **kwargs):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.options = kwargs
        self._zones: list[dict] | None = None

    # ---- 子类必须实现 ---- #

    def list_zones(self) -> list[dict]:
        """返回 [{'name': 'example.com', 'id': '...'}, ...]，实现方负责分页。"""
        raise NotImplementedError

    def list_txt(self, zone: str, rr: str) -> list[dict]:
        """返回该主机记录下的 TXT 记录：[{'value':..., 'id':...}, ...]。"""
        raise NotImplementedError

    def add_txt(self, zone: str, rr: str, value: str, ttl: int = 600) -> dict:
        raise NotImplementedError

    def delete_record(self, record_id: str) -> None:
        raise NotImplementedError

    # ---- 通用逻辑 ---- #

    def zones(self) -> list[dict]:
        if self._zones is None:
            self._zones = self.list_zones()
        return self._zones

    def find_zone(self, fqdn: str) -> str:
        """在托管域名中找出 fqdn 所属的 zone（最长后缀优先）。"""
        fqdn = fqdn.rstrip(".").lower()
        best = ""
        for zone in self.zones():
            name = (zone.get("name") or "").rstrip(".").lower()
            if not name:
                continue
            if fqdn == name or fqdn.endswith("." + name):
                if len(name) > len(best):
                    best = name
        if best:
            return best
        known = "、".join(z.get("name", "") for z in self.zones()[:8]) or "（空）"
        raise DnsError(
            f"域名 {fqdn} 不在当前账号的托管域名中",
            "ZoneNotFound",
            f"该账号下的域名有：{known}。请确认域名的 NS 指向本服务商，或换一个有权限的账号",
        )

    @staticmethod
    def relative_rr(fqdn: str, zone: str) -> str:
        fqdn, zone = fqdn.rstrip(".").lower(), zone.rstrip(".").lower()
        if fqdn == zone:
            return "@"
        return fqdn[: -(len(zone) + 1)]

    def ensure_txt(self, fqdn: str, value: str, ttl: int = 600) -> dict:
        """保证 fqdn 上存在值为 value 的 TXT 记录。

        已经存在同值记录时直接复用（幂等），避免重复执行产生一堆重复记录。
        返回值里 created=False 表示复用的是既有记录，这类记录不会被工具删除。
        """
        zone = self.find_zone(fqdn)
        rr = self.relative_rr(fqdn, zone)
        value = value.strip()
        for item in self.list_txt(zone, rr):
            if (item.get("value") or "").strip() == value:
                return {
                    "zone": zone,
                    "rr": rr,
                    "name": fqdn,
                    "record_id": item.get("id", ""),
                    "created": False,
                    "value": value,
                }
        added = self.add_txt(zone, rr, value, ttl=ttl)
        return {
            "zone": zone,
            "rr": rr,
            "name": fqdn,
            "record_id": added.get("id", ""),
            "created": True,
            "value": value,
        }


# --------------------------------------------------------------------------- #
# 注册表
# --------------------------------------------------------------------------- #

def _aliyun_class():
    from .aliyun import AliyunDns

    return AliyunDns


PROVIDER_META = {
    "aliyun": {
        "label": "阿里云云解析",
        "factory": _aliyun_class,
        "hint": "域名的 NS 记录需指向阿里云云解析",
    },
}


def provider_label(name: str) -> str:
    return (PROVIDER_META.get(name) or {}).get("label", name)


def create(name: str, access_key_id: str, access_key_secret: str, **kwargs) -> DnsProvider:
    meta = PROVIDER_META.get(name)
    if not meta:
        raise DnsError(
            f"不支持的解析服务商：{name}",
            "UnknownProvider",
            "当前仅支持 aliyun",
        )
    if not access_key_id or not access_key_secret:
        raise DnsError("缺少 AccessKey，无法自动写入解析记录", "NoCredential")
    factory = meta["factory"]
    return factory()(access_key_id, access_key_secret, **kwargs)


def check_fqdn(name: str) -> str:
    """粗校验待写入的记录名，避免把明显错误的字符串发到云上。"""
    name = (name or "").strip().rstrip(".").lower()
    if not re.match(r"^(?:_[a-z0-9-]+\.)?(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$", name):
        raise DnsError(f"记录名不合法：{name or '(空)'}", "BadRecordName")
    return name


def summarize(records: list[dict[str, Any]]) -> str:
    if not records:
        return "无"
    parts = []
    for r in records:
        parts.append(f"{r.get('name', '')} → {r.get('zone', '')}({r.get('rr', '')})")
    return "；".join(parts)

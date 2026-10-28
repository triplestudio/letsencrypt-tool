#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb_deploy.py —— 把 letsencrypt-tool 已签发的证书自动上传并绑定到阿里云应用型负载均衡（ALB）。

职责边界（刻意做窄）：
    只做「本地已有证书 -> 阿里云证书服务 -> 替换 ALB 监听证书」这一段。
    不负责签发、不负责 DNS 记录、不负责后端服务器组。

用法：
    python deploy/alb_deploy.py --listener-id lsn-xxxxxxxx --region cn-hangzhou \
        --domain example.com --verify-host www.example.com

凭证来源（优先级从高到低）：
    1. 命令行 --access-key-id / --access-key-secret
    2. 环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET
    3. --env-file 指定的文件（KEY=VALUE 形式，建议放在已被 .gitignore 排除的 data/ 下）

退出码：
    0  成功（或已是最新，无需变更）
    1  本地证书问题（缺文件、私钥不配对、已过期等）
    2  凭证或权限问题
    3  证书上传失败
    4  监听证书替换失败
    5  替换后 TLS 校验未通过
    6  运行环境问题（缺少 SDK 等）
    7  网络问题（域名解析失败、连不上阿里云）
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:  # pragma: no cover
    print("缺少 cryptography，请先执行：pip install -r requirements.txt")
    sys.exit(6)

ROOT = Path(__file__).resolve().parent.parent
CERTS_DIR = ROOT / "certs"
DEFAULT_STATE = ROOT / "data" / "alb-state.json"

EXIT_OK = 0
EXIT_CERT = 1
EXIT_AUTH = 2
EXIT_UPLOAD = 3
EXIT_LISTENER = 4
EXIT_VERIFY = 5
EXIT_ENV = 6
EXIT_NET = 7


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------

_VERBOSE = False

# 日志出口。None 表示直接打印到终端（命令行用法）；Web 界面会注册一个收集器。
_LOG_SINK = None

# 进程内传入的凭证。用于被 app.py 调用时避免把 AccessKey 写进命令行或临时文件。
_CRED_OVERRIDE = None


def set_log_sink(sink) -> None:
    """注册日志收集器，回调签名为 sink({"time","level","message"})；传 None 恢复打印。"""
    global _LOG_SINK
    _LOG_SINK = sink


def set_credentials(ak: str = "", sk: str = "") -> None:
    """由宿主进程直接传入凭证，优先级高于命令行与环境变量。传空值则清除。"""
    global _CRED_OVERRIDE
    _CRED_OVERRIDE = (ak, sk) if (ak and sk) else None


def set_verbose(value: bool) -> None:
    global _VERBOSE
    _VERBOSE = bool(value)


def log(msg: str, level: str = "info") -> None:
    mark = {
        "ok": " OK ",
        "info": "INFO",
        "warn": "WARN",
        "fail": "FAIL",
        "step": "STEP",
        "debug": "DBUG",
    }.get(level, "INFO")
    if level == "debug" and not _VERBOSE:
        return
    stamp = datetime.now().strftime("%H:%M:%S")
    if _LOG_SINK is not None:
        _LOG_SINK({"time": stamp, "level": level, "mark": mark.strip(), "message": msg})
        return
    line = "[%s] [%s] %s" % (stamp, mark, msg)
    print(line, flush=True)


class DeployError(Exception):
    """带退出码的业务异常。"""

    def __init__(self, message: str, exit_code: int = EXIT_CERT, detail: str = ""):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.detail = detail


_NET_MARKERS = (
    "getaddrinfo",
    "nameresolutionerror",
    "name or service not known",
    "nodename nor servname",
    "proxyerror",
    "tunnel connection failed",
    "max retries exceeded",
    "connection refused",
    "connection reset",
    "connection aborted",
    "timed out",
    "timeout",
)


def _network_failure(desc: str, text: str):
    """把 DNS / 代理 / 连接类底层异常翻译成能直接照做的提示。

    不是网络问题就返回 None，交给调用处按原来的错误码处理。
    """
    low = text.lower()
    if not any(marker in low for marker in _NET_MARKERS):
        return None

    # 异常文本里的引号可能被 repr 转义成 \'，所以要容忍一个反斜杠。
    matched = re.search(r"host\s*[=:]\s*\\?['\"]?([A-Za-z0-9._-]+)", text)
    host = matched.group(1) if matched else "阿里云接口"

    if (
        "getaddrinfo" in low
        or "nameresolutionerror" in low
        or "name or service not known" in low
        or "nodename nor servname" in low
    ):
        return DeployError(
            "%s失败：本机无法解析域名 %s。若浏览器打开其他网站正常，说明该域名本身不存在"
            "（端点地址写错），而不是网络故障。" % (desc, host),
            EXIT_NET,
        )

    if "proxyerror" in low or "tunnel connection failed" in low:
        proxy = ""
        for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "ALL_PROXY", "all_proxy"):
            if os.environ.get(key):
                proxy = os.environ[key]
                break
        return DeployError(
            "%s失败：代理服务器%s 没能连通 %s。请检查系统代理设置，或临时关闭代理后重试。"
            % (desc, ("（%s）" % proxy) if proxy else "", host),
            EXIT_NET,
        )

    return DeployError("%s失败：连接 %s 失败（网络超时或被拒绝）。" % (desc, host), EXIT_NET)


# ---------------------------------------------------------------------------
# 本地证书读取与校验
# ---------------------------------------------------------------------------

def _not_after(cert: x509.Certificate) -> datetime:
    """兼容不同版本的 cryptography。"""
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _cn(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if names:
        return names[0].value
    return cert.subject.rfc4514_string()


def _san(cert: x509.Certificate) -> list:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def pick_cert_dir(explicit: str, domain: str) -> Path:
    """定位证书目录：显式指定优先，否则取 certs/ 下最新的一版。"""
    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            path = ROOT / path
        if not path.is_dir():
            raise DeployError("证书目录不存在：%s" % path, EXIT_CERT)
        return path

    if not CERTS_DIR.is_dir():
        raise DeployError("未找到 certs/ 目录，请先签发证书", EXIT_CERT)

    candidates = [d for d in CERTS_DIR.iterdir() if d.is_dir() and (d / "fullchain.pem").is_file()]
    if domain:
        key = domain.lower().replace("*.", "")
        candidates = [d for d in candidates if key in d.name.lower()]
    if not candidates:
        raise DeployError(
            "certs/ 下没有可用证书目录%s" % ("（域名过滤：%s）" % domain if domain else ""),
            EXIT_CERT,
        )
    candidates.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return candidates[0]


def _key_label(key_obj) -> str:
    """把 cryptography 的类名换成人能读的密钥描述。"""
    name = type(key_obj).__name__
    if name == "ECPrivateKey":
        curve = getattr(getattr(key_obj, "curve", None), "name", "") or ""
        return {
            "secp256r1": "EC P-256",
            "secp384r1": "EC P-384",
            "secp521r1": "EC P-521",
        }.get(curve, "EC " + curve if curve else "EC")
    if "RSA" in name:
        return "RSA %d" % key_obj.key_size
    if "Ed25519" in name:
        return "Ed25519"
    if "Ed448" in name:
        return "Ed448"
    return name


def load_bundle(cert_dir: Path, quiet: bool = False) -> dict:
    """读取并校验 fullchain.pem / privkey.pem，返回上传所需的全部信息。

    quiet=True 时不输出日志（界面列证书清单时用，避免刷屏）。
    """
    chain_path = cert_dir / "fullchain.pem"
    key_path = cert_dir / "privkey.pem"
    for p in (chain_path, key_path):
        if not p.is_file():
            raise DeployError("证书目录缺少 %s" % p.name, EXIT_CERT)

    chain_pem = chain_path.read_text(encoding="utf-8")
    key_pem = key_path.read_text(encoding="utf-8")

    if "BEGIN CERTIFICATE" not in chain_pem:
        raise DeployError("fullchain.pem 内容不是 PEM 证书", EXIT_CERT)
    if "PRIVATE KEY" not in key_pem:
        raise DeployError("privkey.pem 内容不是 PEM 私钥", EXIT_CERT)
    if "ENCRYPTED" in key_pem:
        raise DeployError("私钥带口令，阿里云不接受加密私钥", EXIT_CERT)

    leaf = x509.load_pem_x509_certificate(chain_pem.encode())
    cert_count = chain_pem.count("BEGIN CERTIFICATE")

    # 私钥与证书是否配对：比对双方公钥
    try:
        key_obj = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except Exception as exc:
        raise DeployError("私钥无法解析：%s" % exc, EXIT_CERT)

    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    enc = serialization.Encoding.DER
    cert_pub = leaf.public_key().public_bytes(enc, fmt)
    key_pub = key_obj.public_key().public_bytes(enc, fmt)
    if cert_pub != key_pub:
        raise DeployError("私钥与该证书不配对，上传后必然握手失败", EXIT_CERT)

    not_after = _not_after(leaf)
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days
    if days_left < 0:
        raise DeployError("证书已过期（%s），请先重新签发" % not_after.strftime("%Y-%m-%d"), EXIT_CERT)
    if days_left <= 30:
        log("证书将在 %d 天后过期（%s），建议先续期再部署" % (days_left, not_after.strftime("%Y-%m-%d")), "warn")

    if not quiet:
        log("证书目录：%s" % cert_dir.name)
        log("域名（CN）：%s    SAN：%s" % (_cn(leaf), ", ".join(_san(leaf)) or "-"))
        log("证书链：%d 张    密钥：%s    剩余：%d 天" % (cert_count, _key_label(key_obj), days_left))

        if cert_count < 2:
            log("证书链只有 1 张，ALB 侧可能提示缺少中间证书", "warn")

    return {
        "dir": cert_dir,
        "chain_pem": chain_pem.strip() + "\n",
        "key_pem": key_pem.strip() + "\n",
        "serial": "%X" % leaf.serial_number,
        "cn": _cn(leaf),
        "san": _san(leaf),
        "not_after": not_after,
        "days_left": days_left,
        "cert_count": cert_count,
        "key_type": _key_label(key_obj),
    }


def cert_display_name(info: dict) -> str:
    """上传到阿里云时使用的证书名称：域名 + 到期日，便于到期前一眼分辨新旧。"""
    base = info["cn"].replace("*.", "wildcard.")
    base = "".join(ch if (ch.isalnum() or ch in ".-") else "-" for ch in base)
    return "%s-%s" % (base, info["not_after"].strftime("%Y%m%d"))


# ---------------------------------------------------------------------------
# 阿里云 SDK 封装
# ---------------------------------------------------------------------------

class AliyunClients(object):
    """把 SDK 细节收拢在一处，便于出错时统一翻译成人话。"""

    def __init__(self, ak: str, sk: str, region: str, alb_endpoint: str = "", cas_endpoint: str = ""):
        try:
            from alibabacloud_tea_openapi import models as open_api_models
            from alibabacloud_cas20200407.client import Client as CasClient
            from alibabacloud_cas20200407 import models as cas_models
            from alibabacloud_alb20200616.client import Client as AlbClient
            from alibabacloud_alb20200616 import models as alb_models
            from Tea.exceptions import TeaException
        except ImportError as exc:
            raise DeployError(
                "缺少阿里云 SDK（%s）。请执行：pip install -r deploy/requirements-aliyun.txt" % exc,
                EXIT_ENV,
            )

        self._cas_models = cas_models
        self._alb_models = alb_models
        self._tea = TeaException

        def build(endpoint: str):
            cfg = open_api_models.Config(access_key_id=ak, access_key_secret=sk)
            cfg.endpoint = endpoint
            cfg.region_id = region
            cfg.read_timeout = 15000
            cfg.connect_timeout = 10000
            return cfg

        # 证书服务（CAS）是全局服务：SDK 自带的 endpoint map 里，cn-hangzhou、cn-beijing
        # 等所有地域都映射到 cas.aliyuncs.com。不存在 cas.<region>.aliyuncs.com 这个域名，
        # 拼成那样只会得到 DNS 解析失败。
        cas_ep = cas_endpoint or ("cas.aliyuncs.com")
        # 负载均衡（ALB）是地域级服务，端点必须带 region。
        alb_ep = alb_endpoint or ("alb.%s.aliyuncs.com" % region)
        self.cas = CasClient(build(cas_ep))
        self.alb = AlbClient(build(alb_ep))
        log("已初始化客户端：CAS=%s  ALB=%s" % (cas_ep, alb_ep), "debug")

    # -- 错误翻译 ---------------------------------------------------------

    def call(self, desc: str, fn, exit_code: int):
        try:
            return fn()
        except self._tea as exc:
            code = getattr(exc, "code", "") or ""
            msg = getattr(exc, "message", "") or str(exc)
            # SDK 会把 DNS/代理这类底层异常包成 code 为空的 TeaException，
            # 不先翻译就会被归成「错误码：未知」的访问密钥问题，误导排查方向。
            net = _network_failure(desc, msg)
            if net is not None:
                raise net
            hint = ""
            lowered = (code + " " + msg).lower()
            if "accesskey" in lowered or "signature" in lowered:
                hint = "AccessKey 不正确，或与 RAM 用户不匹配"
                exit_code = EXIT_AUTH
            elif "forbidden" in lowered or "nopermission" in lowered or "not authorized" in lowered:
                hint = "RAM 权限不足，请检查 deploy/ram-policy.json 中的动作是否已授予"
                exit_code = EXIT_AUTH
            elif "throttling" in lowered:
                hint = "触发限流，稍后重试"
            elif "region" in lowered and "not" in lowered:
                hint = "region 与资源所在地域不一致"
            detail = "%s（错误码：%s）" % (msg, code or "未知")
            raise DeployError("%s失败：%s%s" % (desc, detail, ("；" + hint) if hint else ""), exit_code)
        except DeployError:
            raise
        except Exception as exc:
            # 网络不可达、DNS 解析失败、SDK 内部异常等
            name = type(exc).__name__
            text = str(exc)
            net = _network_failure(desc, text)
            if net is not None:
                raise net
            raise DeployError("%s失败：%s: %s" % (desc, name, text), exit_code)

    # -- 证书服务 ---------------------------------------------------------

    def upload_certificate(self, name: str, chain_pem: str, key_pem: str) -> str:
        req = self._cas_models.UploadUserCertificateRequest(
            name=name,
            cert=chain_pem,
            key=key_pem,
        )
        resp = self.call("上传证书", lambda: self.cas.upload_user_certificate(req), EXIT_UPLOAD)
        cert_id = getattr(resp.body, "cert_id", None)
        if not cert_id:
            raise DeployError("上传接口未返回 CertId，无法继续", EXIT_UPLOAD)
        return str(cert_id)

    def delete_certificate(self, cert_id: str) -> None:
        req = self._cas_models.DeleteUserCertificateRequest(cert_id=int(cert_id))
        self.call("删除旧证书", lambda: self.cas.delete_user_certificate(req), EXIT_UPLOAD)

    # -- 负载均衡 ---------------------------------------------------------

    def list_listeners(self) -> list:
        """只读：列出当前地域的 ALB 监听。界面用它自动带出监听 ID。"""
        req = self._alb_models.ListListenersRequest(max_results=100)
        resp = self.call("查询监听列表", lambda: self.alb.list_listeners(req), EXIT_LISTENER)
        out = []
        for item in (getattr(resp.body, "listeners", None) or []):
            out.append(
                {
                    "listener_id": str(getattr(item, "listener_id", "") or ""),
                    "protocol": str(getattr(item, "listener_protocol", "") or ""),
                    "port": getattr(item, "listener_port", None),
                    "load_balancer_id": str(getattr(item, "load_balancer_id", "") or ""),
                    "description": str(getattr(item, "description", "") or ""),
                }
            )
        return out

    def probe_cas(self) -> int:
        """只读：拿一次已上传证书的计数，用于确认 CAS 读权限与 AK 有效性。"""
        req = self._cas_models.ListUserCertificateOrderRequest(
            order_type="UPLOAD", current_page=1, show_size=10
        )
        resp = self.call("查询已上传证书", lambda: self.cas.list_user_certificate_order(req), EXIT_AUTH)
        return int(getattr(resp.body, "total_count", 0) or 0)

    def listener_certs(self, listener_id: str) -> list:
        req = self._alb_models.ListListenerCertificatesRequest(listener_id=listener_id)
        resp = self.call("查询监听证书", lambda: self.alb.list_listener_certificates(req), EXIT_LISTENER)
        out = []
        for item in (resp.body.certificates or []):
            out.append(
                {
                    "certificate_id": str(getattr(item, "certificate_id", "") or ""),
                    "is_default": bool(getattr(item, "is_default", False)),
                }
            )
        return out

    def set_default_certificate(self, listener_id: str, cert_id: str) -> None:
        cert = self._alb_models.UpdateListenerAttributeRequestCertificates(certificate_id=cert_id)
        req = self._alb_models.UpdateListenerAttributeRequest(
            listener_id=listener_id,
            certificates=[cert],
        )
        self.call("替换监听默认证书", lambda: self.alb.update_listener_attribute(req), EXIT_LISTENER)

    def add_additional_certificate(self, listener_id: str, cert_id: str) -> None:
        item = self._alb_models.AssociateAdditionalCertificatesWithListenerRequestCertificates(
            certificate_id=cert_id
        )
        req = self._alb_models.AssociateAdditionalCertificatesWithListenerRequest(
            listener_id=listener_id,
            certificates=[item],
        )
        self.call(
            "关联扩展证书",
            lambda: self.alb.associate_additional_certificates_with_listener(req),
            EXIT_LISTENER,
        )

    def remove_additional_certificate(self, listener_id: str, cert_id: str) -> None:
        item = self._alb_models.DissociateAdditionalCertificatesFromListenerRequestCertificates(
            certificate_id=cert_id
        )
        req = self._alb_models.DissociateAdditionalCertificatesFromListenerRequest(
            listener_id=listener_id,
            certificates=[item],
        )
        self.call(
            "摘除旧扩展证书",
            lambda: self.alb.dissociate_additional_certificates_from_listener(req),
            EXIT_LISTENER,
        )


# ---------------------------------------------------------------------------
# 状态文件（幂等判断依据）
# ---------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    if not path.is_file():
        return {"listeners": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data.get("listeners"), dict):
            data["listeners"] = {}
        return data
    except Exception:
        log("状态文件损坏，按空状态处理：%s" % path, "warn")
        return {"listeners": {}}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# 替换后的 TLS 校验
# ---------------------------------------------------------------------------

def verify_tls(host: str, expect_serial: str, port: int = 443, retries: int = 6) -> None:
    """连一次真实握手，比对线上证书序列号。ALB 证书生效可能有数秒延迟，故重试。"""
    last_err = ""
    for i in range(retries):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    proto = tls.version()
            live = x509.load_der_x509_certificate(der)
            live_serial = "%X" % live.serial_number
            if live_serial.upper() == expect_serial.upper():
                log("线上证书序列号一致（%s），%s 生效" % (live_serial, proto), "ok")
                return
            last_err = "线上序列号 %s != 本地 %s" % (live_serial, expect_serial)
        except Exception as exc:
            last_err = str(exc)
        if i < retries - 1:
            log("等待证书生效（第 %d/%d 次）：%s" % (i + 1, retries, last_err), "debug")
            time.sleep(5)

    raise DeployError("TLS 校验未通过：%s" % last_err, EXIT_VERIFY)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="把本地已签发的证书上传并绑定到阿里云 ALB 监听",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  python deploy/alb_deploy.py --listener-id lsn-abc123 --region cn-hangzhou \\\n"
               "      --domain example.com --verify-host www.example.com\n",
    )
    p.add_argument("--listener-id", action="append", default=[], required=True,
                   help="ALB 监听 ID（lsn- 开头），可逗号分隔或重复传多次")
    p.add_argument("--region", default="cn-hangzhou", help="地域，默认 cn-hangzhou")
    p.add_argument("--role", choices=["default", "additional"], default="default",
                   help="default=替换监听默认证书；additional=作为扩展证书（SNI）")
    p.add_argument("--domain", default="", help="按域名挑选 certs/ 下最新的证书目录")
    p.add_argument("--cert-dir", default="", help="直接指定证书目录（优先于 --domain）")
    p.add_argument("--verify-host", default="", help="替换后用该域名做一次 TLS 校验")
    p.add_argument("--dry-run", action="store_true", help="只打印将要执行的动作，不调用写接口")
    p.add_argument("--force-upload", action="store_true", help="忽略幂等判断，强制重新上传")
    p.add_argument("--prune-additional", action="store_true",
                   help="role=additional 时，顺带摘除状态文件里记录的上一张扩展证书")
    p.add_argument("--prune-old-cert", action="store_true",
                   help="切换成功后删除上一张证书（仍被其他云产品引用时会跳过并告警）")
    p.add_argument("--access-key-id", default="", help="建议改用环境变量")
    p.add_argument("--access-key-secret", default="", help="建议改用环境变量")
    p.add_argument("--env-file", default="", help="从 KEY=VALUE 文件读取凭证")
    p.add_argument("--state-file", default=str(DEFAULT_STATE), help="状态文件路径")
    p.add_argument("-v", "--verbose", action="store_true", help="输出调试信息")
    return p.parse_args(argv)


def read_env_file(path: str) -> dict:
    result = {}
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    if not p.is_file():
        raise DeployError("env 文件不存在：%s" % p, EXIT_ENV)
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def _mask(key: str) -> str:
    return key[:4] + "***" + key[-4:] if len(key) > 8 else "***"


def resolve_credentials(args) -> tuple:
    if _CRED_OVERRIDE:
        ak, sk = _CRED_OVERRIDE
        log("凭证：%s（由界面提交，不落磁盘、不进命令行）" % _mask(ak), "debug")
        return ak, sk

    ak = args.access_key_id or os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
    sk = args.access_key_secret or os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")
    if args.env_file:
        env = read_env_file(args.env_file)
        ak = ak or env.get("ALIBABA_CLOUD_ACCESS_KEY_ID", "") or env.get("ACCESS_KEY_ID", "")
        sk = sk or env.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "") or env.get("ACCESS_KEY_SECRET", "")
    if not ak or not sk:
        raise DeployError(
            "缺少 AccessKey。请设置环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET，"
            "或使用 --env-file 指向密钥文件",
            EXIT_AUTH,
        )
    if args.access_key_id or args.access_key_secret:
        log("凭证来自命令行参数，可能残留在命令历史中，建议改用环境变量", "warn")
    masked = _mask(ak)
    log("凭证：%s（RAM 用户）" % masked, "debug")
    return ak, sk


def main(argv=None) -> int:
    global _VERBOSE
    args = parse_args(argv)
    _VERBOSE = args.verbose

    listeners = []
    for raw in args.listener_id:
        for part in raw.split(","):
            part = part.strip()
            if part and part not in listeners:
                listeners.append(part)
    if not listeners:
        raise DeployError("--listener-id 不能为空", EXIT_CERT)
    for item in listeners:
        if not re.match(r"^lsn-[A-Za-z0-9]+$", item) and not re.match(r"^lsr-[A-Za-z0-9]+$", item):
            raise DeployError(
                "监听 ID 格式不正确：%s（ALB 监听 ID 形如 lsn-xxxxxxxx）" % item, EXIT_CERT
            )

    log("目标监听：%s" % ", ".join(listeners), "step")

    # 1. 本地证书
    cert_dir = pick_cert_dir(args.cert_dir, args.domain)
    info = load_bundle(cert_dir)

    if args.verify_host:
        host = args.verify_host.lower()
        san = [s.lower() for s in info["san"]]
        covered = host in san or any(
            s.startswith("*.") and host.count(".") == s.count(".") and host.endswith(s[1:]) for s in san
        )
        if not covered:
            raise DeployError(
                "证书不覆盖 %s（SAN：%s）。注意泛域名不包含裸域名。" % (host, ", ".join(info["san"])),
                EXIT_CERT,
            )

    # 2. 状态与客户端
    state_path = Path(args.state_file)
    if not state_path.is_absolute():
        state_path = ROOT / state_path
    state = load_state(state_path)
    ak, sk = resolve_credentials(args)
    clients = AliyunClients(ak, sk, args.region)

    # 3. 逐监听做幂等判断
    pending = []
    prev_cert_ids = {}
    for lsr in listeners:
        current = clients.listener_certs(lsr)
        ids = [c["certificate_id"] for c in current]
        log("监听 %s 现有 %d 张证书：%s" % (lsr, len(current), ", ".join(ids) or "-"), "debug")

        record = state["listeners"].get(lsr, {})
        prev_cert_ids[lsr] = str(record.get("cert_id", "") or "")
        same_serial = str(record.get("serial", "")).upper() == info["serial"].upper()
        still_bound = str(record.get("cert_id", "")) in ids

        if same_serial and still_bound and not args.force_upload:
            log("监听 %s 已是该证书（序列号 %s），跳过" % (lsr, info["serial"]), "ok")
            continue
        pending.append((lsr, ids))

    if not pending:
        log("所有监听均已是最新，无需变更", "ok")
        return EXIT_OK

    # 4. 上传（多个监听共用同一张新证书，只传一次）
    name = cert_display_name(info)
    if args.dry_run:
        log("[dry-run] 将上传证书：%s（序列号 %s）" % (name, info["serial"]))
        for lsr, _ in pending:
            action = "替换默认证书" if args.role == "default" else "关联为扩展证书"
            log("[dry-run] 将对监听 %s %s" % (lsr, action))
        return EXIT_OK

    log("上传证书：%s" % name, "step")
    cert_id = clients.upload_certificate(name, info["chain_pem"], info["key_pem"])
    log("上传成功，CertId=%s" % cert_id, "ok")

    # 5. 绑定到监听
    failed = []
    for lsr, ids in pending:
        try:
            if args.role == "default":
                clients.set_default_certificate(lsr, cert_id)
            else:
                clients.add_additional_certificate(lsr, cert_id)
                old = prev_cert_ids.get(lsr, "")
                if args.prune_additional and old and old != cert_id and old in ids:
                    clients.remove_additional_certificate(lsr, old)

            state["listeners"][lsr] = {
                "cert_id": cert_id,
                "serial": info["serial"],
                "cn": info["cn"],
                "not_after": info["not_after"].strftime("%Y-%m-%d"),
                "role": args.role,
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            save_state(state_path, state)
            log("监听 %s 已切换到新证书" % lsr, "ok")
        except DeployError as exc:
            failed.append((lsr, exc))
            log("监听 %s 处理失败：%s" % (lsr, exc.message), "fail")

    # 6. 线上校验
    if args.verify_host and not failed:
        log("校验线上证书：%s" % args.verify_host, "step")
        try:
            verify_tls(args.verify_host, info["serial"])
        except DeployError as exc:
            log(exc.message, "fail")
            log("监听已切换到新证书，但线上校验未通过；旧证书保留未删，可手工回退", "warn")
            return exc.exit_code

    if failed:
        for lsr, exc in failed:
            log("%s -> %s" % (lsr, exc.message), "fail")
        return failed[0][1].exit_code

    # 7. 清理上一张证书（放在校验之后，保留回滚余地；失败只告警）
    if args.prune_old_cert:
        alive = {str(r.get("cert_id", "")) for r in state["listeners"].values()}
        stale = {v for v in prev_cert_ids.values() if v} - {cert_id} - alive
        for old in sorted(stale):
            try:
                clients.delete_certificate(old)
                log("已清理旧证书 CertId=%s" % old, "ok")
            except DeployError as exc:
                log("旧证书 %s 未清理（可能仍被其他云产品引用）：%s" % (old, exc.message), "warn")

    log("全部完成。证书 %s 到期 %s（%d 天）" % (
        info["cn"], info["not_after"].strftime("%Y-%m-%d"), info["days_left"]), "ok")
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DeployError as exc:
        log(exc.message, "fail")
        if exc.detail:
            log(exc.detail, "debug")
        sys.exit(exc.exit_code)
    except KeyboardInterrupt:
        log("已中断", "warn")
        sys.exit(130)

"""
ACME (RFC 8555) 客户端核心实现 —— 用于向 Let's Encrypt 申请 HTTPS 证书。

只依赖 cryptography 库，其余全部使用 Python 标准库，便于离线部署。
支持 HTTP-01 与 DNS-01 两种验证方式。
"""

from __future__ import annotations

import base64
import datetime
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

USER_AGENT = "LetsEncryptTool/1.0 (+python-stdlib)"
PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"


# --------------------------------------------------------------------------- #
# HTTPS 证书校验配置
# --------------------------------------------------------------------------- #

def _build_ssl_context() -> ssl.SSLContext:
    """构造 HTTPS 证书校验上下文。

    Windows 上不少 Python 环境没有默认 CA 根证书库
    （OpenSSL 默认路径 C:\\Program Files\\Common Files\\SSL\\cert.pem 并不存在），
    直接用系统默认会报 CERTIFICATE_VERIFY_FAILED —— 而浏览器走 Windows 证书库，
    所以同一个网址浏览器能开、Python 打不开。
    这里优先使用 certifi 提供的根证书库（requirements.txt 已包含），
    未安装 certifi 时退回系统默认配置。
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


# 全局复用的 HTTPS opener，所有网络请求（ACME / DoH / 查公网 IP）都走它
_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_build_ssl_context())
)


def _urlopen(req: urllib.request.Request, timeout: float):
    return _OPENER.open(req, timeout=timeout)


# --------------------------------------------------------------------------- #
# 编码工具
# --------------------------------------------------------------------------- #

def b64u(data: bytes) -> str:
    """base64url 编码（无填充），JWS 规范要求。"""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _int_to_b64u(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return b64u(value.to_bytes(length, "big"))


class AcmeError(Exception):
    """ACME 协议错误，携带 RFC 7807 problem 详情。"""

    def __init__(self, message: str, status: int | None = None,
                 problem_type: str | None = None, details: list[str] | None = None,
                 network: bool = False):
        super().__init__(message)
        self.message = message
        self.status = status
        self.problem_type = problem_type or ""
        self.details = details or []
        self.network = network

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "status": self.status,
            "type": self.problem_type,
            "details": self.details,
        }


# --------------------------------------------------------------------------- #
# 密钥生成
# --------------------------------------------------------------------------- #

def generate_account_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def generate_cert_key(key_type: str = "ec256"):
    """生成证书私钥。默认 ECDSA P-256（体积小、握手快、现代浏览器全支持）。"""
    if key_type == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "rsa4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if key_type == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    return ec.generate_private_key(ec.SECP256R1())


def pem_private_key(key, passphrase: bytes | None = None) -> bytes:
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def load_account_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


_THUMB_LOCK = threading.Lock()


def _jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK 指纹：按字典序拼接必需字段后 sha256。"""
    if jwk["kty"] == "RSA":
        ordered = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:  # EC
        ordered = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(ordered, separators=(",", ":"), sort_keys=True)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonical.encode("utf-8"))
    return b64u(digest.finalize())


# --------------------------------------------------------------------------- #
# 域名工具
# --------------------------------------------------------------------------- #

DOMAIN_RE = re.compile(r"^(?:\*\.)?(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def normalize_domains(raw: str | list[str]) -> list[str]:
    """清洗用户输入：去空白、转小写、IDN→punycode、去重、校验格式。"""
    if isinstance(raw, str):
        parts = re.split(r"[\s,;]+", raw)
    else:
        parts = list(raw)

    result: list[str] = []
    for item in parts:
        item = item.strip().lower().rstrip(".")
        if not item:
            continue
        if item.startswith("http://") or item.startswith("https://"):
            item = urllib.parse.urlparse(item).hostname or ""
        if ":" in item and not item.startswith("["):  # 去掉端口
            item = item.split(":", 1)[0]
        if not item:
            continue
        # 国际化域名转 punycode
        try:
            if not item.isascii():
                item = ".".join(
                    part.encode("idna").decode("ascii") if not part.startswith("*") else "*"
                    for part in item.split(".")
                )
        except Exception:
            raise AcmeError(f"域名无法转换为 punycode：{item}")
        if not DOMAIN_RE.match(item):
            raise AcmeError(f"域名格式不合法：{item}")
        if item not in result:
            result.append(item)

    if not result:
        raise AcmeError("请至少填写一个域名")
    if len(result) > 100:
        raise AcmeError("单张证书最多 100 个域名")
    return result


def base_domain_of(domain: str) -> str:
    return domain[2:] if domain.startswith("*.") else domain


# --------------------------------------------------------------------------- #
# DNS 查询（通过 DoH，避免依赖系统解析缓存）
# --------------------------------------------------------------------------- #

def doh_query(name: str, rtype: str = "TXT", timeout: int = 8) -> list[str] | None:
    """使用 DNS over HTTPS 查询记录，返回字符串记录列表；查询失败返回 None。"""
    endpoints = [
        ("https://cloudflare-dns.com/dns-query", "application/dns-json"),
        ("https://dns.google/resolve", "application/dns-json"),
    ]
    for endpoint, accept in endpoints:
        url = f"{endpoint}?name={urllib.parse.quote(name)}&type={rtype}"
        req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
        try:
            with _urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
        except Exception:
            continue
        answers = data.get("Answer") or []
        values = [str(a.get("data", "")).strip().strip('"') for a in answers
                  if a.get("type") == {"TXT": 16, "A": 1, "AAAA": 28, "CNAME": 5}.get(rtype)]
        return values
    return None


def resolve_ips(domain: str) -> dict[str, list[str]]:
    """查询域名的 A / AAAA 记录（通配符域名去掉 *）。"""
    name = base_domain_of(domain)
    out: dict[str, list[str]] = {"A": [], "AAAA": []}
    for rtype in ("A", "AAAA"):
        values = doh_query(name, rtype)
        if values:
            out[rtype] = values
        elif values is None:
            # DoH 不可用时退回系统解析
            try:
                infos = socket.getaddrinfo(name, None)
                ips = {i[4][0] for i in infos}
                out[rtype] = [ip for ip in ips if (":" in ip) == (rtype == "AAAA")]
            except Exception:
                pass
    return out


def public_ip(timeout: int = 6) -> str | None:
    """获取本机出口公网 IP，用于提示 DNS 是否指向本机。"""
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with _urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------- #
# ACME 客户端
# --------------------------------------------------------------------------- #

class AcmeClient:
    def __init__(self, directory_url: str, account_key=None, timeout: int = 60):
        self.directory_url = directory_url
        self.account_key = account_key or generate_account_key()
        self.timeout = timeout
        self.kid: str | None = None          # 账号 URL，注册后获得
        self._directory: dict | None = None
        self._nonce: str | None = None
        self._lock = threading.Lock()
        self._thumbprint: str | None = None

    # ---------------------------- 基础属性 ---------------------------- #

    def public_jwk(self) -> dict:
        pub = self.account_key.public_key()
        numbers = pub.public_numbers()
        if isinstance(pub, rsa.RSAPublicKey):
            return {"e": _int_to_b64u(numbers.e), "kty": "RSA", "n": _int_to_b64u(numbers.n)}
        size = (pub.key_size + 7) // 8
        crv = "P-256" if pub.key_size == 256 else "P-384" if pub.key_size == 384 else "P-521"
        return {
            "crv": crv,
            "kty": "EC",
            "x": b64u(numbers.x.to_bytes(size, "big")),
            "y": b64u(numbers.y.to_bytes(size, "big")),
        }

    @property
    def thumbprint(self) -> str:
        if self._thumbprint is None:
            self._thumbprint = _jwk_thumbprint(self.public_jwk())
        return self._thumbprint

    @property
    def directory(self) -> dict:
        if self._directory is None:
            last: Exception | None = None
            for attempt in range(3):
                try:
                    status, _, body = self._http("GET", self.directory_url)
                    if status != 200:
                        raise AcmeError(
                            f"无法读取 ACME 目录（HTTP {status}）：{self.directory_url}", status
                        )
                    self._directory = json.loads(body)
                    break
                except AcmeError as exc:
                    last = exc
                    if not exc.network or attempt == 2:
                        raise
                    time.sleep(1.5 * (attempt + 1))
            if self._directory is None:
                raise last or AcmeError("无法读取 ACME 目录")
        return self._directory

    # ---------------------------- HTTP 层 ---------------------------- #

    def _http(self, method: str, url: str, data: bytes | None = None,
              headers: dict | None = None) -> tuple[int, dict, bytes]:
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", USER_AGENT)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with _urlopen(req, timeout=self.timeout) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()
        except urllib.error.URLError as exc:
            reason = str(exc.reason)
            hint = ""
            if "CERTIFICATE_VERIFY_FAILED" in reason:
                hint = ("（TLS 证书校验失败：请检查系统日期时间是否准确，"
                        "以及是否安装了拦截/代理类软件）")
            raise AcmeError(f"网络请求失败：{reason}{hint}（目标 {url}）", network=True) from exc
        except Exception as exc:  # socket timeout 等
            raise AcmeError(f"网络请求失败：{exc}", network=True) from exc

    def _refresh_nonce(self) -> str:
        last: AcmeError | None = None
        for attempt in range(3):
            try:
                status, headers, _ = self._http("HEAD", self.directory["newNonce"])
                nonce = headers.get("replay-nonce")
                if not nonce:
                    status, headers, _ = self._http("GET", self.directory["newNonce"])
                    nonce = headers.get("replay-nonce")
                if nonce:
                    return nonce
            except AcmeError as exc:
                last = exc
                if not exc.network:
                    raise
            time.sleep(1.1 * (attempt + 1))
        if last:
            raise last
        raise AcmeError("无法从 CA 获取 nonce（Replay-Nonce 缺失）")

    def _take_nonce(self) -> str:
        with self._lock:
            nonce, self._nonce = self._nonce, None
        return nonce or self._refresh_nonce()

    def _sign(self, signing_input: bytes) -> str:
        if isinstance(self.account_key, rsa.RSAPrivateKey):
            sig = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            return b64u(sig)
        algo = hashes.SHA256() if self.account_key.key_size == 256 else hashes.SHA384()
        return b64u(self.account_key.sign(signing_input, ec.ECDSA(algo)))

    def _alg(self) -> str:
        if isinstance(self.account_key, rsa.RSAPrivateKey):
            return "RS256"
        return "ES256" if self.account_key.key_size == 256 else "ES384"

    def post(self, url: str, payload: Any = None, use_jwk: bool = False,
             parsed: bool = True, retries: int = 3) -> tuple[int, dict, Any]:
        """
        POST-as-GET：payload 传 None 时发送空载荷。
        parsed=False 时返回原始字节（下载证书用）。
        """
        if payload is None:
            payload_b64 = ""
        else:
            payload_b64 = b64u(json.dumps(payload, separators=(",", ":")).encode())

        last_error: AcmeError | None = None
        attempt = 0
        network_failures = 0
        while attempt < retries:
            protected = {"alg": self._alg(), "nonce": self._take_nonce(), "url": url}
            if use_jwk:
                protected["jwk"] = self.public_jwk()
            else:
                if not self.kid:
                    raise AcmeError("内部错误：尚未注册 ACME 账号")
                protected["kid"] = self.kid

            protected_b64 = b64u(json.dumps(protected, separators=(",", ":")).encode())
            signing_input = f"{protected_b64}.{payload_b64}".encode()
            body = json.dumps({
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": self._sign(signing_input),
            }, separators=(",", ":")).encode()

            attempt += 1
            try:
                status, headers, raw = self._http(
                    "POST", url, data=body,
                    headers={"Content-Type": "application/jose+json", "Accept": "application/json"},
                )
            except AcmeError as exc:
                # 网络抖动自动重试（不消耗协议重试次数）：换新 nonce 后重发
                if exc.network and network_failures < 2:
                    network_failures += 1
                    last_error = exc
                    attempt -= 1
                    time.sleep(1.5 * network_failures)
                    continue
                raise
            if headers.get("replay-nonce"):
                with self._lock:
                    self._nonce = headers["replay-nonce"]

            if status >= 400:
                try:
                    problem = json.loads(raw)
                except Exception:
                    problem = {}
                ptype = problem.get("type", "")
                details = []
                for sub in problem.get("subproblems", []) or []:
                    ident = (sub.get("identifier") or {}).get("value", "")
                    details.append(f"{ident} {sub.get('detail', '')}".strip())
                message = problem.get("detail") or f"CA 返回 HTTP {status}"
                last_error = AcmeError(message, status, ptype, details)
                # badNonce 属于可重试错误
                if ptype.endswith(":badNonce") and attempt < retries:
                    self._nonce = None
                    continue
                raise last_error

            if not parsed:
                return status, headers, raw
            return status, headers, (json.loads(raw) if raw else {})

        raise last_error or AcmeError("请求失败")

    # ---------------------------- 账号 ---------------------------- #

    def register(self, email: str | None = None, phone: str | None = None,
                 tos_agreed: bool = True) -> dict:
        payload: dict[str, Any] = {"termsOfServiceAgreed": bool(tos_agreed)}
        contacts = []
        if email:
            contacts.append(f"mailto:{email}")
        if phone:
            contacts.append(f"tel:{phone}")
        if contacts:
            payload["contact"] = contacts

        status, headers, data = self.post(self.directory["newAccount"], payload, use_jwk=True)
        location = headers.get("location")
        if not location:
            raise AcmeError("CA 未返回账号 URL")
        self.kid = location
        return data

    def update_contact(self, contacts: list[str]) -> dict:
        _, _, data = self.post(self.kid, {"contact": contacts})
        return data

    # ---------------------------- 订单 / 授权 ---------------------------- #

    def new_order(self, domains: list[str]) -> tuple[str, dict]:
        identifiers = [{"type": "dns", "value": d} for d in domains]
        _, headers, order = self.post(self.directory["newOrder"], {"identifiers": identifiers})
        order_url = headers.get("location")
        if not order_url:
            raise AcmeError("CA 未返回订单 URL")
        return order_url, order

    def get_order(self, order_url: str) -> dict:
        _, _, order = self.post(order_url, None)
        return order

    def get_authz(self, authz_url: str) -> dict:
        _, _, authz = self.post(authz_url, None)
        return authz

    def trigger_challenge(self, challenge_url: str) -> dict:
        _, _, data = self.post(challenge_url, {})
        return data

    def finalize(self, order_url: str, csr_der: bytes) -> dict:
        order = self.get_order(order_url)
        finalize_url = order.get("finalize")
        if not finalize_url:
            raise AcmeError("订单缺少 finalize 地址")
        _, _, data = self.post(finalize_url, {"csr": b64u(csr_der)})
        return data

    def download_certificate(self, cert_url: str) -> str:
        _, _, raw = self.post(cert_url, None, parsed=False)
        return raw.decode("utf-8", "replace")

    def revoke(self, cert_pem: str, reason: int = 4) -> None:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        self.post(self.directory["revokeCert"], {
            "certificate": b64u(cert.public_bytes(serialization.Encoding.DER)),
            "reason": reason,
        })


# --------------------------------------------------------------------------- #
# 轮询 / 等待
# --------------------------------------------------------------------------- #

def _retry_after(headers: dict, default: float = 2.0) -> float:
    value = headers.get("retry-after")
    if not value:
        return default
    try:
        return max(1.0, min(10.0, float(value)))
    except ValueError:
        return default


def poll_authorization(client: AcmeClient, authz_url: str, timeout: float = 180.0) -> dict:
    """轮询授权状态直到 valid / invalid / 超时。"""
    deadline = time.time() + timeout
    while True:
        _, headers, authz = client.post(authz_url, None)
        status = authz.get("status")
        if status in ("valid", "invalid", "deactivated", "expired", "revoked"):
            return authz
        if time.time() > deadline:
            raise AcmeError(f"验证超时（{int(timeout)} 秒内未完成，当前状态：{status}）")
        time.sleep(_retry_after(headers))


def poll_order(client: AcmeClient, order_url: str, timeout: float = 180.0) -> dict:
    deadline = time.time() + timeout
    while True:
        _, headers, order = client.post(order_url, None)
        status = order.get("status")
        if status in ("valid", "invalid"):
            return order
        if time.time() > deadline:
            raise AcmeError(f"订单处理超时（当前状态：{status}）")
        time.sleep(_retry_after(headers))


def challenge_error(authz: dict) -> str:
    """从失败的授权中提取可读的错误原因。"""
    for ch in authz.get("challenges", []):
        err = ch.get("error")
        if err:
            detail = err.get("detail") or err.get("type") or "未知错误"
            return str(detail)
    return "CA 未能完成验证，原因未知"


# --------------------------------------------------------------------------- #
# CSR / 证书解析
# --------------------------------------------------------------------------- #

def build_csr(domains: list[str], key) -> bytes:
    """构造 CSR。

    注意：CN 必须原样使用域名（保留泛域名的 *. 前缀）。
    CA 在最终校验时会把 CSR 的 CommonName 与 SAN 合在一起，和订单标识做
    集合比对——CN 被改写（例如把 *.example.com 剥成 example.com）会导致
    "CSR does not specify same identifiers as Order" 错误。
    CN 超过 64 字符（X.509 的 ub-common-name 上限）时只能省略 CN，
    仅依靠 SAN 承载域名。
    """
    builder = x509.CertificateSigningRequestBuilder()
    subject = []
    cn = domains[0] if domains else ""
    if cn and len(cn) <= 64:
        subject.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    builder = builder.subject_name(x509.Name(subject))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False
    )
    csr = builder.sign(key, hashes.SHA256() if key.key_size <= 3072 else hashes.SHA384())
    return csr.public_bytes(serialization.Encoding.DER)


def split_chain(chain_pem: str) -> tuple[str, str]:
    """把 PEM 链拆成（叶子证书, 中间证书）。"""
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*", chain_pem, re.S)
    if not blocks:
        raise AcmeError("CA 返回的证书内容为空")
    leaf = blocks[0] if blocks[0].endswith("\n") else blocks[0] + "\n"
    rest = "".join(blocks[1:])
    return leaf, rest


def describe_certificate(cert_pem: str) -> dict:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        domains = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        domains = []
    issuer_cn = ""
    for attr in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME):
        issuer_cn = attr.value
        break
    cn = ""
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        cn = attr.value
        break

    def iso(dt):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""

    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    days_left = 0
    if not_after is not None:
        days_left = max(0, (not_after - datetime.datetime.now(datetime.timezone.utc)).days)

    return {
        "common_name": cn,
        "domains": domains,
        "issuer": issuer_cn or cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "X"),
        "not_before": iso(not_before),
        "not_after": iso(not_after),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "days_left": days_left,
    }


# --------------------------------------------------------------------------- #
# HTTP-01 验证服务器
# --------------------------------------------------------------------------- #

class ChallengeHttpServer:
    """
    临时 HTTP 服务，应答 /.well-known/acme-challenge/<token>。
    仅在「自动 HTTP 验证」模式下启动。
    """

    def __init__(self, port: int = 80):
        self.port = port
        self.tokens: dict[str, str] = {}
        self._server = None
        self._thread: threading.Thread | None = None
        self.requests: list[str] = []

    @property
    def running(self) -> bool:
        return self._server is not None

    def start(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):  # 静默，避免刷屏
                pass

            def do_GET(self):
                path = urllib.parse.urlparse(self.path).path
                prefix = "/.well-known/acme-challenge/"
                if path.startswith(prefix):
                    token = path[len(prefix):]
                    keyauth = outer.tokens.get(token)
                    if keyauth:
                        outer.requests.append(path)
                        body = keyauth.encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                outer.requests.append(path + " [404]")
                body = b"404 Not Found"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_HEAD = do_GET

        try:
            server = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
            server.daemon_threads = True
        except OSError as exc:
            raise AcmeError(
                f"无法监听端口 {self.port}：{exc}。"
                f"该端口可能被 IIS / Nginx / Apache 等程序占用，或需要管理员权限。"
                f"请改用「手动 HTTP」或「DNS 验证」方式。"
            ) from exc

        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        self._server = None

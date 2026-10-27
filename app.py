"""
Let's Encrypt 证书申请工具 —— 本地 Web 服务。

启动后浏览器打开 http://127.0.0.1:8899 ，按界面引导完成证书申请。
后端只监听本机回环地址，证书私钥不会离开本机。
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import acme_client as acme  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
DATA_DIR = BASE_DIR / "data"
CERT_DIR = BASE_DIR / "certs"
ACCOUNT_DIR = DATA_DIR / "accounts"

for d in (DATA_DIR, CERT_DIR, ACCOUNT_DIR):
    d.mkdir(parents=True, exist_ok=True)

VERSION = "1.0.0"
SESSIONS: dict[str, "Session"] = {}
SESSIONS_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
# 会话
# --------------------------------------------------------------------------- #

class Session:
    def __init__(self, config: dict):
        self.id = secrets.token_urlsafe(12)
        self.created_at = time.time()
        self.config = config
        self.state = "created"          # created → prepared → validated → issued
        self.logs: list[dict] = []
        self.client: acme.AcmeClient | None = None
        self.order_url: str | None = None
        self.order: dict = {}
        self.challenges: list[dict] = []
        self.http_server: acme.ChallengeHttpServer | None = None
        self.cert_pem = ""
        self.chain_pem = ""
        self.key_pem = ""
        self.cert_info: dict = {}
        self.output_dir: str | None = None
        self.preflight: dict = {}
        self.error: dict | None = None
        self.log("会话已创建", "info")

    # ---- 日志 ---- #
    def log(self, message: str, level: str = "info") -> None:
        self.logs.append({
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        })
        if len(self.logs) > 400:
            del self.logs[:100]
        mark = {"info": "·", "ok": "✓", "warn": "!", "error": "×"}.get(level, "·")
        print(f"  {mark} {message}")

    # ---- 序列化 ---- #
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "state": self.state,
            "config": {
                "domains": self.config["domains"],
                "email": self.config.get("email", ""),
                "challenge": self.config["challenge"],
                "staging": self.config.get("staging", False),
                "key_type": self.config.get("key_type", "ec256"),
                "http_port": self.config.get("http_port", 80),
                "webroot": self.config.get("webroot", ""),
            },
            "preflight": self.preflight,
            "challenges": self.challenges,
            "order_status": self.order.get("status") if self.order else None,
            "cert_info": self.cert_info,
            "output_dir": self.output_dir,
            "logs": self.logs[-120:],
            "error": self.error,
            "http_server_running": bool(self.http_server and self.http_server.running),
            "http_server_requests": (self.http_server.requests[-12:] if self.http_server else []),
        }


def _account_key_path(directory_url: str) -> Path:
    if "staging" in directory_url:
        slug = "staging"
    elif "acme-v02.api.letsencrypt.org" in directory_url:
        slug = "production"
    else:
        slug = "custom-" + re.sub(r"[^a-z0-9]+", "-", directory_url.lower())[:40]
    return ACCOUNT_DIR / f"{slug}.pem"


def _load_or_create_account_key(directory_url: str, sess: "Session"):
    path = _account_key_path(directory_url)
    if path.exists():
        try:
            key = acme.load_account_key(path.read_bytes())
            sess.log(f"复用已有 ACME 账号密钥（{path.name}）", "info")
            return key
        except Exception:
            sess.log("已有账号密钥无法读取，将重新生成", "warn")
    key = acme.generate_account_key()
    path.write_bytes(acme.pem_private_key(key))
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    sess.log(f"已生成新的 ACME 账号密钥（{path.name}）", "ok")
    return key


# --------------------------------------------------------------------------- #
# 业务动作
# --------------------------------------------------------------------------- #

def action_prepare(sess: Session) -> None:
    cfg = sess.config
    domains: list[str] = cfg["domains"]
    challenge_type = cfg["challenge"]
    directory_url = cfg.get("directory_url") or (
        acme.STAGING_DIRECTORY if cfg.get("staging") else acme.PRODUCTION_DIRECTORY
    )

    if any(d.startswith("*.") for d in domains) and challenge_type.startswith("http"):
        raise acme.AcmeError(
            "通配符证书（*.example.com）只能用 DNS 验证，请返回上一步切换为「DNS 验证」。"
        )

    # ---------- 环境预检查 ---------- #
    sess.log("开始环境预检查", "info")
    preflight: dict = {"dns": [], "warnings": [], "public_ip": None, "port_available": None}

    pub_ip = None
    if challenge_type == "http_auto":
        pub_ip = acme.public_ip()
        preflight["public_ip"] = pub_ip

    for domain in domains:
        info = {"domain": domain, "a": [], "aaaa": []}
        try:
            ips = acme.resolve_ips(domain)
            info["a"], info["aaaa"] = ips["A"], ips["AAAA"]
        except Exception:
            pass
        if not info["a"] and not info["aaaa"]:
            preflight["warnings"].append(
                f"域名 {domain} 没有解析到任何 IP，请先在域名服务商处配置 A/AAAA 记录。"
            )
        elif challenge_type.startswith("http") and pub_ip:
            if pub_ip not in info["a"]:
                preflight["warnings"].append(
                    f"域名 {domain} 解析到 {', '.join(info['a']) or '(无)'}，"
                    f"但本机公网出口 IP 是 {pub_ip}。如果它们不是同一台机器（或有 CDN 代理），"
                    f"HTTP 验证会失败。"
                )
        preflight["dns"].append(info)

    if challenge_type == "http_auto":
        port = int(cfg.get("http_port") or 80)
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("0.0.0.0", port))
            preflight["port_available"] = True
        except OSError:
            preflight["port_available"] = False
            preflight["warnings"].append(
                f"本机 {port} 端口已被占用（可能是 IIS/Nginx/Apache 正在运行），"
                f"自动 HTTP 模式可能无法启动。可以改用「手动 HTTP」方式，或先停掉占用端口的程序。"
            )
        finally:
            probe.close()

    sess.preflight = preflight
    sess.log("预检查完成", "ok")

    # ---------- ACME 账号 ---------- #
    sess.log(f"连接 CA：{directory_url}", "info")
    account_key = _load_or_create_account_key(directory_url, sess)
    client = acme.AcmeClient(directory_url, account_key=account_key)
    client.directory  # 触发目录读取，尽早暴露网络问题
    sess.client = client
    sess.log("ACME 目录读取成功", "ok")

    email = cfg.get("email") or None
    client.register(email=email, tos_agreed=True)
    sess.log(f"ACME 账号就绪（{client.kid}）", "ok")

    _start_order(sess, preflight)

    sess.state = "prepared"
    sess.log("准备完成，等待完成域名所有权验证", "ok")

    if (sess.order or {}).get("status") == "ready":
        sess.log("所有授权已通过，可直接签发证书", "ok")
        # 授权全部有效等同验证通过：推进状态机，否则前端跳过 validate 直接
        # finalize 时会因 state 仍为 prepared 而误报「域名验证尚未通过」
        sess.state = "validated"


def _start_order(sess: Session, preflight: dict) -> None:
    """创建 ACME 订单并准备验证素材（挑战 token、验证文件、DNS 记录值）。"""
    cfg = sess.config
    client = sess.client
    challenge_type = cfg["challenge"]
    domains = cfg["domains"]

    # ---------- 创建订单 ---------- #
    order_url, order = client.new_order(domains)
    sess.order_url, sess.order = order_url, order
    sess.log(f"订单已创建，状态：{order.get('status')}", "ok")

    authz_urls = order.get("authorizations") or []
    if not authz_urls:
        raise acme.AcmeError(
            f"CA 返回的订单中没有域名授权信息（订单状态：{order.get('status') or '未知'}），"
            f"请稍后重试；反复出现请更换网络环境后再试。"
        )

    # ---------- 收集挑战信息 ---------- #
    sess.challenges = []
    for authz_url in authz_urls:
        try:
            authz = client.get_authz(authz_url)
        except acme.AcmeError as exc:
            raise acme.AcmeError(
                f"获取授权信息失败（{authz_url}）：{exc.message}",
                exc.status, exc.problem_type, exc.details,
            )
        identifier = (authz.get("identifier") or {}).get("value", "")
        wildcard = bool(authz.get("wildcard"))
        domain_label = ("*." + identifier) if wildcard else identifier

        item = {
            "domain": domain_label,
            "authz_url": authz_url,
            "status": authz.get("status"),
            "challenge_type": None,
            "token": "",
            "keyauth": "",
            "http_url": "",
            "http_relative_path": "",
            "http_file_path": "",
            "dns_name": "",
            "dns_value": "",
            "error": None,
        }

        if authz.get("status") == "valid":
            item["status"] = "valid"
            sess.log(f"{domain_label} 的授权已有效，无需再次验证", "ok")
            sess.challenges.append(item)
            continue

        want = "dns-01" if challenge_type == "dns" else "http-01"
        chosen = None
        for ch in authz.get("challenges", []):
            if ch.get("type") == want:
                chosen = ch
                break
        if chosen is None:
            raise acme.AcmeError(
                f"CA 没有为 {domain_label} 提供 {want} 验证方式（通配符域名仅支持 dns-01）"
            )

        token = chosen.get("token", "")
        keyauth = f"{token}.{client.thumbprint}"
        item["challenge_type"] = want
        item["token"] = token
        item["keyauth"] = keyauth
        item["challenge_url"] = chosen.get("url")
        item["status"] = authz.get("status")

        if want == "http-01":
            port = int(sess.config.get("http_port") or 80)
            host_suffix = "" if port == 80 else f":{port}"
            item["http_url"] = f"http://{acme.base_domain_of(domain_label)}{host_suffix}/.well-known/acme-challenge/{token}"
            item["http_relative_path"] = f".well-known/acme-challenge/{token}"
        else:
            item["dns_name"] = f"_acme-challenge.{acme.base_domain_of(domain_label)}"
            import hashlib
            digest = hashlib.sha256(keyauth.encode()).digest()
            item["dns_value"] = acme.b64u(digest)

        sess.challenges.append(item)

    # ---------- 落地验证素材 ---------- #
    if challenge_type == "http_auto":
        port = int(cfg.get("http_port") or 80)
        server = acme.ChallengeHttpServer(port)
        server.tokens = {c["token"]: c["keyauth"] for c in sess.challenges if c["token"]}
        try:
            server.start()
            sess.http_server = server
            sess.log(f"已在本机 {port} 端口启动临时验证服务，共 {len(server.tokens)} 个待验证文件", "ok")
        except acme.AcmeError as exc:
            # 端口被占用时降级为手动放置文件，不中断整个流程
            sess.http_server = None
            sess.log(f"临时验证服务未能启动：{exc.message}", "warn")
            preflight["warnings"].append(
                f"临时验证服务未能启动（端口 {port}）。工具已改为显示验证文件内容，"
                f"请手动放到网站根目录的 .well-known/acme-challenge/ 下。"
            )
            sess.log("已降级为手动放置验证文件模式", "warn")
    elif challenge_type == "http_manual":
        webroot = (cfg.get("webroot") or "").strip()
        if webroot:
            root = Path(webroot)
            target = root / ".well-known" / "acme-challenge"
            try:
                target.mkdir(parents=True, exist_ok=True)
                for c in sess.challenges:
                    if not c["token"]:
                        continue
                    path = target / c["token"]
                    path.write_text(c["keyauth"], encoding="utf-8", newline="\n")
                    c["http_file_path"] = str(path)
                sess.log(f"已将 {len(sess.challenges)} 个验证文件写入 {target}", "ok")
            except Exception as exc:
                sess.log(f"写入网站根目录失败：{exc}", "warn")
        else:
            sess.log("未填写网站根目录，请按界面提示手动创建验证文件", "info")


def action_validate(sess: Session) -> None:
    if sess.state not in ("prepared", "validated"):
        raise acme.AcmeError("请先完成准备工作")
    if sess.client is None:
        raise acme.AcmeError("会话状态异常，请重新开始")

    # 先向 CA 复核每个授权的真实状态（上次可能只是轮询超时，实际已经通过）
    for c in sess.challenges:
        if c["status"] == "valid":
            continue
        try:
            authz = sess.client.get_authz(c["authz_url"])
            c["status"] = authz.get("status")
            if authz.get("status") == "valid":
                c["error"] = None
                sess.log(f"{c['domain']} 授权已有效", "ok")
        except acme.AcmeError:
            pass

    pending = [c for c in sess.challenges if c["status"] != "valid"]
    if not pending:
        sess.state = "validated"
        sess.log("所有域名已验证通过", "ok")
        return

    # 授权一旦被判定失败就无法再复用，必须换一张新订单重新验证
    dead = [c for c in sess.challenges if c["status"] in ("invalid", "timeout", "deactivated", "expired", "revoked")]
    if dead:
        sess.log("上次验证已使授权失效，正在为你重新创建订单…", "warn")
        if sess.http_server:
            sess.http_server.stop()
            sess.http_server = None
        _start_order(sess, sess.preflight if isinstance(sess.preflight, dict) else {})
        sess.state = "prepared"
        raise acme.AcmeError(
            "上次验证失败后原授权已失效，工具已自动创建新订单，界面上的验证信息已更新。"
            "请按最新的验证文件 / TXT 记录重新操作，然后再点「开始验证」。"
        )

    # DNS 模式下先检查记录是否生效，避免浪费验证次数
    if sess.config["challenge"] == "dns":
        for c in pending:
            values = acme.doh_query(c["dns_name"], "TXT") or []
            if c["dns_value"] in values:
                sess.log(f"DNS 记录已生效：{c['dns_name']}", "ok")
            else:
                sess.log(
                    f"DNS 记录尚未查询到：{c['dns_name']}（可能仍在传播中，继续尝试验证）", "warn"
                )

    sess.log("向 CA 提交验证请求…", "info")
    for c in pending:
        try:
            sess.client.trigger_challenge(c["challenge_url"])
        except acme.AcmeError as exc:
            c["error"] = exc.message
            sess.log(f"{c['domain']} 触发验证失败：{exc.message}", "error")

    for c in pending:
        try:
            authz = acme.poll_authorization(sess.client, c["authz_url"], timeout=120)
            c["status"] = authz.get("status")
            if authz.get("status") == "valid":
                c["error"] = None
                sess.log(f"{c['domain']} 验证通过", "ok")
            else:
                c["error"] = acme.challenge_error(authz)
                sess.log(f"{c['domain']} 验证失败：{c['error']}", "error")
        except acme.AcmeError as exc:
            c["error"] = exc.message
            c["status"] = "timeout"
            sess.log(f"{c['domain']} 验证未完成：{exc.message}", "error")

    failed = [c for c in sess.challenges if c["status"] != "valid"]
    if failed:
        sess.state = "prepared"
        raise acme.AcmeError(
            "部分域名验证未通过：" + "；".join(f"{c['domain']}（{c['error'] or c['status']}）" for c in failed)
        )

    sess.state = "validated"
    if sess.http_server:
        sess.http_server.stop()
        sess.log("验证通过，已关闭临时验证服务", "info")
    # 刷新订单状态
    try:
        sess.order = sess.client.get_order(sess.order_url)
    except Exception:
        pass
    sess.log("全部域名验证通过，可以签发证书", "ok")


def action_finalize(sess: Session) -> None:
    if sess.state == "issued":
        return

    if sess.client is None or not sess.order_url:
        raise acme.AcmeError("会话状态异常，请重新开始")

    if sess.state not in ("validated", "issued"):
        # 兜底：授权复用时订单可能直接 ready，而状态机未推进。向 CA 复核订单状态，
        # 确已就绪则放行，避免误报「域名验证尚未通过」。
        try:
            sess.order = sess.client.get_order(sess.order_url)
        except acme.AcmeError:
            pass
        if (sess.order or {}).get("status") in ("ready", "valid"):
            sess.state = "validated"
            sess.log("复核订单状态：授权已全部有效，继续签发", "ok")
        else:
            raise acme.AcmeError("域名验证尚未通过，无法签发证书")

    cfg = sess.config
    sess.log(f"生成证书私钥（{cfg.get('key_type')}）", "info")
    key = acme.generate_cert_key(cfg.get("key_type", "ec256"))
    key_pem = acme.pem_private_key(key)

    sess.log("构造 CSR 并提交签发请求", "info")
    csr_der = acme.build_csr(cfg["domains"], key)
    try:
        sess.client.finalize(sess.order_url, csr_der)
    except acme.AcmeError as exc:
        raise acme.AcmeError(f"签发失败：{exc.message}", exc.status, exc.problem_type, exc.details)

    order = acme.poll_order(sess.client, sess.order_url, timeout=120)
    sess.order = order
    if order.get("status") != "valid" or not order.get("certificate"):
        err = order.get("error") or {}
        raise acme.AcmeError(
            f"证书签发失败：{err.get('detail') or order.get('status')}"
        )

    sess.log("证书签发成功，正在下载", "info")
    chain_pem = sess.client.download_certificate(order["certificate"])
    leaf_pem, issuer_pem = acme.split_chain(chain_pem)

    stem = re.sub(r"[^a-z0-9.-]+", "-", cfg["domains"][0].replace("*.", "wildcard-")) or "cert"
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = CERT_DIR / f"{stem}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "privkey.pem").write_bytes(key_pem)
    (out_dir / "cert.pem").write_text(leaf_pem, encoding="utf-8")
    (out_dir / "chain.pem").write_text(issuer_pem, encoding="utf-8")
    (out_dir / "fullchain.pem").write_text(leaf_pem + issuer_pem, encoding="utf-8")
    try:
        os.chmod(out_dir / "privkey.pem", 0o600)
    except Exception:
        pass

    info = acme.describe_certificate(leaf_pem)
    info["directory"] = "staging" if cfg.get("staging") else "production"
    (out_dir / "cert-info.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    sess.cert_pem, sess.chain_pem, sess.key_pem = leaf_pem, issuer_pem, key_pem.decode()
    sess.cert_info = info
    sess.output_dir = str(out_dir)
    sess.state = "issued"
    sess.error = None
    sess.log(f"证书已保存到 {out_dir}", "ok")
    if sess.http_server:
        sess.http_server.stop()


def action_check_dns(sess: Session) -> dict:
    """检查 DNS-01 的 TXT 记录是否已经全网可见。"""
    results = []
    for c in sess.challenges:
        if not c["dns_name"]:
            continue
        values = acme.doh_query(c["dns_name"], "TXT")
        if values is None:
            results.append({"domain": c["domain"], "dns_name": c["dns_name"], "state": "unknown",
                            "found": [], "expected": c["dns_value"]})
            continue
        results.append({
            "domain": c["domain"],
            "dns_name": c["dns_name"],
            "state": "ok" if c["dns_value"] in values else "pending",
            "found": values,
            "expected": c["dns_value"],
        })
    ok = all(r["state"] == "ok" for r in results) if results else False
    sess.log(
        "DNS 记录检查：" + ("全部已生效" if ok else "部分记录尚未生效"),
        "ok" if ok else "warn",
    )
    return {"records": results, "all_ok": ok}


# --------------------------------------------------------------------------- #
# HTTP 处理
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"LetsEncryptTool/{VERSION}"

    def log_message(self, fmt, *args):
        pass

    # ---- 工具 ---- #
    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, data, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _ok(self, data=None):
        self._json({"ok": True, "data": data})

    def _fail(self, message: str, status: int = 400, extra: dict | None = None):
        payload = {"ok": False, "error": {"message": message}}
        if extra:
            payload["error"].update(extra)
        self._json(payload, status)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "::1", "")
    # ---- 路由 ---- #
    def do_GET(self):
        self._route("GET")

    def do_HEAD(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method: str):
        if not self._host_ok():
            self._fail("只允许通过 127.0.0.1 访问本工具", 403)
            return
        path = urllib.parse.urlparse(self.path).path
        try:
            if method == "GET":
                self._handle_get(path)
            else:
                self._handle_post(path)
        except acme.AcmeError as exc:
            self._fail(exc.message, 400, {"type": exc.problem_type, "details": exc.details})
        except Exception as exc:
            traceback.print_exc()
            self._fail(f"服务器内部错误：{exc}", 500)

    def _handle_get(self, path: str):
        if path in ("/", "/index.html"):
            self._serve_file(WEB_DIR / "index.html")
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            candidate = (WEB_DIR / rel).resolve()
            if WEB_DIR.resolve() in candidate.parents and candidate.is_file():
                self._serve_file(candidate)
            else:
                self._fail("文件不存在", 404)
            return
        if path == "/api/health":
            self._ok({"version": VERSION, "python": sys.version.split()[0]})
            return
        m = re.match(r"^/api/sessions/([A-Za-z0-9_-]+)$", path)
        if m:
            sess = SESSIONS.get(m.group(1))
            if not sess:
                self._fail("会话不存在或已失效", 404)
                return
            self._ok(sess.to_dict())
            return
        m = re.match(r"^/api/sessions/([A-Za-z0-9_-]+)/download/([a-z]+)$", path)
        if m:
            self._download(m.group(1), m.group(2))
            return
        m = re.match(r"^/api/sessions/([A-Za-z0-9_-]+)/logs$", path)
        if m:
            sess = SESSIONS.get(m.group(1))
            if not sess:
                self._fail("会话不存在", 404)
                return
            self._ok({"logs": sess.logs, "requests": sess.http_server.requests[-40:] if sess.http_server else []})
            return
        self._fail("未找到该地址", 404)

    def _handle_post(self, path: str):
        body = self._body()

        if path == "/api/sessions":
            cfg = self._build_config(body)
            sess = Session(cfg)
            with SESSIONS_LOCK:
                SESSIONS[sess.id] = sess
            self._ok(sess.to_dict())
            return

        m = re.match(r"^/api/sessions/([A-Za-z0-9_-]+)/(prepare|validate|finalize|check-dns|stop-http)$", path)
        if not m:
            self._fail("未找到该地址", 404)
            return
        sess = SESSIONS.get(m.group(1))
        if not sess:
            self._fail("会话不存在或已失效", 404)
            return
        action = m.group(2)

        try:
            if action == "prepare":
                sess.error = None
                action_prepare(sess)
                self._ok(sess.to_dict())
            elif action == "validate":
                action_validate(sess)
                self._ok(sess.to_dict())
            elif action == "finalize":
                action_finalize(sess)
                self._ok(sess.to_dict())
            elif action == "check-dns":
                self._ok(action_check_dns(sess))
            elif action == "stop-http":
                if sess.http_server:
                    sess.http_server.stop()
                    sess.log("已手动关闭临时验证服务", "info")
                self._ok(sess.to_dict())
        except acme.AcmeError as exc:
            sess.error = {"message": exc.message, "details": exc.details, "type": exc.problem_type}
            sess.log(exc.message, "error")
            self._json({"ok": False, "error": sess.error, "data": sess.to_dict()}, 400)
        except Exception as exc:
            traceback.print_exc()
            sess.error = {"message": str(exc), "details": [], "type": ""}
            sess.log(f"发生异常：{exc}", "error")
            self._json({"ok": False, "error": sess.error, "data": sess.to_dict()}, 500)

    # ---- 配置校验 ---- #
    def _build_config(self, body: dict) -> dict:
        domains = acme.normalize_domains(body.get("domains") or "")
        email = (body.get("email") or "").strip()
        if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            raise acme.AcmeError("邮箱格式不正确（用于接收证书到期提醒，可留空）")

        challenge = body.get("challenge") or "http_auto"
        if challenge not in ("http_auto", "http_manual", "dns"):
            raise acme.AcmeError("未知的验证方式")
        if challenge in ("http_auto", "http_manual") and any(d.startswith("*.") for d in domains):
            raise acme.AcmeError("通配符域名只能使用 DNS 验证方式")

        # 注意：*.example.com 不覆盖 example.com，两者可同时申请，不能去重

        key_type = body.get("key_type") or "ec256"
        if key_type not in ("ec256", "ec384", "rsa2048", "rsa4096"):
            raise acme.AcmeError("未知的密钥类型")

        try:
            http_port = int(body.get("http_port") or 80)
        except Exception:
            http_port = 80
        if not (1 <= http_port <= 65535):
            raise acme.AcmeError("端口号必须在 1-65535 之间")

        staging = bool(body.get("staging"))
        directory_url = body.get("directory_url") or (
            acme.STAGING_DIRECTORY if staging else acme.PRODUCTION_DIRECTORY
        )

        return {
            "domains": domains,
            "email": email,
            "challenge": challenge,
            "staging": staging,
            "key_type": key_type,
            "http_port": http_port,
            "webroot": (body.get("webroot") or "").strip(),
            "directory_url": directory_url,
        }

    # ---- 文件 ---- #
    def _serve_file(self, path: Path):
        if not path.is_file():
            self._fail("文件不存在", 404)
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".ico": "image/x-icon",
        }.get(path.suffix.lower(), "application/octet-stream")
        self._send(200, path.read_bytes(), ctype)

    def _download(self, sid: str, kind: str):
        sess = SESSIONS.get(sid)
        if not sess:
            self._fail("会话不存在", 404)
            return
        if sess.state != "issued" or not sess.output_dir:
            self._fail("证书尚未签发完成", 400)
            return

        if kind == "bundle":
            buffer = BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "cert-info.json"):
                    p = Path(sess.output_dir) / name
                    if p.exists():
                        zf.write(p, arcname=name)
            data = buffer.getvalue()
            self._send(200, data, "application/zip", {
                "Content-Disposition": 'attachment; filename="certificates.zip"'
            })
            return

        mapping = {
            "cert": ("cert.pem", sess.cert_pem),
            "chain": ("chain.pem", sess.chain_pem),
            "fullchain": ("fullchain.pem", sess.cert_pem + sess.chain_pem),
            "key": ("privkey.pem", sess.key_pem),
        }
        if kind not in mapping:
            self._fail("不支持的文件", 404)
            return
        filename, content = mapping[kind]
        self._send(200, content.encode(), "application/x-pem-file", {
            "Content-Disposition": f'attachment; filename="{filename}"'
        })

    # ---- 静态资源回退 ---- #
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError):
            self.close_connection = True


# --------------------------------------------------------------------------- #
# 启动
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="Let's Encrypt 证书申请工具")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    parser.add_argument("--port", type=int, default=8899, help="界面端口（默认 8899）")
    parser.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}/"
    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        print(f"\n启动失败：端口 {args.port} 无法监听（{exc}）")
        print(f"可以换一个端口，例如：python app.py --port 8898\n")
        sys.exit(1)

    print("=" * 62)
    print("  Let's Encrypt 证书申请工具")
    print("=" * 62)
    print(f"  界面地址：{url}")
    print(f"  证书目录：{CERT_DIR}")
    print(f"  按 Ctrl+C 退出")
    print("=" * 62)

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

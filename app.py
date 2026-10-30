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
from dns_providers import DnsError, provider_label  # noqa: E402
from dns_providers import check as dns_check  # noqa: E402
from dns_providers import create as create_dns_provider  # noqa: E402

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
        self.dns_client = None            # provider 实例（延迟创建）
        self.dns_records: list[dict] = []  # 由本工具写入的记录，用于收尾清理
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
                "dns_provider": self.config.get("dns_provider", "manual"),
            },
            "dns_records": [
                {
                    "name": r.get("name", ""),
                    "zone": r.get("zone", ""),
                    "rr": r.get("rr", ""),
                    "created": r.get("created", False),
                }
                for r in self.dns_records
            ],
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

    # 换新订单时，上一轮写入的记录已经没有意义，先清掉
    if sess.dns_records:
        action_cleanup_dns(sess, quiet=True)

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

    # ---------- 自动写入 DNS 记录 ---------- #
    if dns_auto_enabled(sess):
        try:
            action_write_dns(sess)
        except Exception:
            # 只写了一半就失败：把已经建好的记录收回去，避免留下垃圾
            action_cleanup_dns(sess, quiet=True)
            raise


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

    # 记录是否生效：自动写记录时以权威服务器为准，手动模式退回公共 DNS 查询
    if dns_auto_enabled(sess):
        _wait_dns_records(sess, pending)
    elif sess.config["challenge"] == "dns":
        for c in pending:
            values = acme.doh_query(c["dns_name"], "TXT") or []
            if c["dns_value"] in values:
                sess.log(f"DNS 记录已生效：{c['dns_name']}", "ok")
            else:
                sess.log(
                    f"DNS 记录尚未查询到：{c['dns_name']}（可能仍在传播中，继续尝试验证）", "warn"
                )

    try:
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
    finally:
        # 验证结束（无论成败）记录都不再有价值：成功即可删，失败也是单次有效
        if dns_auto_enabled(sess):
            action_cleanup_dns(sess)

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
    """检查 TXT 记录是否已经生效。

    自动写记录的会话优先问权威服务器（不受递归缓存影响），手动模式仍用 DoH。
    """
    auto = (sess.config.get("dns_provider") or "manual") != "manual"
    results = []
    for c in sess.challenges:
        if not c["dns_name"]:
            continue
        item = {
            "domain": c["domain"],
            "dns_name": c["dns_name"],
            "expected": c["dns_value"],
            "found": [],
            "source": "authoritative" if auto else "public",
            "detail": "",
        }
        if auto:
            try:
                info = dns_check.authoritative_txt(c["dns_name"])
            except DnsError as exc:
                item.update({"state": "unknown", "detail": exc.readable()})
                results.append(item)
                continue
            item["found"] = info["values"]
            item["detail"] = "；".join(
                f"{s['ns']}：{'不可达' if s['error'] else '%d 条' % len(s['values'])}"
                for s in info["servers"]
            )
            item["state"] = "ok" if c["dns_value"] in info["values"] else "pending"
        else:
            values = acme.doh_query(c["dns_name"], "TXT")
            if values is None:
                item.update({"state": "unknown", "detail": "公共 DNS 查询失败"})
                results.append(item)
                continue
            item["found"] = values
            item["state"] = "ok" if c["dns_value"] in values else "pending"
        results.append(item)

    ok = all(r["state"] == "ok" for r in results) if results else False
    sess.log(
        "DNS 记录检查：" + ("全部已生效" if ok else "部分记录尚未生效"),
        "ok" if ok else "warn",
    )
    return {"records": results, "all_ok": ok}


# --------------------------------------------------------------------------- #
# 自动写入解析记录（DNS-01 免手工）
# --------------------------------------------------------------------------- #

def dns_provider_name(sess: Session) -> str:
    return (sess.config.get("dns_provider") or "manual").strip()


def dns_auto_enabled(sess: Session) -> bool:
    return dns_provider_name(sess) not in ("", "manual")


def _dns_client(sess: Session):
    if sess.dns_client is None:
        cfg = sess.config
        sess.dns_client = create_dns_provider(
            dns_provider_name(sess),
            cfg.get("dns_access_key_id", ""),
            cfg.get("dns_access_key_secret", ""),
        )
    return sess.dns_client


def _remember_record(sess: Session, record: dict) -> None:
    for existing in sess.dns_records:
        if existing.get("record_id") and existing["record_id"] == record.get("record_id"):
            existing.update(record)
            return
        if not record.get("record_id") and existing.get("name") == record.get("name"):
            existing.update(record)
            return
    sess.dns_records.append(record)


def action_write_dns(sess: Session) -> int:
    """把当前订单需要的 TXT 记录写到云解析。返回写入条数。"""
    pending = [c for c in sess.challenges if c.get("dns_name") and c["status"] != "valid"]
    if not pending:
        return 0

    provider = _dns_client(sess)
    label = provider_label(dns_provider_name(sess))
    ttl = int(sess.config.get("dns_ttl") or 600)
    sess.log(f"向{label}写入 {len(pending)} 条 TXT 记录", "info")

    try:
        zones = provider.zones()
    except DnsError as exc:
        raise acme.AcmeError(f"读取托管域名失败：{exc.readable()}")
    sess.log(f"账号下托管域名共 {len(zones)} 个，开始定位记录所属域名", "info")

    for c in pending:
        try:
            info = provider.ensure_txt(c["dns_name"], c["dns_value"], ttl=ttl)
        except DnsError as exc:
            raise acme.AcmeError(f"写入解析记录失败：{exc.readable()}")
        c["dns_auto"] = True
        c["dns_zone"] = info["zone"]
        c["dns_record_id"] = info["record_id"]
        _remember_record(sess, {
            "name": c["dns_name"],
            "zone": info["zone"],
            "rr": info["rr"],
            "record_id": info["record_id"],
            "created": info["created"],
            "domain": c["domain"],
        })
        if info["created"]:
            sess.log(f"已添加 TXT：{c['dns_name']}（{info['zone']} / {info['rr']}）", "ok")
        else:
            sess.log(f"已存在同值记录，直接复用：{c['dns_name']}", "info")
    return len(pending)


def _wait_dns_records(sess: Session, pending: list[dict]) -> None:
    """等权威服务器能查到记录，再提交验证。"""
    timeout = float(sess.config.get("dns_wait") or 180)
    # 通配符与裸域会落在同一个记录名上，按名字归并，一次等齐所有期望值
    targets: dict[str, list[str]] = {}
    for c in pending:
        if not c.get("dns_auto") or not c.get("dns_name"):
            continue
        targets.setdefault(c["dns_name"], []).append(c["dns_value"])

    missing: list[str] = []
    for name, values in targets.items():
        sess.log(f"等待 {name} 在权威服务器上生效（最多 {int(timeout)} 秒）", "info")
        ok, detail = dns_check.wait_for_txt(name, values, timeout=timeout, log=sess.log)
        for c in pending:
            if c.get("dns_name") == name:
                c["dns_visible"] = ok
        if ok:
            sess.log(f"{name} 已生效", "ok")
            continue
        missing.append(name)
        servers = detail.get("servers") or []
        if servers:
            sess.log(
                "未生效的服务器："
                + "；".join(
                    f"{s['ns']}（{'不可达' if s['error'] else '无该值'}）" for s in servers
                ),
                "warn",
            )
    if missing:
        raise acme.AcmeError(
            "TXT 记录尚未在权威服务器生效，为避免浪费验证次数，暂未提交验证："
            + "、".join(missing)
            + "。记录已保留，可稍等几十秒后重新点击「开始验证」；"
            "若长时间不生效，请检查域名的 NS 是否确实指向该解析服务商。"
        )


def action_cleanup_dns(sess: Session, quiet: bool = False) -> int:
    """删除本会话写入的记录。失败只告警，不中断主流程。"""
    records = list(sess.dns_records)
    if not records:
        return 0
    provider = sess.dns_client
    removed = 0
    for record in records:
        try:
            provider.delete_record(record.get("record_id", ""))
            removed += 1
        except Exception as exc:
            message = getattr(exc, "message", str(exc))
            sess.log(f"清理 {record.get('name', '')} 失败：{message}", "warn")
    sess.dns_records = []
    if removed and not quiet:
        sess.log(f"已清理 {removed} 条临时 TXT 记录", "info")
    return removed


# --------------------------------------------------------------------------- #
# 阿里云 ALB 部署（界面后端）
# --------------------------------------------------------------------------- #

DEPLOY_DIR = BASE_DIR / "deploy"
ALB_ENV_FILE = DATA_DIR / "alb.env"
DNS_ENV_FILE = DATA_DIR / "dns.env"

_ALBD = None
DEPLOY_SERIAL = threading.Lock()
DEPLOY_JOBS: dict[str, "DeployJob"] = {}
DEPLOY_JOBS_LOCK = threading.Lock()

EXIT_HINTS = {
    0: "成功",
    1: "本地证书问题",
    2: "凭证或权限问题",
    3: "证书上传失败",
    4: "监听证书替换失败",
    5: "线上校验未通过",
    6: "运行环境问题",
    7: "网络或域名解析问题",
}


def alb_module():
    """延迟载入 deploy/alb_deploy.py，避免主界面因缺少可选依赖而起不来。"""
    global _ALBD
    if _ALBD is None:
        if str(DEPLOY_DIR) not in sys.path:
            sys.path.insert(0, str(DEPLOY_DIR))
        import alb_deploy as mod
        _ALBD = mod
    return _ALBD


class DeployJob:
    """一次部署运行。日志由 alb_deploy 的 log sink 推入，前端轮询。"""

    def __init__(self, params: dict):
        self.id = secrets.token_urlsafe(9)
        self.params = params
        self.logs: list[dict] = []
        self.running = True
        self.exit_code: int | None = None
        self.started_at = time.time()
        self.finished_at: float | None = None

    def append(self, entry: dict) -> None:
        self.logs.append({
            "time": entry.get("time") or datetime.datetime.now().strftime("%H:%M:%S"),
            "level": entry.get("level", "info"),
            "message": entry.get("message", ""),
        })
        if len(self.logs) > 800:
            del self.logs[:200]

    def note(self, message: str, level: str = "info") -> None:
        self.append({"level": level, "message": message})

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "running": self.running,
            "exit_code": self.exit_code,
            "exit_hint": EXIT_HINTS.get(self.exit_code or 0, ""),
            "elapsed": round((self.finished_at or time.time()) - self.started_at, 1),
            "params": self.params,
            "logs": self.logs[-250:],
        }


def list_cert_bundles() -> list:
    """列出 certs/ 下可部署的证书，附带校验结论。"""
    mod = alb_module()
    items: list[dict] = []
    if not CERT_DIR.is_dir():
        return items

    dirs = [d for d in CERT_DIR.iterdir() if d.is_dir() and (d / "fullchain.pem").is_file()]
    dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    for d in dirs:
        stat = d.stat()
        item = {
            "name": d.name,
            "path": str(d),
            "saved_at": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            "usable": True,
            "error": "",
            "cn": "",
            "san": [],
            "serial": "",
            "not_after": "",
            "days_left": 0,
            "cert_count": 0,
            "key_type": "",
        }
        try:
            info = mod.load_bundle(d, quiet=True)
            item.update({
                "cn": info["cn"],
                "san": info["san"],
                "serial": info["serial"],
                "not_after": info["not_after"].strftime("%Y-%m-%d"),
                "days_left": info["days_left"],
                "cert_count": info["cert_count"],
                "key_type": info["key_type"],
            })
        except Exception as exc:
            item["usable"] = False
            item["error"] = getattr(exc, "message", str(exc))
        items.append(item)
    return items


def _read_env_pairs(path: Path) -> dict:
    pairs: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            pairs[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        return {}
    return pairs


def read_saved_credential(path: Path | None = None) -> dict:
    """只回传掩码后的 AK，绝不把 Secret 送到前端。"""
    target = path or ALB_ENV_FILE
    if not target.is_file():
        return {"saved": False, "masked": "", "updated_at": ""}

    pairs = _read_env_pairs(target)
    ak = pairs.get("ALIBABA_CLOUD_ACCESS_KEY_ID", "") or pairs.get("ACCESS_KEY_ID", "")
    sk = pairs.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "") or pairs.get("ACCESS_KEY_SECRET", "")
    if not ak or not sk:
        return {"saved": False, "masked": "", "updated_at": ""}

    try:
        stamp = datetime.datetime.fromtimestamp(target.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
    except Exception:
        stamp = ""
    masked = (ak[:4] + "***" + ak[-4:]) if len(ak) > 8 else "***"
    return {"saved": True, "masked": masked, "updated_at": stamp}


def load_saved_secret(path: Path | None = None) -> tuple:
    """取回完整凭证，仅在服务端内部用于发起请求。"""
    target = path or ALB_ENV_FILE
    if not target.is_file():
        return "", ""
    pairs = _read_env_pairs(target)
    ak = pairs.get("ALIBABA_CLOUD_ACCESS_KEY_ID", "") or pairs.get("ACCESS_KEY_ID", "")
    sk = pairs.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "") or pairs.get("ACCESS_KEY_SECRET", "")
    return ak, sk


def save_credential(ak: str, sk: str, path: Path | None = None,
                    comment: str = "") -> None:
    target = path or ALB_ENV_FILE
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    header = comment or (
        "# 阿里云 RAM 凭证 —— 本文件位于 data/ 下，已被 .gitignore 排除，请勿提交到仓库。\n"
        "# 建议使用仅授予 ALB/CAS 相关动作的子账号，不要使用主账号 AccessKey。\n"
    )
    text = (
        "%sALIBABA_CLOUD_ACCESS_KEY_ID=%s\n"
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET=%s\n" % (header, ak, sk)
    )
    target.write_text(text, encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except Exception:
        pass


def resolve_deploy_credential(body: dict) -> tuple:
    """按优先级取凭证：表单填写的 > 已保存的。"""
    ak = (body.get("access_key_id") or "").strip()
    sk = (body.get("access_key_secret") or "").strip()
    if ak and sk:
        return ak, sk
    if body.get("use_saved", True):
        saved_ak, saved_sk = load_saved_secret()
        if saved_ak and saved_sk:
            return saved_ak, saved_sk
    raise acme.AcmeError("缺少 AccessKey：请填写 AccessKey ID 与 Secret，或勾选使用已保存的凭证")


def resolve_dns_credential(body: dict, required: bool = True) -> tuple:
    """解析自动写解析用的凭证；与部署凭证分开存放，便于分配给权限更小的子账号。"""
    ak = (body.get("dns_access_key_id") or body.get("access_key_id") or "").strip()
    sk = (body.get("dns_access_key_secret") or body.get("access_key_secret") or "").strip()
    if ak and sk:
        return ak, sk
    if body.get("use_saved", True):
        saved_ak, saved_sk = load_saved_secret(DNS_ENV_FILE)
        if saved_ak and saved_sk:
            return saved_ak, saved_sk
    if not required:
        return "", ""
    raise acme.AcmeError(
        "缺少云解析 AccessKey：自动写入 TXT 记录需要一个具备云解析权限的 RAM 子账号"
    )


def _deploy_argv(params: dict) -> list:
    argv: list = []
    for lsr in params["listeners"]:
        argv += ["--listener-id", lsr]
    argv += ["--region", params["region"]]
    argv += ["--role", params["role"]]
    argv += ["--cert-dir", params["cert_dir"]]
    if params.get("verify_host"):
        argv += ["--verify-host", params["verify_host"]]
    if params.get("dry_run"):
        argv.append("--dry-run")
    if params.get("force_upload"):
        argv.append("--force-upload")
    if params.get("prune_old_cert"):
        argv.append("--prune-old-cert")
    if params.get("prune_additional"):
        argv.append("--prune-additional")
    if params.get("verbose"):
        argv.append("--verbose")
    return argv


def _listener_id_hint(value: str) -> str:
    """识别常见的“填错层级”的情况，给出可操作的提示。"""
    low = value.lower()
    prefix = low.split("-", 1)[0] if "-" in low else low
    table = {
        "alb": "ALB 实例 ID",
        "lsg": "服务器组 ID",
        "sgp": "服务器组 ID",
        "rule": "转发规则 ID",
        "acl": "访问控制策略组 ID",
    }
    if prefix in table:
        label = table[prefix]
        joiner = " " if label[0].isascii() else ""
        return "%s 是%s%s，不是监听 ID；请在实例 → 监听 中复制 lsn- 开头的监听 ID" % (
            value,
            joiner,
            label,
        )
    if low.startswith("http") or "/" in value:
        return "请填写监听 ID，不要填 URL 或域名：%s" % value
    return ""


def parse_deploy_params(body: dict) -> dict:
    mod = alb_module()

    raw_listeners = body.get("listeners") or ""
    if isinstance(raw_listeners, list):
        raw_listeners = ",".join(str(x) for x in raw_listeners)
    listeners: list[str] = []
    for part in re.split(r"[,;\s]+", str(raw_listeners)):
        part = part.strip()
        if part and part not in listeners:
            listeners.append(part)
    if not listeners:
        raise acme.AcmeError("请填写至少一个监听 ID（形如 lsn-xxxxxxxx）")
    for lsr in listeners:
        if re.match(r"^lsn-[A-Za-z0-9]+$", lsr):
            continue
        # 兼容早期误写的 lsr- 前缀，真正的 ALB 监听 ID 是 lsn-
        if re.match(r"^lsr-[A-Za-z0-9]+$", lsr):
            continue
        hint = _listener_id_hint(lsr)
        if hint:
            raise acme.AcmeError(hint)
        raise acme.AcmeError("监听 ID 格式不正确：%s（应以 lsn- 开头）" % lsr)

    cert_dir = (body.get("cert_dir") or "").strip()
    if not cert_dir:
        raise acme.AcmeError("请选择要部署的证书")
    candidate = Path(cert_dir).resolve()
    if CERT_DIR.resolve() not in candidate.parents:
        raise acme.AcmeError("证书目录必须位于 certs/ 下")
    if not (candidate / "fullchain.pem").is_file():
        raise acme.AcmeError("所选目录缺少 fullchain.pem")

    role = body.get("role") or "default"
    if role not in ("default", "additional"):
        raise acme.AcmeError("证书用途取值不正确")

    region = (body.get("region") or "cn-hangzhou").strip()
    if not re.match(r"^[a-z0-9-]+$", region):
        raise acme.AcmeError("地域格式不正确")

    verify_host = (body.get("verify_host") or "").strip().lower()
    if verify_host and not re.match(r"^[a-z0-9.*-]+$", verify_host):
        raise acme.AcmeError("校验域名格式不正确")

    return {
        "listeners": listeners,
        "region": region,
        "role": role,
        "cert_dir": str(candidate),
        "cert_name": candidate.name,
        "verify_host": verify_host,
        "dry_run": bool(body.get("dry_run")),
        "force_upload": bool(body.get("force_upload")),
        "prune_old_cert": bool(body.get("prune_old_cert")),
        "prune_additional": bool(body.get("prune_additional")),
        "verbose": bool(body.get("verbose", True)),
    }


def run_deploy_job(job: DeployJob, params: dict, ak: str, sk: str) -> None:
    mod = alb_module()
    try:
        mod.set_log_sink(job.append)
        mod.set_credentials(ak, sk)
        mod.set_verbose(params.get("verbose", False))
        job.note("开始部署：监听 %s ｜ 地域 %s ｜ 证书 %s" % (
            ", ".join(params["listeners"]), params["region"], params["cert_name"]), "step")
        if params["dry_run"]:
            job.note("当前为预演模式，只查询现状，不会上传或替换任何证书", "warn")
        job.exit_code = mod.main(_deploy_argv(params))
    except mod.DeployError as exc:
        job.note(exc.message, "fail")
        if exc.detail:
            job.note(exc.detail, "debug")
        job.exit_code = exc.exit_code
    except Exception as exc:
        traceback.print_exc()
        job.note("部署过程出现未预期错误：%s: %s" % (type(exc).__name__, exc), "fail")
        job.exit_code = 6
    finally:
        mod.set_log_sink(None)
        mod.set_credentials("", "")
        job.running = False
        job.finished_at = time.time()
        if job.exit_code == 0:
            job.note("部署结束（耗时 %.1f 秒）" % (job.finished_at - job.started_at), "ok")
        else:
            job.note("部署结束，退出码 %s：%s" % (
                job.exit_code, EXIT_HINTS.get(job.exit_code, "未知")), "fail")


def probe_aliyun(ak: str, sk: str, region: str) -> dict:
    """验证凭证并列出该地域的监听，一次调用解决「AK 对不对、有哪些监听」。"""
    mod = alb_module()
    if not DEPLOY_SERIAL.acquire(blocking=False):
        raise acme.AcmeError("有部署任务正在运行，请稍后再试")
    try:
        clients = mod.AliyunClients(ak, sk, region)
        listeners = clients.list_listeners()
        cas_total = None
        cas_error = ""
        try:
            cas_total = clients.probe_cas()
        except Exception as exc:
            cas_error = getattr(exc, "message", str(exc))
        return {"listeners": listeners, "cas_total": cas_total, "cas_error": cas_error}
    except mod.DeployError as exc:
        raise acme.AcmeError(exc.message)
    finally:
        DEPLOY_SERIAL.release()


# --------------------------------------------------------------------------- #
# 配置校验（Web 与命令行共用）
# --------------------------------------------------------------------------- #

def build_config(body: dict) -> dict:
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

    dns_provider = (body.get("dns_provider") or "manual").strip().lower()
    if dns_provider in ("", "off", "none", "false", "0"):
        dns_provider = "manual"
    if dns_provider not in ("manual", "aliyun"):
        raise acme.AcmeError(f"暂不支持的解析服务商：{dns_provider}")
    if dns_provider != "manual" and challenge != "dns":
        raise acme.AcmeError("自动写入解析记录只能配合「DNS 验证」使用")

    dns_ak = dns_sk = ""
    dns_ttl = 600
    try:
        dns_wait = int(body.get("dns_wait") or 180)
    except Exception:
        dns_wait = 180
    if not (30 <= dns_wait <= 900):
        raise acme.AcmeError("等待解析生效的时间应在 30-900 秒之间")

    if dns_provider != "manual":
        dns_ak, dns_sk = resolve_dns_credential(body)
        if len(dns_ak) < 12 or len(dns_sk) < 16:
            raise acme.AcmeError(
                "AccessKey 长度异常，请确认已完整粘贴（ID 通常 24 位，Secret 通常 30 位）"
            )
        try:
            dns_ttl = max(600, int(body.get("dns_ttl") or 600))
        except Exception:
            dns_ttl = 600

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
        "dns_provider": dns_provider,
        "dns_access_key_id": dns_ak,
        "dns_access_key_secret": dns_sk,
        "dns_ttl": dns_ttl,
        "dns_wait": dns_wait,
    }


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
        if path in ("/deploy", "/deploy.html"):
            self._serve_file(WEB_DIR / "deploy.html")
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
        if path == "/api/deploy/certs":
            self._ok({"certs": list_cert_bundles()})
            return
        if path == "/api/deploy/credential":
            self._ok(read_saved_credential())
            return
        if path == "/api/dns/credential":
            self._ok(read_saved_credential(DNS_ENV_FILE))
            return
        if path == "/api/dns/meta":
            self._ok({
                "providers": [
                    {"name": "aliyun", "label": provider_label("aliyun"),
                     "hint": "域名的 NS 需指向阿里云云解析"},
                ],
                "credential": read_saved_credential(DNS_ENV_FILE),
            })
            return
        m = re.match(r"^/api/deploy/runs/([A-Za-z0-9_-]+)$", path)
        if m:
            job = DEPLOY_JOBS.get(m.group(1))
            if not job:
                self._fail("任务不存在或已失效", 404)
                return
            self._ok(job.to_dict())
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

        if path == "/api/deploy/credential":
            ak = (body.get("access_key_id") or "").strip()
            sk = (body.get("access_key_secret") or "").strip()
            if not ak or not sk:
                raise acme.AcmeError("AccessKey ID 与 Secret 都不能为空")
            if len(ak) < 12 or len(sk) < 16:
                raise acme.AcmeError("AccessKey 长度异常，请确认已完整粘贴（ID 通常 24 位，Secret 通常 30 位）")
            save_credential(ak, sk)
            self._ok(read_saved_credential())
            return

        if path == "/api/deploy/credential/clear":
            if ALB_ENV_FILE.is_file():
                ALB_ENV_FILE.unlink()
            self._ok(read_saved_credential())
            return

        if path == "/api/dns/credential":
            ak = (body.get("dns_access_key_id") or body.get("access_key_id") or "").strip()
            sk = (body.get("dns_access_key_secret") or body.get("access_key_secret") or "").strip()
            if not ak or not sk:
                raise acme.AcmeError("AccessKey ID 与 Secret 都不能为空")
            if len(ak) < 12 or len(sk) < 16:
                raise acme.AcmeError("AccessKey 长度异常，请确认已完整粘贴（ID 通常 24 位，Secret 通常 30 位）")
            save_credential(
                ak, sk, DNS_ENV_FILE,
                "# 云解析凭证 —— 仅用于 DNS-01 自动写入 TXT 记录，已被 .gitignore 排除。\n"
                "# 建议单独创建子账号，只授予 alidns 的 Add/Delete/Describe 权限，不要与部署凭证共用。\n",
            )
            self._ok(read_saved_credential(DNS_ENV_FILE))
            return

        if path == "/api/dns/credential/clear":
            if DNS_ENV_FILE.is_file():
                DNS_ENV_FILE.unlink()
            self._ok(read_saved_credential(DNS_ENV_FILE))
            return

        if path == "/api/dns/zones":
            ak, sk = resolve_dns_credential(body)
            provider = create_dns_provider("aliyun", ak, sk)
            try:
                zones = [z["name"] for z in provider.zones()]
            except DnsError as exc:
                raise acme.AcmeError(exc.readable())
            self._ok({"count": len(zones), "zones": zones[:50]})
            return

        if path == "/api/deploy/probe":
            ak, sk = resolve_deploy_credential(body)
            region = (body.get("region") or "cn-hangzhou").strip()
            if not re.match(r"^[a-z0-9-]+$", region):
                raise acme.AcmeError("地域格式不正确")
            self._ok(probe_aliyun(ak, sk, region))
            return

        if path == "/api/deploy/run":
            if not DEPLOY_SERIAL.acquire(blocking=False):
                raise acme.AcmeError("已有部署任务正在运行，请等待其结束")
            try:
                params = parse_deploy_params(body)
                ak, sk = resolve_deploy_credential(body)
            except Exception:
                DEPLOY_SERIAL.release()
                raise

            job = DeployJob(params)
            with DEPLOY_JOBS_LOCK:
                DEPLOY_JOBS[job.id] = job
                if len(DEPLOY_JOBS) > 20:
                    for stale in list(DEPLOY_JOBS)[:-20]:
                        DEPLOY_JOBS.pop(stale, None)

            def worker():
                try:
                    run_deploy_job(job, params, ak, sk)
                finally:
                    try:
                        DEPLOY_SERIAL.release()
                    except RuntimeError:
                        pass

            threading.Thread(target=worker, daemon=True).start()
            self._ok(job.to_dict())
            return

        if path == "/api/sessions":
            cfg = self._build_config(body)
            sess = Session(cfg)
            with SESSIONS_LOCK:
                SESSIONS[sess.id] = sess
            self._ok(sess.to_dict())
            return

        m = re.match(r"^/api/sessions/([A-Za-z0-9_-]+)/(prepare|validate|finalize|check-dns|stop-http|dns-write|dns-cleanup)$", path)
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
            elif action == "dns-write":
                if not dns_auto_enabled(sess):
                    raise acme.AcmeError("当前会话没有启用自动写入解析记录")
                count = action_write_dns(sess)
                sess.log(f"已确认 {count} 条 TXT 记录就位", "ok")
                self._ok(sess.to_dict())
            elif action == "dns-cleanup":
                removed = action_cleanup_dns(sess)
                self._ok({"removed": removed, "session": sess.to_dict()})
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
        return build_config(body)

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

class _Server(ThreadingHTTPServer):
    """默认的 ThreadingHTTPServer 开着 SO_REUSEADDR，在 Windows 上会允许同一端口
    被两个进程同时绑定：新实例看起来启动成功，请求却可能落到旧实例上跑旧代码，
    排查时极难发现。这里在 Windows 关闭该选项，重复启动就会直接报端口被占用。"""

    allow_reuse_address = os.name != "nt"


def _port_listener_pid(port: int) -> str:
    """尽力找出占用该端口的进程 PID（仅 Windows，查不到返回空串）。"""
    if os.name != "nt":
        return ""
    try:
        import subprocess

        out = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
        ).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        cols = line.split()
        if (
            len(cols) >= 5
            and cols[0].upper() == "TCP"
            and cols[1].endswith(":%d" % port)
            and cols[3].upper() == "LISTENING"
        ):
            return cols[4]
    return ""


def main():
    parser = argparse.ArgumentParser(description="Let's Encrypt 证书申请工具")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    parser.add_argument("--port", type=int, default=8899, help="界面端口（默认 8899）")
    parser.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}/"
    try:
        server = _Server((args.host, args.port), Handler)
    except OSError as exc:
        pid = _port_listener_pid(args.port)
        print(f"\n启动失败：端口 {args.port} 已被占用（{exc}）")
        if pid:
            print(f"占用进程 PID：{pid}，这是上一次启动后没有关掉的旧实例（跑的可能是旧代码）。")
            print(f"先结束它：taskkill /PID {pid} /F")
        else:
            print("请关闭占用该端口的旧实例，或换一个端口。")
        print(f"换端口启动示例：python app.py --port 8898\n")
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

"""续期检查的公共实现。

谁调这里：
    scheduler.py  常驻进程，按心跳触发
    app.py        界面上的「立即检查」按钮
两者共用同一个文件锁，保证任何时刻只有一次检查在跑——两轮同时往同一个域名
写 TXT，验证必然失败，而且报错看起来像"DNS 没生效"，最难查。
"""

from __future__ import annotations

import contextlib
import datetime
import io
import json
import os
import re
import socket
import subprocess
import sys
import traceback
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

DATA_DIR = BASE_DIR / "data"
LOG_DIR = DATA_DIR / "logs"
CONFIG_FILE = DATA_DIR / "scheduler.json"
STATE_FILE = DATA_DIR / "renewal-state.json"
LOCK_FILE = DATA_DIR / "renewal.lock"

# 调度器用它做三件事：单实例互斥、存活探测、接收触发请求
SCHED_PORT = 8898

DEFAULT_CONFIG = {"domains": [], "threshold_days": 15, "interval_hours": 6}
MAX_NOTICES = 20
MAX_OUTPUT = 3000


# --------------------------------------------------------------------------- 基础

def _now() -> datetime.datetime:
    return datetime.datetime.now()


def _stamp(dt: datetime.datetime | None = None) -> str:
    return (dt or _now()).strftime("%Y-%m-%dT%H:%M:%S")


def _parse(text: str):
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
    except (TypeError, ValueError):
        return None


def _write_json(path: Path, data: dict) -> None:
    """先写临时文件再替换，避免读到写了一半的内容。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


# --------------------------------------------------------------------------- 配置

def load_config(create: bool = False) -> dict:
    """读配置；首次运行时按 certs/ 下现有证书初始化一份，随后由人维护。"""
    if CONFIG_FILE.is_file():
        cfg = dict(DEFAULT_CONFIG)
        cfg.update(_read_json(CONFIG_FILE))
        cfg.setdefault("domains", [])
        return cfg

    cfg = dict(DEFAULT_CONFIG)
    if create:
        cfg["domains"] = [item["cn"] for item in scan()]
        _write_json(CONFIG_FILE, cfg)
    return cfg


def save_config(cfg: dict) -> None:
    _write_json(CONFIG_FILE, cfg)


# --------------------------------------------------------------------------- 状态

def load_state() -> dict:
    state = _read_json(STATE_FILE)
    state.setdefault("last_check", "")
    state.setdefault("last_code", None)
    state.setdefault("last_summary", "")
    state.setdefault("last_output", "")
    state.setdefault("last_certs", [])
    state.setdefault("notices", [])
    state.setdefault("consecutive_failures", 0)
    state.setdefault("running", False)
    return state


def save_state(state: dict) -> None:
    _write_json(STATE_FILE, state)


# --------------------------------------------------------------------------- 证书扫描

def scan() -> list:
    """列出 certs/ 下每张证书的最新生产版本，并现算剩余天数。

    复用 renew.scan_certs()，那边已经处理了两件事：按 CN 取最新一版、
    排除测试环境签发的目录。
    """
    import renew

    now = datetime.datetime.now(datetime.timezone.utc)
    items = []
    for cn, cert in renew.scan_certs().items():
        left = (cert["not_after"] - now).days
        items.append({
            "cn": cn,
            "domains": cert["domains"],
            "not_after": cert["not_after"].astimezone().strftime("%Y-%m-%d"),
            "days_left": left,
            "dir": cert["dir"].name,
        })
    items.sort(key=lambda x: x["days_left"])
    return items


# --------------------------------------------------------------------------- 通知

TOAST_PS = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$texts = $xml.GetElementsByTagName('text')
$texts.Item(0).AppendChild($xml.CreateTextNode($env:CERTTOOL_TITLE)) | Out-Null
$texts.Item(1).AppendChild($xml.CreateTextNode($env:CERTTOOL_BODY)) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Microsoft.Windows.Shell.RunDialog').Show($toast)
"""


def notify(title: str, body: str) -> bool:
    """弹一条系统通知。失败不抛异常——通知是锦上添花，不能拖垮检查。"""
    if os.name != "nt":
        return False
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", TOAST_PS],
            env={**os.environ, "CERTTOOL_TITLE": title, "CERTTOOL_BODY": body},
            capture_output=True, timeout=20,
        )
        return proc.returncode == 0
    except Exception:
        return False


# --------------------------------------------------------------------------- 互斥

@contextlib.contextmanager
def exclusive():
    """跨进程互斥。拿不到锁时 yield False，调用方据此放弃这一轮。"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fh = LOCK_FILE.open("a+b")
    locked = False
    try:
        if fh.tell() == 0:
            fh.write(b"0")
            fh.flush()
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
    except OSError:
        locked = False

    try:
        yield locked
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
        fh.close()


# --------------------------------------------------------------------------- 检查

def run_check(dry_run: bool = False) -> dict:
    """跑一次检查。真正需要续期时才签发并部署，否则只读文件后返回。"""
    with exclusive() as locked:
        if not locked:
            return {"ok": False, "busy": True, "message": "已有一次检查正在进行，稍后再试"}

        import renew

        cfg = load_config()
        state = load_state()
        state["running"] = True
        save_state(state)

        buffer = io.StringIO()
        result = {"ok": True, "renewed": [], "failed": [], "checked": []}
        try:
            tracked = [c for c in scan()
                       if not cfg["domains"] or c["cn"] in cfg["domains"]]
            if not tracked:
                result["message"] = "certs/ 下没有找到可续期的证书，请先手工签发一次"
                state["last_summary"] = result["message"]
                state["last_code"] = 2
                return result

            failures = 0
            for cert in tracked:
                argv = ["--domain", cert["cn"], "--days", str(cfg["threshold_days"])]
                if dry_run:
                    argv.append("--dry-run")
                with contextlib.redirect_stdout(buffer):
                    try:
                        code = renew.main(argv)
                    except SystemExit as exc:
                        code = int(exc.code or 0)
                    except Exception:
                        traceback.print_exc(file=buffer)
                        code = 1
                result["checked"].append(cert["cn"])
                text = buffer.getvalue()
                attempted = "开始续期" in text
                if code != 0:
                    failures += 1
                    result["failed"].append({"cn": cert["cn"], "code": code})
                elif attempted:
                    result["renewed"].append(cert["cn"])

            mins = min((c["days_left"] for c in tracked), default=0)
            if result["failed"]:
                summary = "；".join("%s 续期失败（退出码 %d）" % (x["cn"], x["code"])
                                   for x in result["failed"])
                code = 1
            elif result["renewed"]:
                summary = "已续期：%s" % "、".join(result["renewed"])
                code = 0
            else:
                summary = "还剩 %d 天，未进入 %d 天窗口，无需续期" % (mins, cfg["threshold_days"])
                code = 0

            state["last_check"] = _stamp()
            state["last_code"] = code
            state["last_summary"] = summary
            state["last_certs"] = scan()
            state["last_output"] = buffer.getvalue()[-MAX_OUTPUT:]
            state["consecutive_failures"] = (state["consecutive_failures"] + 1) if code else 0

            if result["renewed"] or result["failed"]:
                level = "ok" if not result["failed"] else "error"
                title = "证书已续期" if not result["failed"] else "证书续期失败"
                notify(title, summary)
                state["notices"] = ([{
                    "at": _stamp(), "level": level, "title": title, "body": summary,
                }] + state["notices"])[:MAX_NOTICES]

            result["message"] = summary
            result["code"] = code
            return result
        finally:
            state["running"] = False
            save_state(state)


# --------------------------------------------------------------------------- 状态汇总

def scheduler_alive() -> dict:
    """探测常驻调度器是否在跑（它占着 SCHED_PORT）。

    用 HTTP/1.0 请求，让服务端应答后立刻断开，这样可以一直读到 EOF，
    不必猜响应有多长。
    """
    try:
        with socket.create_connection(("127.0.0.1", SCHED_PORT), timeout=0.6) as sock:
            sock.sendall(b"GET /ping HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            chunks = []
            total = 0
            while total < 8192:
                data = sock.recv(1024)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
        raw = b"".join(chunks).decode("utf-8", "replace")
        body = raw.split("\r\n\r\n", 1)[-1]
        return {"running": True, "info": json.loads(body)}
    except Exception:
        return {"running": False, "info": None}


def status() -> dict:
    cfg = load_config()
    state = load_state()
    certs = scan()

    tracked_cns = set(cfg["domains"])
    tracked = [c for c in certs if not tracked_cns or c["cn"] in tracked_cns]
    for item in certs:
        item["tracked"] = not tracked_cns or item["cn"] in tracked_cns

    last = _parse(state["last_check"])
    nxt = ""
    if last:
        nxt = (last + datetime.timedelta(hours=cfg["interval_hours"])).strftime("%Y-%m-%dT%H:%M:%S")

    return {
        "config": cfg,
        "certs": certs,
        "tracked_count": len(tracked),
        "untracked": [c["cn"] for c in certs if not c["tracked"]],
        "minimum_days": min((c["days_left"] for c in tracked), default=None),
        "last_check": state["last_check"],
        "last_summary": state["last_summary"],
        "last_code": state["last_code"],
        "last_output": state["last_output"],
        "last_certs": state["last_certs"],
        "next_check": nxt,
        "running": state["running"],
        "consecutive_failures": state["consecutive_failures"],
        "notices": state["notices"][:5],
        "scheduler": scheduler_alive(),
        "interval_hours": cfg["interval_hours"],
    }


# --------------------------------------------------------------------------- 日志读取
#
# 日志是给机器写的，行格式来自 renew.py 的 log()：
#     [15:34:24] 自动续期检查开始
#     [15:34:24] 证书：*.hnjs888.com
#     [15:34:24]   到期时间  2027-01-28（剩余 85 天）
#     [15:34:24]   判断      剩余 85 天 > 阈值 15 天，今天不需要续期
#     [15:34:24] 结束：全部处理完成
# 这里把它还原成「轮次 → 证书 → 明细」，界面直接渲染，不用在前端猜字符串。

_RENEW_FILE = re.compile(r"^renew-(\d{8})\.log$")
_LOG_LINE = re.compile(r"^\[(\d{2}:\d{2}:\d{2})\]\s?(.*)$")
_DAY_LINE = re.compile(r"^\[(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\]\s?(.*)$")
_FIELD = re.compile(r"^(\s*)(\S+)(\s{2,})(.*)$")
_RULE = {"=", "—", "-"}

_BAD_WORDS = ("失败", "异常", "错误", "不正确", "超时", "拒绝")


def _tone_for(key: str, value: str) -> str:
    """给一行明细定色调。

    key 和 value 都要看：`异常` 这一行的值未必带"失败"二字
    （例如 `DnsError: 域名 … 不在当前账号的托管域名中`），只查 value 会漏判。
    """
    if key in ("异常",) or any(w in key for w in ("失败", "错误")):
        return "bad"
    if any(w in value for w in _BAD_WORDS):
        return "bad"
    if key == "结果" and ("成功" in value or "现在使用该证书" in value):
        return "ok"
    if key == "判断":
        if "不需要续期" in value:
            return "muted"
        if "开始续期" in value:
            return "accent"
    if key in ("预演模式",):
        return "muted"
    return "normal"


def _cert_status(cert: dict) -> str:
    tones = [i["tone"] for i in cert["items"]]
    if "bad" in tones:
        return "fail"
    if "ok" in tones:
        return "renewed"
    verdict = ""
    for item in cert["items"]:
        if item["k"] == "判断":
            verdict = item["v"]
            break
    if "不需要续期" in verdict:
        return "skip"
    if "开始续期" in verdict:
        return "renewing"
    return "check"


def list_renew_dates() -> list:
    """data/logs/renew-YYYYMMDD.log 的日期，新的在前。"""
    try:
        names = [p.name for p in LOG_DIR.glob("renew-*.log")]
    except OSError:
        return []
    dates = [m.group(1) for m in (_RENEW_FILE.match(n) for n in names) if m]
    return sorted(set(dates), reverse=True)


def read_renew_log(date: str = "", max_rounds: int = 40, max_lines: int = 8000) -> dict:
    dates = list_renew_dates()
    if date not in dates:
        date = dates[0] if dates else ""

    if not date:
        return {"dates": [], "date": "", "rounds": [],
                "empty": "还没有检查记录。等第一轮心跳（或点「立即检查」）之后就会出现。"}

    path = LOG_DIR / ("renew-%s.log" % date)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"dates": dates, "date": date, "rounds": [], "empty": "读取失败：%s" % exc}

    rounds, cur, cert = [], None, None

    for raw in text.splitlines()[-max_lines:]:
        m = _LOG_LINE.match(raw)
        if not m:
            continue
        ts, body = m.group(1), m.group(2)
        stripped = body.strip()
        if not stripped or set(stripped) <= _RULE:
            continue

        if stripped.startswith("自动续期检查"):
            cur = {"time": ts, "end": "", "dry_run": "预演" in stripped,
                   "summary": "", "certs": [], "notes": []}
            rounds.append(cur)
            cert = None
            continue

        if cur is None:
            continue

        if stripped.startswith("结束："):
            cur["summary"] = stripped[3:].strip()
            cur["end"] = ts
            continue

        if stripped.startswith("证书："):
            cert = {"cn": stripped[3:].strip(), "items": [], "status": "unknown"}
            cur["certs"].append(cert)
            continue

        if cert is None:
            cur["notes"].append(stripped)
            continue

        # 部署脚本的原始输出：| 正常行，! 警告行
        if stripped[0] in "|!":
            if cert["items"]:
                cert["items"][-1].setdefault("detail", []).append(
                    {"text": stripped[1:].strip(),
                     "tone": "bad" if stripped[0] == "!" else "muted"})
            continue

        fm = _FIELD.match(body)
        if fm and fm.group(1):
            key, value = fm.group(2), fm.group(4).strip()
            cert["items"].append({"k": key, "v": value, "tone": _tone_for(key, value)})
        else:
            cert["items"].append({"k": "", "v": stripped, "tone": _tone_for("", stripped)})

    out = []
    for r in rounds:
        for c in r["certs"]:
            c["status"] = _cert_status(c)
        statuses = [c["status"] for c in r["certs"]]
        summary = r.get("summary") or ""
        if "fail" in statuses or any(w in summary for w in _BAD_WORDS):
            r["status"] = "fail"
        elif "renewed" in statuses:
            r["status"] = "renewed"
        elif "renewing" in statuses:
            r["status"] = "renewing"
        elif statuses and all(s == "skip" for s in statuses):
            r["status"] = "skip"
        else:
            r["status"] = "check"
        out.append(r)

    out.reverse()  # 最新的在最上面
    truncated = len(out) > max_rounds
    out = out[:max_rounds]
    for i, r in enumerate(out):
        r["id"] = i

    return {
        "dates": dates,
        "date": date,
        "rounds": out,
        "truncated": truncated,
        "counts": {
            "renewed": sum(1 for r in out if r["status"] == "renewed"),
            "fail": sum(1 for r in out if r["status"] == "fail"),
            "skip": sum(1 for r in out if r["status"] == "skip"),
        },
        "empty": "" if out else "这一天有日志文件，但没有可解析的检查记录。",
    }


def read_scheduler_log(max_entries: int = 150) -> dict:
    """调度器自己的事件流：启动、每轮检查、停止。比 renew 日志粗，但能看到"它还在跑"。"""
    path = LOG_DIR / "scheduler.log"
    if not path.is_file():
        return {"entries": [], "empty": "还没有调度记录，说明调度器还没启动过。"}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {"entries": [], "empty": "读取失败：%s" % exc}

    entries = []
    for raw in lines[-max_entries:]:
        m = _DAY_LINE.match(raw)
        if not m:
            continue
        text = m.group(3).strip()
        if not text:
            continue
        if any(w in text for w in _BAD_WORDS):
            level = "bad"
        elif "检查结束" in text:
            level = "ok"
        elif "已启动" in text or "已停止" in text:
            level = "note"
        else:
            level = "normal"
        entries.append({"date": m.group(1), "time": m.group(2),
                        "level": level, "text": text})

    entries.reverse()
    return {"entries": entries, "empty": "" if entries else "日志文件是空的。"}

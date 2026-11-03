"""常驻调度器：开机自启，按心跳判断证书要不要续期。

它不"定时执行"某件事，只是每隔一段时间问一次"现在该不该做"。这个区别很重要：
机器凌晨关机时不会有任何一次"错过"，因为压根没有固定的执行时刻。

单实例靠占用 127.0.0.1:8898 实现——端口拿不到就说明已经有一个在跑。
同一个端口顺带提供存活探测，界面据此显示"运行中 / 未运行"。

用法：
    python scheduler.py                 # 前台运行，Ctrl+C 退出
    python scheduler.py --check-now     # 只跑一次检查，不进循环
    python scheduler.py --status        # 打印当前状态
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import renewal_job as job

LOG_FILE = job.LOG_DIR / "scheduler.log"
PID_FILE = job.DATA_DIR / "scheduler.pid"
_STARTED = job._stamp()
_CHECK_SERIAL = threading.Lock()


# --------------------------------------------------------------------------- 日志

def log(message: str) -> None:
    line = "[%s] %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message)
    print(line, flush=True)
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------- 服务

class _Server(ThreadingHTTPServer):
    """Windows 的 SO_REUSEADDR 允许两个进程绑同一个端口，必须关掉，
    否则"端口即锁"这套单实例机制会失效——两个调度器同时在跑，各写各的 TXT。
    """

    allow_reuse_address = os.name != "nt"


class Handler(BaseHTTPRequestHandler):
    server_version = "certtool-scheduler"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # 默认会往 stderr 打每条请求，太吵
        pass

    def _send(self, payload: dict, code: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/ping":
            self._send({"ok": True, "pid": os.getpid(), "started": _STARTED})
            return
        if path in ("/health", "/status"):
            try:
                state = job.status()
                # 自己就是调度器，不必再向自己探测一次
                state["scheduler"] = {"running": True,
                                      "info": {"pid": os.getpid(), "started": _STARTED}}
                payload = {"ok": True, "pid": os.getpid(),
                           "started": _STARTED, "status": state}
            except Exception as exc:
                payload = {"ok": False, "error": str(exc)}
            self._send(payload)
            return
        self._send({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/check":
            started = _spawn_check("手动触发")
            self._send({"ok": True, "started": started})
            return
        self._send({"ok": False, "error": "not found"}, 404)


def _spawn_check(reason: str) -> bool:
    if not _CHECK_SERIAL.acquire(blocking=False):
        log("已有检查在进行，忽略本次触发（%s）" % reason)
        return False

    def worker():
        try:
            log("开始检查（%s）" % reason)
            result = job.run_check()
            log("检查结束：%s" % (result.get("message") or "无结论"))
        except Exception:
            log("检查异常：\n" + traceback.format_exc())
        finally:
            _CHECK_SERIAL.release()

    threading.Thread(target=worker, daemon=True).start()
    return True


# --------------------------------------------------------------------------- 主循环

def _last_check():
    stamp = job.load_state().get("last_check") or ""
    try:
        return datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def loop() -> int:
    log("进入主循环，每 60 秒看一次表")
    while True:
        try:
            cfg = job.load_config()
            last = _last_check()
            interval = max(1, int(cfg.get("interval_hours") or 6))
            due = last is None or (datetime.datetime.now() - last) >= datetime.timedelta(hours=interval)
            if due:
                _spawn_check("距上次检查超过 %d 小时" % interval)
            time.sleep(60)
        except KeyboardInterrupt:
            log("收到中断，退出")
            return 0
        except Exception:
            log("主循环异常：\n" + traceback.format_exc())
            time.sleep(60)



def stop_running() -> int:
    """按 pid 文件停掉正在运行的调度器。

    不用 taskkill：这台机器的安全策略会拦下它。OpenProcess + TerminateProcess
    只依赖 kernel32，等价于在任务管理器里结束进程。
    """
    if not PID_FILE.is_file():
        log("调度器没有在运行（找不到 pid 文件）")
        return 0
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        log("pid 文件内容不合法，已删除")
        PID_FILE.unlink(missing_ok=True)
        return 0

    if os.name != "nt":
        try:
            os.kill(pid, 15)
            log("已停止调度器（PID %d）" % pid)
        except OSError as exc:
            log("停止失败：%s" % exc)
        return 0

    import ctypes

    PROCESS_TERMINATE = 0x0001
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not handle:
        log("进程 %d 已不存在，清理 pid 文件" % pid)
        PID_FILE.unlink(missing_ok=True)
        return 0
    try:
        ctypes.windll.kernel32.TerminateProcess(handle, 1)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)
    PID_FILE.unlink(missing_ok=True)
    log("已停止调度器（PID %d）" % pid)
    return 0


def report() -> int:
    """人话版状态：一眼看清「它活着吗 / 上次干了什么 / 下次什么时候 / 各证书还剩几天」。"""
    s = job.status()
    cfg = s["config"]
    alive = bool(s["scheduler"]["running"])
    pid = s["scheduler"]["info"].get("pid") if s["scheduler"].get("info") else None

    print("")
    print("  证书自动续期  状态检查")
    print("  " + "-" * 56)
    print("")

    if alive:
        print("  调度器      ● 正在运行" + ("（PID %s）" % pid if pid else ""))
    else:
        print("  调度器      ○ 没有运行")
        print("              双击 start-scheduler.bat 启动")

    print("  检查间隔    每 %d 小时一次，剩余 <= %d 天时签发并部署"
          % (cfg["interval_hours"], cfg["threshold_days"]))
    print("")

    if s["last_check"]:
        print("  上次检查    %s" % s["last_check"].replace("T", " "))
        print("  结论        %s" % (s["last_summary"] or "-"))
        code = s["last_code"]
        print("  退出码      %s%s" % (code, "" if code == 0 else "   ← 最近一次有问题"))
    else:
        print("  上次检查    还没有检查记录")

    if alive and s["next_check"]:
        print("  下次检查    %s" % s["next_check"].replace("T", " "))
    print("")

    print("  托管的证书")
    for c in s["certs"]:
        mark = "  " if c["tracked"] else " ×"
        if not c["tracked"]:
            note = "   （未纳入托管）"
        elif c["days_left"] <= cfg["threshold_days"]:
            note = "   ← 已进入续期窗口"
        elif c["days_left"] <= 20:
            note = "   ← 快到期了"
        else:
            note = ""
        print("   %s %-20s 剩 %3d 天   %s 到期%s"
              % (mark, c["cn"], c["days_left"], c["not_after"], note))
    print("")

    fails = s["consecutive_failures"] or 0
    if fails:
        print("  连续失败    %d 次" % fails)

    print("  日志        data\\logs\\scheduler.log")
    print("              data\\logs\\renew-*.log")
    print("")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scheduler.py", description="证书续期常驻调度器")
    parser.add_argument("--check-now", action="store_true", help="只跑一次检查，不进循环")
    parser.add_argument("--status", action="store_true", help="打印当前状态后退出（JSON）")
    parser.add_argument("--report", action="store_true", help="打印人话版状态后退出")
    parser.add_argument("--stop", action="store_true", help="停止正在运行的调度器")
    args = parser.parse_args(argv)

    if args.stop:
        return stop_running()

    if args.report:
        return report()

    if args.status:
        print(json.dumps(job.status(), ensure_ascii=False, indent=2))
        return 0

    if args.check_now:
        result = job.run_check()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 1

    # 首次运行时，按现有证书生成一份可编辑的配置
    cfg = job.load_config(create=True)

    if job.scheduler_alive().get("running"):
        log("已经有一个调度器在运行，本次不做任何事")
        return 3

    try:
        server = _Server(("127.0.0.1", job.SCHED_PORT), Handler)
    except OSError as exc:
        log("无法监听 %d：%s" % (job.SCHED_PORT, exc))
        log("通常说明已经有一个调度器在运行，本次不做任何事")
        return 3

    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    except Exception:
        pass
    log("调度器已启动，端口 %d，间隔 %d 小时，托管 %s"
        % (job.SCHED_PORT, cfg["interval_hours"],
           "、".join(cfg["domains"]) or "全部证书"))
    log("启动即检查一次（等价于计划任务的「错过就补」）")
    _spawn_check("启动补检")

    try:
        return loop()
    finally:
        server.shutdown()
        try:
            PID_FILE.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())

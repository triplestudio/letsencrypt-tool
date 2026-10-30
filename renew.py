"""按到期时间自动续期：只在临期时才签发，签完自动换到阿里云 ALB 监听上。

和 issue.py 的分工：
    issue.py  无条件签一张新证书（手工用）
    renew.py  先判断"该不该续"，该续才调用 issue.py 的流程，然后把新证书推上 ALB

计划任务只需调用 renew.bat，它再调本文件。日常运行的绝大多数时候，
本脚本只是读几个 cert-info.json、发现还有 80 多天、然后退出，不发任何网络请求。

用法：
    python renew.py                          # 管理 certs/ 下所有域名，剩余 <=15 天时续期
    python renew.py --dry-run                # 只看判断结果，不签发、不部署
    python renew.py --domain "*.hnjs888.com" # 只处理这一张证书
    python renew.py --days 20 --force        # 改阈值 / 强制重签（测试用）
    python renew.py --staging                # 走 Let's Encrypt 测试环境，不消耗正式配额

退出码：0 无需续期或续期成功；1 续期/部署失败；2 参数或环境错误。
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

CERTS_DIR = BASE_DIR / "certs"
DATA_DIR = BASE_DIR / "data"
LOG_DIR = DATA_DIR / "logs"
ALB_ENV = DATA_DIR / "alb.env"
ALB_STATE = DATA_DIR / "alb-state.json"
DEPLOY_SCRIPT = BASE_DIR / "deploy" / "alb_deploy.py"

UTC = datetime.timezone.utc


# --------------------------------------------------------------------------- 日志

class Log:
    """同时写终端和按天的日志文件。终端那份由 renew.bat 重定向进 renew.log。"""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = path.open("a", encoding="utf-8")

    def __call__(self, message: str) -> None:
        line = "[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S"), message)
        print(line, flush=True)
        self.fh.write(line + "\n")
        self.fh.flush()

    def close(self) -> None:
        try:
            self.fh.close()
        except Exception:
            pass


# ----------------------------------------------------------------------- 证书扫描

def parse_time(text: str):
    """cert-info.json 里 not_after 的格式是 "2027-01-28 01:23:48 UTC"。"""
    text = (text or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def scan_certs() -> dict:
    """按 common_name 归组，每组只留 not_after 最新的那一版。

    注意：不能用 cert-info.json 里的 days_left 字段——那是签发当天算好写死的，
    放到一个月后就是错的。必须用 not_after 现算。
    """
    groups: dict = {}
    if not CERTS_DIR.is_dir():
        return groups

    for info_path in CERTS_DIR.glob("*/cert-info.json"):
        try:
            info = json.loads(info_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        cn = (info.get("common_name") or "").strip()
        not_after = parse_time(info.get("not_after", ""))
        if not cn or not not_after:
            continue

        # 测试环境签出来的证书也落在这里，但它不能代表线上状态。
        # 若把它当"最新版本"，正式证书到期时就会误判成"还有 90 天"而漏续。
        if (info.get("directory") or "production") != "production":
            continue

        entry = {
            "cn": cn,
            "domains": info.get("domains") or [cn],
            "not_after": not_after,
            "dir": info_path.parent,
        }
        old = groups.get(cn)
        if old is None or not_after > old["not_after"]:
            groups[cn] = entry
    return groups


def load_listeners(cn: str) -> list:
    """从 alb-state.json 找出当前挂着这张证书的监听。没有则返回空列表。"""
    if not ALB_STATE.is_file():
        return []
    try:
        state = json.loads(ALB_STATE.read_text(encoding="utf-8"))
    except Exception:
        return []

    result = []
    for lsn, meta in (state.get("listeners") or {}).items():
        if (meta.get("cn") or "").strip() == cn:
            result.append({"listener": lsn, "role": meta.get("role") or "default"})
    return result


def role_for(lsn: str, default: str = "default") -> str:
    """手工指定 --listener-id 时，role 仍然从状态文件里取。

    否则会把「扩展证书」的监听当成「默认证书」来挂，改错了不会报错，
    但线上拿到的还是旧证书——这类错最难查。
    """
    if not ALB_STATE.is_file():
        return default
    try:
        state = json.loads(ALB_STATE.read_text(encoding="utf-8"))
    except Exception:
        return default
    meta = (state.get("listeners") or {}).get(lsn) or {}
    return meta.get("role") or default


# --------------------------------------------------------------------------- 主流程

def renew_one(cert: dict, args, log: Log, manual_listeners: list | None = None) -> int:
    cn = cert["cn"]
    left = (cert["not_after"] - datetime.datetime.now(UTC)).days
    expire = cert["not_after"].astimezone().strftime("%Y-%m-%d")

    log("—" * 58)
    log("证书：%s" % cn)
    log("  当前文件  %s" % cert["dir"].name)
    log("  到期时间  %s（剩余 %d 天）" % (expire, left))
    log("  SAN       %s" % ", ".join(cert["domains"]))

    if left > args.days and not args.force:
        log("  判断      剩余 %d 天 > 阈值 %d 天，今天不需要续期" % (left, args.days))
        return 0

    reason = "已进入 %d 天窗口" % args.days if left <= args.days else "--force 强制"
    log("  判断      %s，开始续期" % reason)

    if args.dry_run:
        log("  预演模式  --dry-run，跳过实际签发")
        return 0

    # 1) 签发。域名集合直接沿用旧证书的 SAN，避免续期后续域名悄悄变少。
    import issue  # 延迟导入，--dry-run 时不加载签发相关依赖

    argv = [
        "--domains", ",".join(cert["domains"]),
        "--dns", args.dns,
        "--key-type", args.key_type,
    ]
    if args.email:
        argv += ["--email", args.email]
    if args.staging:
        argv.append("--staging")

    log("  第一步    申请新证书（DNS-01 自动写 TXT）")
    code = issue.main(argv)
    if code != 0:
        log("  结果      签发失败（退出码 %d），线上证书保持原样不动" % code)
        return 1

    new_dir = issue.LAST_CERT_DIR
    if new_dir:
        log("  结果      签发成功，新版本 %s" % Path(new_dir).name)
    else:
        log("  结果      签发成功")

    if args.no_deploy:
        log("  第二步    已指定 --no-deploy，跳过 ALB 部署")
        return 0

    # 2) 部署。先把新证书传上去、再切监听，失败时监听仍是旧证书。
    targets = manual_listeners if manual_listeners is not None else load_listeners(cn)
    if not targets:
        log("  第二步    未在 alb-state.json 找到挂载 %s 的监听，跳过部署" % cn)
        log("            如需部署请加 --listener-id lsn-xxxx（可重复）")
        return 0

    for item in targets:
        log("  第二步    部署到监听 %s（%s）" % (item["listener"], item["role"]))
        cmd = [
            sys.executable, str(DEPLOY_SCRIPT),
            "--listener-id", item["listener"],
            "--role", item["role"],
            "--region", args.region,
            "--cert-dir", new_dir,
            "--env-file", str(ALB_ENV),
        ]
        if args.verify_host:
            cmd += ["--verify-host", args.verify_host]
        if args.dry_run_deploy:
            cmd.append("--dry-run")

        proc = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        for line in (proc.stdout or "").splitlines():
            log("            | " + line)
        if proc.returncode != 0:
            for line in (proc.stderr or "").splitlines()[-10:]:
                log("            ! " + line)
            log("  结果      部署失败（退出码 %d），监听仍使用旧证书，可手工重跑："
                % proc.returncode)
            log("            python deploy/alb_deploy.py --cert-dir %s --listener-id %s"
                % (new_dir, item["listener"]))
            return 1
        log("  结果      监听 %s 现在使用该证书" % item["listener"])

    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="renew.py",
        description="到期前自动续期并部署到阿里云 ALB（供计划任务调用）",
    )
    p.add_argument("--domain", default="", help="只处理这一张证书（按 CN 匹配），默认处理全部")
    p.add_argument("--days", type=int, default=15, help="剩余天数小于等于该值时续期，默认 15")
    p.add_argument("--dry-run", action="store_true", help="只输出判断结果，不签发也不部署")
    p.add_argument("--dry-run-deploy", action="store_true", help="真签发，但部署只预演")
    p.add_argument("--force", action="store_true", help="忽略天数，强制续期")
    p.add_argument("--no-deploy", action="store_true", help="只续期，不推 ALB")
    p.add_argument("--staging", action="store_true", help="使用测试环境，不消耗正式配额")
    p.add_argument("--email", default="", help="联系邮箱（可留空，沿用账户已注册的）")
    p.add_argument("--dns", default="aliyun", choices=["aliyun"], help="解析服务商")
    p.add_argument("--key-type", default="ec256",
                   choices=["ec256", "ec384", "rsa2048", "rsa4096"], help="密钥类型")
    p.add_argument("--region", default="cn-hangzhou", help="ALB 所在地域，默认 cn-hangzhou")
    p.add_argument("--verify-host", default="", help="部署后用该域名做一次 TLS 校验")
    p.add_argument("--listener-id", action="append", default=[],
                   help="手工指定监听，覆盖从 alb-state.json 推断的结果（可重复）")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    log = Log(LOG_DIR / ("renew-%s.log" % datetime.datetime.now().strftime("%Y%m%d")))
    try:
        log("=" * 58)
        log("自动续期检查开始%s" % ("（预演）" if args.dry_run else ""))

        groups = scan_certs()
        if not groups:
            log("certs/ 下没有找到任何证书，请先手工签发一次")
            return 2

        targets = list(groups.values())
        if args.domain:
            hit = groups.get(args.domain)
            if not hit:
                log("没有找到 CN 为 %s 的证书，现有：%s"
                    % (args.domain, "、".join(sorted(groups))))
                return 2
            targets = [hit]

        # 手工指定 listener 时，跳过自动推断
        manual = None
        if args.listener_id:
            manual = [{"listener": x, "role": role_for(x)} for x in args.listener_id]

        failures = 0
        for cert in sorted(targets, key=lambda c: c["not_after"]):
            try:
                failures += renew_one(cert, args, log, manual)
            except Exception as exc:  # 单个域名出错不影响其它域名
                log("  异常      %s: %s" % (cert["cn"], exc))
                failures += 1

        log("=" * 58)
        if failures:
            log("结束：%d 张证书处理失败" % failures)
            return 1
        log("结束：全部处理完成")
        return 0
    finally:
        log.close()


if __name__ == "__main__":
    sys.exit(main())

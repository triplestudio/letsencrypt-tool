"""无人值守签发：一条命令跑完 订单 → 写 TXT → 等生效 → 验证 → 签发 → 落盘。

与网页界面共用同一套逻辑（app.build_config / action_*），区别只是不启动服务、
不需要人点按钮。适合放进计划任务，到期前自动换新。

用法：
    python issue.py --domains "*.example.com,example.com" --email ops@example.com \
        --dns aliyun --access-key-id LTAI... --access-key-secret ...

凭证也可以放在环境变量里，避免出现在命令历史：
    ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET

退出码：0 成功；1 签发失败；2 参数或配置错误。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import acme_client as acme  # noqa: E402
import app  # noqa: E402

# 本次签发落盘的目录，供 renew.py 等调用方直接取用，省得去解析 stdout
LAST_CERT_DIR = ""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="issue.py",
        description="无人值守申请证书（自动写入 DNS 解析记录）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  # 只签发\n"
            "  python issue.py --domains \"*.example.com,example.com\" --dns aliyun\n\n"
            "  # 签发并直接部署到 ALB（监听从 data/alb-state.json 自动推断）\n"
            "  python issue.py --domains \"*.example.com,example.com\" --dns aliyun --deploy\n\n"
            "  # 首次部署时手工指定监听\n"
            "  python issue.py --domains \"*.example.com\" --dns aliyun \\\n"
            "      --deploy --listener-id lsn-xxxxxxxxxxxx\n"
        ),
    )
    parser.add_argument("--domains", required=True, help="域名，多个用逗号分隔，支持 *.example.com")
    parser.add_argument("--email", default="", help="接收到期提醒的邮箱（可留空）")
    parser.add_argument("--dns", default="aliyun", choices=["aliyun"],
                        help="自动写入解析的服务商（目前仅 aliyun）")
    parser.add_argument("--access-key-id", default=os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID", ""),
                        help="云解析 RAM 子账号 AccessKey ID（默认读环境变量）")
    parser.add_argument("--access-key-secret", default=os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET", ""),
                        help="云解析 RAM 子账号 AccessKey Secret（默认读环境变量）")
    parser.add_argument("--key-type", default="ec256",
                        choices=["ec256", "ec384", "rsa2048", "rsa4096"], help="证书密钥类型")
    parser.add_argument("--staging", action="store_true", help="使用测试环境，不消耗正式配额")
    parser.add_argument("--ttl", type=int, default=600, help="TXT 记录 TTL（免费版最小 600）")
    parser.add_argument("--wait", type=int, default=180, help="等待解析生效的最长秒数")
    parser.add_argument("--deploy", action="store_true",
                        help="签发成功后直接部署到阿里云 ALB")
    parser.add_argument("--listener-id", action="append", default=[],
                        help="ALB 监听 ID（可重复）；不给则按证书 CN 从 alb-state.json 推断")
    parser.add_argument("--region", default="cn-hangzhou", help="ALB 地域，默认 cn-hangzhou")
    parser.add_argument("--verify-host", default="",
                        help="部署后用该域名做一次 TLS 校验，如 wildcard.hnjs888.com")
    parser.add_argument("--keep-records", action="store_true",
                        help="失败时保留已写入的 TXT 记录（默认会清理）")
    return parser.parse_args(argv)


def _cert_cn(cert_dir: str) -> str:
    try:
        info = json.loads((Path(cert_dir) / "cert-info.json").read_text(encoding="utf-8"))
        return (info.get("common_name") or "").strip()
    except Exception:
        return ""


def _state_listeners() -> list:
    state_file = BASE_DIR / "data" / "alb-state.json"
    if not state_file.is_file():
        return []
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except Exception:
        return []
    return [
        {
            "listener": lsn,
            "role": (meta.get("role") or "default"),
            "cn": (meta.get("cn") or "").strip(),
        }
        for lsn, meta in (state.get("listeners") or {}).items()
    ]


def listeners_for(cn: str) -> list:
    """从 data/alb-state.json 找出当前正挂着这张证书的监听。

    这份状态由 alb_deploy.py 在每次成功部署后写入，所以"续过一次"的域名
    以后都能自动认出来，不需要再记监听 ID。
    """
    if not cn:
        return []
    return [{"listener": x["listener"], "role": x["role"]}
            for x in _state_listeners() if x["cn"] == cn]


def role_for(lsn: str, default: str = "default") -> str:
    """手工指定 --listener-id 时，role 仍从状态文件里取。

    否则会把「扩展证书」的监听当成「默认证书」去挂，改错了不报错，
    但线上拿到的还是旧证书——这类问题最难查。
    """
    for item in _state_listeners():
        if item["listener"] == lsn:
            return item["role"]
    return default


def deploy_to_alb(cert_dir: str, args) -> int:
    """把刚签下来的证书推到 ALB。失败只影响部署，证书本身已经在盘上了。"""
    if args.listener_id:
        targets = [{"listener": x, "role": role_for(x)} for x in args.listener_id]
    else:
        cn = _cert_cn(cert_dir)
        targets = listeners_for(cn)
        if not targets:
            print("未在 data/alb-state.json 找到挂载 %s 的监听。" % (cn or "该证书"))
            print("首次部署请显式指定：--listener-id lsn-xxxxxxxxxxxx")
            return 5

    script = BASE_DIR / "deploy" / "alb_deploy.py"
    for item in targets:
        print("\n部署到监听 %s（%s）..." % (item["listener"], item["role"]))
        cmd = [
            sys.executable, str(script),
            "--listener-id", item["listener"],
            "--role", item["role"],
            "--region", args.region,
            "--cert-dir", cert_dir,
            "--env-file", str(BASE_DIR / "data" / "alb.env"),
        ]
        if args.verify_host:
            cmd += ["--verify-host", args.verify_host]

        proc = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        for line in (proc.stdout or "").splitlines():
            print("  " + line)
        if proc.returncode != 0:
            for line in (proc.stderr or "").splitlines()[-10:]:
                print("  ! " + line)
            print("部署失败（退出码 %d）。可单独重跑：" % proc.returncode)
            print("  python deploy/alb_deploy.py --cert-dir \"%s\" --listener-id %s"
                  % (cert_dir, item["listener"]))
            return proc.returncode
        print("监听 %s 现在使用该证书" % item["listener"])
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    body = {
        "domains": args.domains,
        "email": args.email,
        "challenge": "dns",
        "dns_provider": args.dns,
        "dns_access_key_id": args.access_key_id,
        "dns_access_key_secret": args.access_key_secret,
        "dns_ttl": args.ttl,
        "dns_wait": args.wait,
        "key_type": args.key_type,
        "staging": args.staging,
        "use_saved": True,
    }

    try:
        config = app.build_config(body)
    except acme.AcmeError as exc:
        print(f"参数错误：{exc.message}")
        return 2

    print(f"=" * 62)
    print(f"开始申请：{', '.join(config['domains'])}")
    print(f"环境：{'测试（staging）' if config['staging'] else '正式'}"
          f" | 密钥：{config['key_type']} | 解析：{config['dns_provider']}")
    print(f"=" * 62)

    sess = app.Session(config)
    try:
        app.action_prepare(sess)
        app.action_validate(sess)
        app.action_finalize(sess)
    except acme.AcmeError as exc:
        print(f"\n签发失败：{exc.message}")
        if not args.keep_records:
            app.action_cleanup_dns(sess, quiet=True)
        return 1
    except Exception as exc:  # 意外异常也要收尾，避免留下临时记录
        print(f"\n签发失败（异常）：{exc}")
        if not args.keep_records:
            app.action_cleanup_dns(sess, quiet=True)
        return 1

    print(f"\n完成。证书目录：{sess.output_dir}")
    print(f"CERT_DIR={sess.output_dir}")
    global LAST_CERT_DIR
    LAST_CERT_DIR = str(sess.output_dir)

    if args.deploy:
        return deploy_to_alb(LAST_CERT_DIR, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

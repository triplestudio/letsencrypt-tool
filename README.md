# Let's Encrypt 证书申请工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

一个带图形界面的本地工具，引导你一步步从 Let's Encrypt 免费获取受浏览器信任的 HTTPS 证书。

后端用 Python 标准库直接实现了 ACME v2 协议（RFC 8555），除 `cryptography` 外无其他依赖；界面在浏览器中运行，全部数据留在本机。

---

## 快速开始

**Windows**：双击 `run.bat`
**macOS / Linux**：`./run.sh`

首次运行会自动创建虚拟环境并安装依赖。启动后浏览器会自动打开 <http://127.0.0.1:8899>。

也可以手动启动：

```bash
python app.py              # 默认 8899 端口
python app.py --port 9000  # 换端口
```

---

## 先搞清楚：该选哪种验证方式

CA 要确认域名确实归你所有，三种方式只是「如何证明」不同：

| 场景 | 推荐方式 |
| --- | --- |
| 证书就装在当前这台机器（或能 SSH 上去操作） | **自动 HTTP 验证** |
| 网站已在跑 Nginx / IIS / 宝塔，不想停服务 | **手动 HTTP 验证** |
| 80 端口不通、套了 CDN、或要申请 `*.example.com` 泛域名 | **DNS 验证** |

三种方式都能签出同样的证书，只是验证途径不同。

DNS 验证还有个附加选项：域名托管在**阿里云云解析**时，可以打开「自动写入解析记录」，由工具调用云解析 API 添加并清理 `_acme-challenge` 记录，不需要手动复制。见 [DNS 记录自动化](./docs/dns-auto-alibaba.md)。

---

## 操作流程

### 第 1 步：填写域名信息

- **域名**：一行一个，或用逗号分隔。`example.com`（apex，即裸域名）和 `www.example.com` 要分别写。
- **泛域名**：写 `*.example.com`，会覆盖所有**一级**子域，但**不包含** `example.com` 本身，需要的话两个都写上；它也不覆盖 `a.b.example.com` 这种两级子域。详见 [证书基础](./docs/certificate-basics.md#13-泛域名不是万能的)。
- **邮箱**：用于接收证书到期提醒，可留空。

### 第 2 步：验证域名所有权

**自动 HTTP**：工具会在本机 80 端口临时起一个服务，直接点「开始验证」即可。前提是域名已解析到这台机器、且外网能访问 80 端口。

**手动 HTTP**：工具给出每个域名的验证文件名和内容，你把它们放到网站根目录下的
`.well-known/acme-challenge/` 目录中。填了「网站根目录」的话工具会直接帮你写进去。
放好后可以先用浏览器确认 `http://你的域名/.well-known/acme-challenge/文件名` 能打开。

**DNS**：到域名解析控制台按表格添加 TXT 记录，主机记录 `_acme-challenge`，值照抄。
解析生效通常 1–10 分钟，可以点「检测解析是否生效」先确认一遍。

域名在阿里云云解析时，可以打开「自动写入解析记录」，填一个有云解析权限的 RAM 子账号
AccessKey，工具会自己添加记录、等权威服务器可见后再提交验证，验证结束自动删除。
凭证保存在 `data/dns.env`（与部署凭证分开），权限只需 `alidns` 的 Describe / Add / Delete。
详见 [DNS 记录自动化](./docs/dns-auto-alibaba.md)。

> 验证失败后原授权会作废，再次点「开始验证」时工具会自动创建新订单并给出新的验证值，
> 按界面最新内容重新操作即可。

### 第 3 步：下载并部署

证书会保存到 `certs/<域名>-<时间戳>/`，包含：

| 文件 | 用途 |
| --- | --- |
| `fullchain.pem` | 证书 + 中间证书，**Nginx / Apache / Node 用这个** |
| `privkey.pem` | 证书私钥，务必保密 |
| `cert.pem` | 仅域名证书 |
| `chain.pem` | 仅中间证书 |
| `cert-info.json` | 证书元信息 |

**部署时只需要两个文件：`fullchain.pem` + `privkey.pem`。** 只用 `cert.pem` 会导致 curl / Java / Node / 老 Android 等客户端校验失败——原因见 [证书基础 · 为什么必须用 fullchain](./docs/certificate-basics.md#43-为什么必须用-fullchain而不是-certpem)。

界面里提供了 Nginx / Apache / IIS / Node.js 的配置片段，可直接复制。

---

## 关于续期

Let's Encrypt 证书有效期 **90 天**。

### 方式一：手工续期（任何场景）

重新申请相同域名，用新文件覆盖旧文件并重载服务：

```bash
nginx -t && nginx -s reload          # Nginx
systemctl reload apache2             # Apache
iisreset /restart                    # IIS（或在管理器里重新绑定）
```

### 方式二：一条命令（域名解析和负载都在阿里云）

这是本工具最顺的路径——**不需要复制 TXT 记录，也不需要手工上传证书**：

```bash
python issue.py --domains "*.example.com,example.com" --dns aliyun --deploy
```

它依次完成：下单 → 用 RAM 账号往云解析写 `_acme-challenge` TXT → 等权威 DNS 生效 →
验证 → 签发落盘 → 清理 TXT → 上传到 CAS → 挂到 ALB 监听。全程无交互。

- 监听从 `data/alb-state.json` 自动推断（该域名部署过一次之后就记住了）
- 首次部署、或想指定别的监听，加 `--listener-id lsn-xxxxxxxxxxxx`（可重复）
- 想部署后立刻验证链路，加 `--verify-host www.example.com`

### 方式三：计划任务（真正的自动续期）

双击 `register-task.bat` 即可注册（默认每天 03:30，只托管 `*.hnjs888.com`）。
需要注销后也继续运行，就右键"以管理员身份运行"并带 `/system` 参数走 SYSTEM 账户。

脚本会先走 `Register-ScheduledTask`（CIM）；如果这台机器的 CIM 通道报
`0x80004005 未指定的错误`，会自动改写任务 XML 并改用 `schtasks /Create /XML`（RPC）重试。
两条都不通时，XML 会保留在 `%TEMP%\LetsEncrypt-Renew.xml`，可在任务计划程序里
「导入任务」直接载入。

脚本会开启三个容易被忽略但很关键的设置：**错过计划时间后补跑**（半夜关机不会漏）、
**电池供电也运行**（笔记本默认不跑）、**不并发启动新实例**（避免上一轮还在等 DNS 生效时又起一轮）。

手工注册也可以，但没有上述设置：

```bat
schtasks /Create /TN "LetsEncrypt-Renew" /TR "D:\ai\letsencrypt-tool\renew.bat --domain \"*.example.com\"" /SC DAILY /ST 03:30 /F
```

`renew.bat` 每天跑一次，只有**剩余天数 ≤ 15** 才真正签发并部署，其余时候只读
`certs/*/cert-info.json` 然后退出，不发任何网络请求。日志按天写在 `data/logs/renew-YYYYMMDD.log`。

关键行为：

- **先签后换**——签发失败时线上证书一个字节都不动，不会出现证书空窗
- 域名集合沿用旧证书的 SAN，不会因为漏写裸域而导致续期后 SAN 变少
- 测试环境（`--staging`）签出的证书会被忽略，不会让正式证书被误判成"还有 90 天"
- 阈值可调：`renew.bat --days 20`；强制重签：`--force`；只看判断：`--dry-run`

> 前提：`data/dns.env` 里要有云解析权限的子账号，`data/alb.env` 里要有 ALB 权限的子账号。
> 两个账号分开更安全——签发只碰解析，部署只碰负载。

---

## 常见问题

**端口 80 被占用，自动验证起不来？**
多半是 IIS / Nginx / Apache 或宝塔面板占着。工具会自动降级为「手动放置文件」模式并显示文件内容；
也可以先停掉占用端口的程序，或改用 DNS 验证。

**提示域名没有解析到本机？**
预检查会对比域名的 A 记录和本机出口公网 IP。不一致说明证书要装的机器不是当前这台，或者中间有 CDN —
这种情况下 HTTP 验证必定失败，请改用 DNS 验证。

**正式环境会不会把配额用光？**
同一组域名每周有签发次数限制。第一次建议勾选「高级选项 → 使用测试环境」跑通全流程，
测试环境签发的证书浏览器不信任，但流程完全一样。

**证书浏览器不信任 / 报警告？**
检查是否误用了测试环境（界面左下角会显示「测试环境」）。测试证书需要重新用正式环境签一次。

**极老的设备提示证书错误？**
默认用 ECDSA P-256 密钥，Windows XP、Java 6 等老系统不支持，请在高级选项里改用 RSA 2048。

**IIS 怎么用 PEM 证书？**
IIS 需要 `.pfx`，用 OpenSSL 转一下即可（界面里给了完整命令）：
`openssl pkcs12 -export -out cert.pfx -inkey privkey.pem -in cert.pem -certfile chain.pem`

---

## 安全说明

- 后端只监听 `127.0.0.1`，并校验 Host 头，不对局域网/公网开放。
- 证书私钥只写入本机 `certs/` 目录，不会上传到任何第三方。
- ACME 账号密钥存放在 `data/accounts/`，重复申请时自动复用，避免重复注册账号。
- `privkey.pem` 权限已设为仅当前用户可读（Windows 下为默认 ACL）。
- 仓库用 `.gitignore` 排除了 `data/`、`certs/` 与所有 `*.pem` 文件，**提交代码不会带上任何私钥**。

---

## 目录结构

```
letsencrypt-tool/
├── run.bat / run.sh      启动脚本（首次自动装环境）
├── app.py                本地 Web 服务与业务流程
├── issue.py              无人值守签发（--deploy 可直接推上 ALB）
├── renew.py              到期判断 + 续期 + 部署（供计划任务调用）
├── renew.bat             计划任务入口（CRLF，勿改成 LF）
├── acme_client.py        ACME v2 协议实现（JWS 签名、订单、挑战、签发）
├── dns_providers/        DNS 记录写入（阿里云云解析，纯标准库）
│   ├── aliyun.py         RPC 签名与云解析接口
│   └── check.py          权威 NS 生效检测
├── requirements.txt      仅 cryptography 与 certifi
├── web/                  界面（index / deploy 两套页面）
├── deploy/               阿里云 ALB 证书自动部署（可选，需额外装 SDK）
│   ├── alb_deploy.py     上传证书并替换监听证书
│   ├── ram-policy.json   最小权限策略（部署）
│   ├── ram-policy-dns.json 最小权限策略（云解析）
│   └── run-alb-deploy.bat
├── docs/                 文档（证书概念、DNS 自动化、ALB 部署）
├── data/accounts/        ACME 账号密钥（已被 .gitignore 排除）
└── certs/                签发的证书（已被 .gitignore 排除）
```

---

## 环境要求

- Python 3.9+
- 能访问 `acme-v02.api.letsencrypt.org`（走代理时会自动沿用系统 `HTTPS_PROXY`）

自动写 DNS 记录不需要额外依赖：云解析的 RPC 签名用标准库实现，`requirements.txt` 不必改。
只有部署到 ALB 才需要装阿里云 SDK。

申请正式证书的前提：域名已完成 ICP 备案（国内服务器）、域名解析指向目标机器、80 或 DNS 可正常访问。

---

## 延伸阅读

初次接触证书概念，建议先读 [**证书基础：域名层级、CSR/SAN 与那一堆 .pem 文件**](./docs/certificate-basics.md)：

- apex（裸域名）是什么，为什么 `*.example.com` 不覆盖 `example.com`
- CSR、CN、SAN 分别管什么，为什么「CSR 与订单标识不一致」会导致签发失败
- 为什么证书是好几个文件，`fullchain` / `cert` / `chain` / `privkey` 各自的作用
- 各服务器到底该配哪两个文件，以及用 openssl 自查证书的 5 条命令
- 术语速查表（ACME、order、authorization、challenge、leaf、intermediate…）

需要把证书自动部署到阿里云负载均衡，见 [**把证书自动部署到阿里云 ALB**](./docs/deploy-alibaba-alb.md)：最小权限策略、幂等替换、线上校验、计划任务写法。

想让 DNS-01 验证也不再手工复制，见 [**让工具自己写 DNS 记录**](./docs/dns-auto-alibaba.md)：云解析最小权限、生效判定为什么查权威服务器、临时记录怎么清理、无人值守命令怎么写。

想知道三块拼起来之后闭环长什么样，见 [**从三个断点到一个闭环**](./docs/auto-renew-close-loop.md)（配 [框图](./docs/auto-renew-close-loop.html)）：为什么 15 天窗口而不是每天签发、失败时线上处于什么状态、闭环成立的三个前提条件。

装好 SDK 后，签发完成页会多出一个「部署到阿里云 ALB」入口；证书申请页左侧边栏底部也有常驻入口，未签发证书时也能直接进入。也可以在浏览器直接访问 `http://127.0.0.1:8899/deploy`：选证书、填 AccessKey 与监听 ID（可自动读取）、先预演后执行。「预演模式」开关常驻在页面主区域，不折叠在「高级选项」里。命令行与界面完全等价。

---

## 许可证

本项目采用 [MIT 协议](./LICENSE) 开源，可自由使用、修改、分发，包括商业用途，保留版权声明即可。

证书与私钥由你自己的 Let's Encrypt 账号签发，**不包含在本仓库中**，也不受本协议约束。

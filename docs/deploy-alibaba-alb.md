# 把证书自动部署到阿里云 ALB

> 适用范围：证书已由本工具签发完成，ALB 实例与 HTTPS 监听已存在，需要把「上传 + 绑定」这一段自动化。

本文只讲**部署**。签发与 DNS 验证仍由主工具完成，两者通过 `certs/` 目录衔接。DNS 记录若也想自动化（阿里云云解析），见 [让工具自己写 DNS 记录](./dns-auto-alibaba.md)。

---

## 前提

- ALB 实例与 **HTTPS 监听** 已建好。如果监听还没建，需要先手动绑定一张证书——ALB 创建 HTTPS 监听时必须选证书，无法留空。第一次可以随便传一张，之后交给脚本替换。
- 证书目录 `certs/<域名>-<时间戳>/` 内包含 `fullchain.pem` 与 `privkey.pem`。
- 站点域名已完成 ICP 备案（中国大陆地域的 ALB 强制要求）。

---

## 图形界面（推荐）

主工具自带一个网页界面，不必记命令行参数。

**打开方式**：先装好 SDK（见下一节），重启 `run.bat`，在「证书已签发」页点 **部署到阿里云 ALB**；也可直接访问 `http://127.0.0.1:8899/deploy`。

界面上需要填的东西只有四项：

| 项目 | 说明 |
|---|---|
| 证书 | 自动列出 `certs/` 下所有证书，按签发时间倒序，选中即显示 SAN、到期日、密钥类型、序列号 |
| AccessKey | RAM 子账号的 ID 与 Secret。勾选「记住凭证」后写入 `data/alb.env`，下次打开只需一键复用 |
| 地域 | 必须与 ALB 实例所在地域一致，否则查不到监听 |
| 监听 ID | 形如 `lsn-e9zuvbx0gwz087g7tq`。可以手填，也可以点「验证凭证并读取监听」自动列出该地域所有监听，点一下即填入 |

界面上还有一个便利：**「验证凭证并读取监听」只调只读接口**，能在真正部署前确认 AccessKey 有效、权限到位、监听 ID 有没有抄错——这一步可以省掉大半排查时间。

推荐的操作顺序：

1. 保持「预演模式」勾选，点「开始部署」。日志会列出将要执行的动作，不产生任何变更。
2. 确认日志符合预期，取消勾选预演，再点一次。此时会弹出确认框，确认后才会真正上传并替换。
3. 部署完成后看结果条与日志末尾，红色记录即失败原因。

界面的所有能力都对应 `alb_deploy.py` 的命令行参数，两者等价：界面提交的参数就是命令行参数，日志也是同一套。所以自动化场景仍按下面几节用命令行或计划任务，日常手工部署用界面更省事。

> 凭证只存在本机：勾选「记住」时写入 `data/alb.env`（已被 `.gitignore` 排除），不勾选则仅当次运行有效，既不落盘也不进命令行。界面回传时只显示掩码（`LTAI***7890`），Secret 不会被读回。

---

## 一、准备

### 1. 安装 SDK

主工具只有 `cryptography` 和 `certifi` 两个依赖，这部分刻意分开，不污染主环境：

```bash
# Windows
.venv\Scripts\python.exe -m pip install -r deploy/requirements-aliyun.txt

# macOS / Linux
.venv/bin/python -m pip install -r deploy/requirements-aliyun.txt
```

装的是 `alibabacloud_cas20200407`（证书服务）与 `alibabacloud_alb20200616`（负载均衡）。

### 2. 建最小权限策略

RAM 控制台 → 权限策略 → 切到「自定义策略」→ **创建权限策略** → 选 **脚本编辑** → 粘贴 `deploy/ram-policy.json` 的内容。

不要用 `AliyunALBFullAccess`：它不覆盖证书服务，而且包含删除监听、修改后端服务器组等权限，泄露后站点可直接被下线。

策略覆盖以下动作，都是这条链路真正会用到的：

| 服务 | 动作 | 用途 |
| --- | --- | --- |
| ALB | `ListListeners` | 界面「读取监听」时列出该地域监听 |
| ALB | `GetListenerAttribute` | 读取监听详情 |
| ALB | `ListListenerCertificates` | 查询监听当前证书（幂等判断） |
| ALB | `UpdateListenerAttribute` | 替换默认证书 |
| ALB | `AssociateAdditionalCertificatesWithListener` | 添加扩展证书 |
| ALB | `DissociateAdditionalCertificatesFromListener` | 摘除旧扩展证书 |
| CAS | `UploadUserCertificate` | 上传证书 |
| CAS | `GetUserCertificateDetail` | 上传后回读证书信息 |
| CAS | `DeleteUserCertificate` | 清理旧证书（可选，对应 `--prune-old-cert`） |
| CAS | `ListUserCertificateOrder` | 只读探测证书服务是否可用（界面「验证凭证」用到） |

注意 `Associate` / `Dissociate` 是**复数**形式，写单数会提示动作不存在。

### 3. 拿 AccessKey

给一个专用 RAM 用户创建 AccessKey，只授上面那条策略。凭证有三种给法，优先级从高到低：

1. 环境变量 `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET`
2. `--env-file` 指向的密钥文件
3. `--access-key-id` / `--access-key-secret` 命令行参数（会留在命令历史里，不建议）

推荐在 `data/alb.env` 放凭证，`data/` 已被 `.gitignore` 排除：

```
ALIBABA_CLOUD_ACCESS_KEY_ID=LTAIxxxxxxxxxxxx
ALIBABA_CLOUD_ACCESS_KEY_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 二、首次部署

先试跑，确认脚本会做什么，不调用任何写接口：

```bash
python deploy/alb_deploy.py \
  --listener-id lsn-xxxxxxxx \
  --region cn-hangzhou \
  --domain example.com \
  --dry-run
```

输出会列出：选中的证书目录、域名与 SAN、证书链张数、剩余天数，以及「将上传**哪个名字**的证书、对哪个监听做什么」。

确认无误后去掉 `--dry-run` 正式执行，并加上线上校验：

```bash
python deploy/alb_deploy.py \
  --listener-id lsn-xxxxxxxx \
  --region cn-hangzhou \
  --domain example.com \
  --verify-host www.example.com
```

`--verify-host` 会真的连一次 443 做 TLS 握手，比对线上证书序列号与本地是否一致。ALB 证书生效有几秒延迟，脚本内部会重试。**只看 API 返回成功不够**，这一步才是「确实生效」的证据。

Windows 下可以直接用 `deploy\run-alb-deploy.bat`，参数相同：

```bat
deploy\run-alb-deploy.bat --listener-id lsn-xxxxxxxx --region cn-hangzhou --domain example.com --verify-host www.example.com
```

脚本会自动带上 `--env-file data\alb.env`（若该文件存在）。

---

## 三、参数

| 参数 | 说明 |
| --- | --- |
| `--listener-id` | 必填。可逗号分隔或重复传多次，多个监听共用一张证书时只上传一次 |
| `--region` | 默认 `cn-hangzhou`，必须与 ALB 实例地域一致 |
| `--domain` | 从 `certs/` 里挑目录名含该域名的最新一版 |
| `--cert-dir` | 直接指定证书目录，优先于 `--domain` |
| `--role` | `default`（默认，替换监听默认证书）或 `additional`（作为扩展证书，SNI 多域名） |
| `--verify-host` | 部署后做一次 TLS 校验；ALB 不对公网开放时不要加 |
| `--dry-run` | 只打印计划 |
| `--force-upload` | 忽略幂等判断强制上传 |
| `--prune-additional` | `role=additional` 时摘除上一张扩展证书 |
| `--prune-old-cert` | 切换成功后删除上一张证书（仍被其他云产品引用时跳过并告警） |
| `--env-file` | 从 KEY=VALUE 文件读凭证 |
| `--state-file` | 状态文件路径，默认 `data/alb-state.json` |
| `-v` | 调试输出 |

---

## 四、幂等

判断依据是 `data/alb-state.json` 里记录的「监听 → 证书 ID + 序列号」，同时会向 ALB 查一次该证书是否还挂在监听上。两个条件都满足才跳过：

```
本地序列号 == 状态文件序列号  AND  状态文件里的 CertId 仍在监听的证书列表中
```

因此重复执行是安全的，可以放心接计划任务。

两个已知行为：

- **状态文件被删**：会重新上传一张。功能不受影响，只是证书服务里多一条记录，可用 `--prune-old-cert` 或在控制台手工清理。
- **多监听**：新证书只上传一次，然后分别绑定到各监听。

上传到阿里云的证书名固定为 `<域名>-<到期日>`，例如 `wildcard.example.com-20270125`。带到期日是为了续期后一眼分清新旧。

---

## 五、接到计划任务

证书 90 天到期，建议**到期前 30 天**开始执行，失败可次日在下一轮自然重试。

Windows 任务计划程序：

- 程序：`D:\ai\letsencrypt-tool\deploy\run-alb-deploy.bat`
- 参数：`--listener-id lsn-xxxxxxxx --region cn-hangzhou --domain example.com --verify-host www.example.com`
- 起始于：`D:\ai\letsencrypt-tool`
- 触发器：每天一次
- 勾选「如果任务失败，按以下频率重新启动」

Linux cron：

```cron
0 9 * * * cd /opt/letsencrypt-tool && .venv/bin/python deploy/alb_deploy.py \
  --listener-id lsn-xxxxxxxx --region cn-hangzhou --domain example.com \
  --verify-host www.example.com --env-file data/alb.env >> data/alb-deploy.log 2>&1
```

每天跑不会产生额外副作用——幂等判断会让它在证书未变时直接退出。

注意：这一步只解决「部署」。新证书从哪来仍需先跑签发流程；要全自动，还需要把 DNS 记录也自动化，那是另一段。

---

## 六、退出码与排查

| 退出码 | 含义 | 常见原因 |
| --- | --- | --- |
| 0 | 成功，或已是最新 | — |
| 1 | 本地证书问题 | 目录不存在、私钥不配对、证书已过期、证书不覆盖 `--verify-host` 的域名 |
| 2 | 凭证或权限 | AccessKey 错误、RAM 策略未授权、地域不符 |
| 3 | 上传失败 | 证书内容格式错误、证书数量配额已满 |
| 4 | 监听更新失败 | 监听 ID 错误、监听不是 HTTPS、扩展证书用法有误 |
| 5 | TLS 校验未通过 | 替换未生效、DNS 未指向该 ALB、`--verify-host` 指向了证书不覆盖的域名 |
| 6 | 运行环境 | 未安装阿里云 SDK |
| 7 | 网络问题 | 域名解析失败、代理拒绝连接、连不上阿里云 |

脚本会把阿里云返回的错误码翻译成人话，例如：

```
[FAIL] 查询监听证书失败：Specified access key is not found.（错误码：InvalidAccessKeyId.NotFound）；AccessKey 不正确，或与 RAM 用户不匹配
```

`data\alb-deploy.log` 只在失败时追加一行，便于发现计划任务连续失败。

几个高频情况：

- **提示「证书不覆盖 xxx」**：泛域名不包含裸域名。证书 SAN 只有 `*.example.com` 时，`example.com` 不可用，`www.example.com` 可以。
- **上传报「私钥与证书不匹配」**：说明拿错了目录里的 `privkey.pem`，脚本在本地就会拦下，不会传到阿里云。
- **上传成功但握手仍是旧证书**：确认改的是同一个监听；若用了扩展证书，`UpdateListenerAttribute` 只改默认证书，扩展证书要走 `--role additional`。
- **报「本机无法解析域名」**：先看提示里的域名。证书服务 CAS 是全局服务，端点是 `cas.aliyuncs.com`；ALB 是地域服务，端点是 `alb.<地域>.aliyuncs.com`。若报的是形如 `cas.cn-hangzhou.aliyuncs.com` 的域名，那是端点拼错，不是网络问题。
- **报「代理服务器拒绝了连接」**：本机设了 `HTTP_PROXY` 而代理不转发该域名。临时清掉代理环境变量，或把阿里云域名加入代理白名单。

---

## 七、扩展证书（SNI 多域名）

一个 HTTPS 监听上按域名挂多张证书时，默认证书由 `UpdateListenerAttribute` 维护，其余是「扩展证书」，走另外两个接口。

```bash
# 新证书作为扩展证书挂上，同时摘掉上一张
python deploy/alb_deploy.py --listener-id lsn-xxxxxxxx --role additional \
  --domain example.com --prune-additional
```

脚本记录每张扩展证书的 CertId，`--prune-additional` 会摘除上一张，避免证书越积越多。

---

## 八、安全须知

- **私钥会上传到阿里云**。TLS 在 ALB 终结，这是必然代价。若不接受，只能改用四层透传（NLB / CLB 的 TCP 监听），由后端自己解密，此时证书不经过云厂商。
- AccessKey 用专用 RAM 用户，只授 `deploy/ram-policy.json` 里的动作；不要复用主账号或其他业务的 AK。
- `data/alb.env` 与 `data/alb-state.json` 都在 `.gitignore` 覆盖范围内，不会进仓库。
- 若脚本跑在 ECS 或函数计算上，优先用**实例角色**代替 AccessKey，磁盘上就不存在长期密钥。
- 建议在费用中心设一条预算告警。证书服务全权限类策略理论上包含证书下单能力，几十元的阈值即可。

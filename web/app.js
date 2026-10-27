/* ============================================================
   前端逻辑：三步向导
   1) 收集信息 → 2) 完成验证 → 3) 下载部署
   ============================================================ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  session: null,
  step: 1,
  deployTab: "nginx",
  logTimer: null,
  logCursor: 0,
  overlayTimer: null,
  overlayStart: 0,
};

/* ----------------------------- 通用工具 ----------------------------- */

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function showOverlay(text, hint = "请勿关闭此页面") {
  $("#overlayText").textContent = text;
  $("#overlayHint").textContent = hint;
  $("#overlay").classList.remove("hidden");
  state.overlayStart = Date.now();
  clearInterval(state.overlayTimer);
  state.overlayTimer = setInterval(() => {
    const sec = Math.floor((Date.now() - state.overlayStart) / 1000);
    if (sec > 2) $("#overlayHint").textContent = `${hint} · 已用 ${sec} 秒`;
  }, 1000);
}

function hideOverlay() {
  $("#overlay").classList.add("hidden");
  clearInterval(state.overlayTimer);
}

function toast(message, type = "error", title = "") {
  const el = document.createElement("div");
  el.className = "toast" + (type === "ok" ? " is-ok" : type === "warn" ? " is-warn" : "");
  el.innerHTML = (title ? `<b>${escapeHtml(title)}</b>` : "") + escapeHtml(message);
  $("#toastWrap").appendChild(el);
  setTimeout(() => {
    el.classList.add("is-out");
    setTimeout(() => el.remove(), 220);
  }, type === "error" ? 7000 : 4200);
}

async function api(path, body) {
  const options = body === undefined
    ? { method: "GET" }
    : {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      };
  const resp = await fetch(path, options);
  let payload;
  try {
    payload = await resp.json();
  } catch (e) {
    throw { message: `服务器返回了无法解析的内容（HTTP ${resp.status}）` };
  }
  if (!payload.ok) {
    const err = payload.error || { message: "未知错误" };
    err.session = payload.data || null;
    throw err;
  }
  return payload.data;
}

function copyText(text, btn) {
  const done = () => {
    const original = btn.textContent;
    btn.textContent = "已复制";
    btn.classList.add("is-copied");
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("is-copied");
    }, 1400);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallback());
  } else {
    fallback();
  }
  function fallback() {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); done(); } catch (e) { toast("复制失败，请手动选中复制"); }
    ta.remove();
  }
}

/* ----------------------------- 步骤切换 ----------------------------- */

function gotoStep(n) {
  state.step = n;
  [1, 2, 3].forEach((i) => $(`#step${i}`).classList.toggle("hidden", i !== n));
  $$("#steps .step").forEach((el) => {
    const num = Number(el.dataset.step);
    el.classList.toggle("is-active", num === n);
    el.classList.toggle("is-done", num < n);
  });
  $(".main-scroll").scrollTop = 0;
}

/* ----------------------------- 步骤 1 ----------------------------- */

const DOMAIN_RE = /^(?:\*\.)?(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

function parseDomains() {
  const raw = $("#domains").value || "";
  const parts = raw.split(/[\s,;，；]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  const seen = new Set();
  const out = [];
  parts.forEach((d) => {
    const clean = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
    if (!clean || seen.has(clean)) return;
    seen.add(clean);
    out.push({ value: clean, ok: DOMAIN_RE.test(clean) });
  });
  return out;
}

function renderChips() {
  const list = parseDomains();
  $("#domainChips").innerHTML = list
    .map((d) => {
      const cls = d.ok ? (d.value.startsWith("*.") ? "chip is-wild" : "chip") : "chip is-bad";
      return `<span class="${cls}">${escapeHtml(d.value)}${d.ok ? "" : " 格式有误"}</span>`;
    })
    .join("");
}

function currentChallenge() {
  return ($('input[name="challenge"]:checked') || {}).value || "http_auto";
}

function syncConditionalFields() {
  const mode = currentChallenge();
  $("#fieldWebroot").classList.toggle("hidden", mode !== "http_manual");
  $("#fieldPort").classList.toggle("hidden", mode !== "http_auto");
}

function syncEnvBadge() {
  const staging = $("#staging").checked;
  const badge = $("#envBadge");
  badge.textContent = staging ? "测试环境" : "正式环境";
  badge.classList.toggle("is-staging", staging);
}

async function submitForm() {
  const domains = parseDomains();
  if (!domains.length) {
    toast("请先填写要申请证书的域名", "error", "缺少域名");
    $("#domains").focus();
    return;
  }
  const bad = domains.filter((d) => !d.ok);
  if (bad.length) {
    toast(`以下域名格式不正确：${bad.map((d) => d.value).join("、")}`, "error", "域名格式有误");
    return;
  }
  const wildcard = domains.some((d) => d.value.startsWith("*."));
  if (wildcard && currentChallenge() !== "dns") {
    toast("泛域名证书只能使用 DNS 验证，请切换验证方式，或去掉 *. 开头的域名", "error", "验证方式不匹配");
    return;
  }

  const body = {
    domains: domains.map((d) => d.value),
    email: $("#email").value.trim(),
    challenge: currentChallenge(),
    staging: $("#staging").checked,
    key_type: $("#keyType").value,
    http_port: Number($("#httpPort").value) || 80,
    webroot: $("#webroot").value.trim(),
  };

  const btn = $("#btnSubmit");
  btn.classList.add("is-loading");
  btn.disabled = true;
  showOverlay("正在连接 Let's Encrypt", "创建 ACME 账号与订单");
  try {
    const session = await api("/api/sessions", body);
    state.session = session;
    gotoStep(2);
    startLogPolling();
    await prepare();
  } catch (err) {
    hideOverlay();
    toast(err.message || "创建会话失败", "error", "无法开始");
  } finally {
    btn.classList.remove("is-loading");
    btn.disabled = false;
  }
}

/* ----------------------------- 步骤 2 ----------------------------- */

async function prepare() {
  showOverlay("正在准备验证", "向 CA 申请域名授权");
  try {
    const session = await api(`/api/sessions/${state.session.id}/prepare`, {});
    state.session = session;
    hideOverlay();
    renderStep2();

    const pending = session.challenges.filter((c) => c.status !== "valid");
    if (!pending.length) {
      toast("域名授权已全部有效，正在直接签发证书", "ok", "无需验证");
      await finalize();
    }
  } catch (err) {
    hideOverlay();
    if (err.session) {
      state.session = err.session;
      renderStep2();
      openLogDock();
    } else {
      gotoStep(1);
    }
    toast(err.message || "准备阶段失败", "error", "出现问题");
  }
}

function statusLabel(status) {
  return ({
    pending: "等待验证",
    processing: "验证中",
    valid: "已验证",
    invalid: "验证失败",
    timeout: "验证超时",
    deactivated: "已失效",
    expired: "已过期",
    revoked: "已吊销",
  }[status] || status || "未知");
}

function statusClass(status) {
  if (status === "valid") return "st-valid";
  if (status === "invalid" || status === "revoked" || status === "expired" || status === "timeout") return "st-invalid";
  if (status === "processing") return "st-processing";
  return "st-pending";
}

function renderStep2() {
  const s = state.session;

  // 顶部提示
  const warnBox = $("#warnBox");
  const warnings = (s.preflight && s.preflight.warnings) || [];
  const noChallenges = !(s.challenges || []).length;

  if (noChallenges) {
    // 准备阶段没有拿到任何验证信息：明确告知用户卡在哪，而不是展示一张空表格
    warnBox.className = "alert alert-warn";
    warnBox.classList.remove("hidden");
    warnBox.innerHTML =
      "<div><b>尚未获取到域名验证信息。</b>「准备」阶段没有成功向 CA 创建订单" +
      "（常见原因：网络波动、CA 暂时无响应、TLS 证书校验失败）。" +
      "请点击右侧「重新准备」重试；若多次失败，请查看底部「运行日志」中的具体错误，" +
      "或「返回修改」确认域名后重新提交。</div>";
  } else if (warnings.length) {
    warnBox.className = "alert alert-warn";
    warnBox.classList.remove("hidden");
    warnBox.innerHTML = "<div><b>注意：</b><ul>" +
      warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("") + "</ul></div>";
  } else {
    warnBox.classList.add("hidden");
  }

  // 域名状态
  $("#challengeList").innerHTML = (s.challenges || []).map((c) => `
    <li>
      <span class="d-domain">${escapeHtml(c.domain)}</span>
      ${c.error ? `<span class="d-error">${escapeHtml(c.error)}</span>` : ""}
      <span class="d-status ${statusClass(c.status)}">${statusLabel(c.status)}</span>
    </li>
  `).join("");

  // 指引
  const mode = s.config.challenge;
  $("#guideAuto").classList.toggle("hidden", mode !== "http_auto");
  $("#guideManual").classList.toggle("hidden", mode !== "http_manual");
  $("#guideDns").classList.toggle("hidden", mode !== "dns");

  if (mode === "http_auto") renderAutoGuide(s);
  if (mode === "http_manual") renderManualGuide(s);
  if (mode === "dns") renderDnsGuide(s);

  // 副标题
  const subtitles = {
    http_auto: "验证服务已在本机启动，确认下面列出的地址可以被外网访问后，点击「开始验证」。",
    http_manual: "按提示把验证文件放到网站根目录，确认可以通过 http:// 访问到后，点击「开始验证」。",
    dns: "添加下列 TXT 记录，等解析生效后点击「开始验证」。",
  };
  $("#step2Subtitle").textContent = subtitles[mode] || "";

  const pending = (s.challenges || []).some((c) => c.status !== "valid");
  $("#btnValidate").classList.toggle("hidden", noChallenges || !pending);
  $("#btnRetryPrepare").classList.toggle("hidden", !noChallenges);
  $("#dnsCheckResult").textContent = "";
}

function fileItemsHtml(s) {
  const items = (s.challenges || []).filter((c) => c.token);
  if (!items.length) {
    return `<p class="muted small">尚未获取到验证文件信息——「准备」阶段未成功创建订单，请点击「重新准备」或「返回修改」后重试。</p>`;
  }
  return items.map((c, i) => `
    <div class="file-item">
      <div class="file-item-head">
        <span>验证文件</span>
        <b>${escapeHtml(c.http_relative_path.split("/").pop())}</b>
        <span class="muted small" style="margin-left:auto">${escapeHtml(c.domain)}</span>
      </div>
      <div class="file-body">
        <pre id="keyauth-${i}">${escapeHtml(c.keyauth)}</pre>
        <button class="copy-btn" data-copy-el="keyauth-${i}">复制</button>
      </div>
      ${c.http_file_path
        ? `<div class="file-path">已写入：${escapeHtml(c.http_file_path)}</div>`
        : `<div class="file-path">放置位置：网站根目录 / ${escapeHtml(c.http_relative_path)}</div>`}
    </div>
  `).join("");
}

function renderAutoGuide(s) {
  const port = s.config.http_port;
  const running = s.http_server_running;

  $("#autoUrls").innerHTML = (s.challenges || [])
    .filter((c) => c.http_url)
    .map((c) => `<li>${escapeHtml(c.http_url)}</li>`)
    .join("") || `<li class="muted">尚未获取到验证地址——「准备」阶段未成功创建订单，请点击「重新准备」后重试。</li>`;

  const alert = $("#autoAlert");
  if (running) {
    alert.className = "alert alert-ok";
    alert.innerHTML = `<b>验证服务已启动。</b>本机已监听 ${port} 端口，CA 访问下列地址时能拿到验证内容，你可以直接点击下面的「开始验证」。`;
  } else {
    alert.className = "alert alert-warn";
    alert.innerHTML = `<b>临时验证服务未能启动（端口 ${port} 可能被占用）。</b>已切换为手动模式：请把下面的验证文件放到网站根目录的 <code>.well-known/acme-challenge/</code> 目录中，确认可通过 <code>http://域名/.well-known/acme-challenge/文件名</code> 访问后，再点击「开始验证」。`;
  }

  const fallback = $("#autoFallback");
  if (running) {
    fallback.classList.add("hidden");
    fallback.innerHTML = "";
  } else {
    fallback.classList.remove("hidden");
    fallback.innerHTML = fileItemsHtml(s);
  }

  $("#btnStopHttp").classList.toggle("hidden", !running);
  $("#step2Subtitle").textContent = running
    ? `验证服务已在本机 ${port} 端口启动，点击「开始验证」即可。`
    : "临时服务未能启动，请按提示手动放置验证文件后继续。";
}

function renderManualGuide(s) {
  $("#manualFiles").innerHTML = fileItemsHtml(s);
}

function renderDnsGuide(s) {
  const items = (s.challenges || []).filter((c) => c.dns_name);
  $("#dnsRows").innerHTML = items.map((c, i) => {
    const base = c.dns_name.replace(/^_acme-challenge\./, "");
    return `
      <tr>
        <td class="mono">${escapeHtml(c.domain)}</td>
        <td class="mono">_acme-challenge.${escapeHtml(base)}</td>
        <td class="mono" id="dnsval-${i}">${escapeHtml(c.dns_value)}</td>
        <td><button class="copy-btn" data-copy-el="dnsval-${i}" style="border:none;background:none;padding:0">复制</button></td>
      </tr>`;
  }).join("") || `<tr><td colspan="4" class="muted">尚未获取到 TXT 记录——「准备」阶段未成功创建订单，请点击「重新准备」或「返回修改」后重试。</td></tr>`;
}

async function checkDns() {
  const btn = $("#btnCheckDns");
  btn.classList.add("is-loading");
  btn.disabled = true;
  try {
    const data = await api(`/api/sessions/${state.session.id}/check-dns`, {});
    const total = data.records.length;
    const ok = data.records.filter((r) => r.state === "ok").length;
    $("#dnsCheckResult").textContent = ok === total
      ? `已检测到全部 ${total} 条记录，可以开始验证了。`
      : `已生效 ${ok} / ${total} 条，请稍等再试（DNS 传播一般需要 1–10 分钟）。`;
    if (ok === total && total > 0) toast("DNS 记录已全部生效", "ok", "检查通过");
  } catch (err) {
    toast(err.message || "检查失败", "error");
  } finally {
    btn.classList.remove("is-loading");
    btn.disabled = false;
  }
}

async function validate() {
  const btn = $("#btnValidate");
  btn.classList.add("is-loading");
  btn.disabled = true;
  showOverlay("CA 正在校验域名所有权", "通常需要 5 秒到 1 分钟");
  try {
    const session = await api(`/api/sessions/${state.session.id}/validate`, {});
    state.session = session;
    hideOverlay();
    await finalize();
  } catch (err) {
    hideOverlay();
    if (err.session) {
      state.session = err.session;
      renderStep2();
      openLogDock();
    }
    toast(err.message || "验证未通过", "error", "验证失败");
  } finally {
    btn.classList.remove("is-loading");
    btn.disabled = false;
  }
}

/* ----------------------------- 步骤 3 ----------------------------- */

async function finalize() {
  showOverlay("正在签发证书", "生成私钥并提交 CSR");
  try {
    const session = await api(`/api/sessions/${state.session.id}/finalize`, {});
    state.session = session;
    hideOverlay();
    gotoStep(3);
    renderStep3();
    stopLogPolling();
    refreshLogs(true);
  } catch (err) {
    hideOverlay();
    if (err.session) state.session = err.session;
    toast(err.message || "签发失败", "error", "签发失败");
    if (state.step === 3) renderStep2();
  }
}

const DEPLOY_TEMPLATES = {
  nginx: (d) => `server {
    listen 443 ssl;
    http2 on;
    server_name ${d.domains.join(" ")};

    ssl_certificate     ${d.dir}/fullchain.pem;
    ssl_certificate_key ${d.dir}/privkey.pem;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    location / {
        root   /var/www/html;   # 改成你的网站目录
        index  index.html;
    }
}

# 检查配置后重载：
#   nginx -t && nginx -s reload`,
  apache: (d) => `<VirtualHost *:443>
    ServerName ${d.domains[0]}
    DocumentRoot "/var/www/html"    # 改成你的网站目录

    SSLEngine on
    SSLCertificateFile      "${d.dir}/cert.pem"
    SSLCertificateKeyFile   "${d.dir}/privkey.pem"
    SSLCertificateChainFile "${d.dir}/chain.pem"

    <Directory "/var/www/html">
        Require all granted
    </Directory>
</VirtualHost>

# 启用 SSL 模块并重载：
#   a2enmod ssl && systemctl reload apache2`,
  iis: (d) => `# IIS 需要 PFX 格式，先用 OpenSSL 转换（Windows 可用 Git 自带的 openssl）：
openssl pkcs12 -export -out cert.pfx \\\\
  -inkey "${d.dir.replace(/\\\\/g, "/")}/privkey.pem" \\\\
  -in "${d.dir.replace(/\\\\/g, "/")}/cert.pem" \\\\
  -certfile "${d.dir.replace(/\\\\/g, "/")}/chain.pem"

# 然后在 IIS 管理器中：
#   1. 服务器 → "服务器证书" → 导入 cert.pfx
#   2. 选中站点 → 绑定 → 添加 → 类型 https，端口 443，选择该证书
#   3. 建议同时添加 http → https 的 URL 重写规则
# 或用命令行：
#   netsh http add sslcert hostnameport=${d.domains[0]}:443 \\\\
#         certhash=<证书指纹> appid={...} certstorename=MY`,
  node: (d) => `const https = require("https");
const fs = require("fs");
const path = require("path");

const dir = ${JSON.stringify(d.dir.replace(/\\/g, "/"))};

https.createServer({
  key:  fs.readFileSync(path.join(dir, "privkey.pem")),
  cert: fs.readFileSync(path.join(dir, "fullchain.pem")),
}, (req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("HTTPS 已生效 🎉");
}).listen(443, () => console.log("https://127.0.0.1:443"));`,
};

function renderStep3() {
  const s = state.session;
  const info = s.cert_info || {};

  $("#certDomains").textContent = (info.domains && info.domains.length
    ? info.domains
    : s.config.domains
  ).join("  ·  ");

  const staging = s.config.staging;
  $("#certMeta").innerHTML = [
    `签发者：${escapeHtml(info.issuer || "-")}`,
    `有效期至：${escapeHtml(info.not_after || "-")}`,
    `密钥：${({ ec256: "ECDSA P-256", ec384: "ECDSA P-384", rsa2048: "RSA 2048", rsa4096: "RSA 4096" })[s.config.key_type] || s.config.key_type}`,
    staging ? `<span style="color:#f5c26b">测试证书 · 浏览器不信任</span>` : "",
  ].filter(Boolean).join("<br>");

  $("#certDays").textContent = info.days_left ?? "--";
  $("#outputDir").textContent = s.output_dir || "";

  $$(".dl").forEach((a) => {
    a.href = `/api/sessions/${s.id}/download/${a.dataset.kind}`;
  });

  renderDeployCode();
  refreshLogs(true);
}

function renderDeployCode() {
  const s = state.session;
  const dir = (s.output_dir || "").replace(/\\/g, "/");
  const tpl = DEPLOY_TEMPLATES[state.deployTab];
  $("#deployCode").textContent = tpl ? tpl({ domains: s.config.domains, dir }) : "";
}

/* ----------------------------- 日志 ----------------------------- */

function openLogDock() {
  const dock = $("#logdock");
  if (dock && !dock.classList.contains("is-open")) {
    dock.classList.add("is-open");
    const body = $("#logBody");
    body.scrollTop = body.scrollHeight;
  }
}

function startLogPolling() {
  stopLogPolling();
  state.logTimer = setInterval(() => refreshLogs(false), 2000);
  refreshLogs(true);
}

function stopLogPolling() {
  clearInterval(state.logTimer);
  state.logTimer = null;
}

async function refreshLogs(force) {
  if (!state.session) return;
  try {
    const data = await api(`/api/sessions/${state.session.id}/logs`);
    const logs = data.logs || [];
    const box = $("#logLines");
    box.innerHTML = logs.length
      ? logs.map((l) => `<div class="log-line ${l.level}"><span class="t">${escapeHtml(l.time)}</span><span class="m">${escapeHtml(l.message)}</span></div>`).join("")
      : `<p class="muted small">暂无日志</p>`;
    if (logs.length) {
      $("#logLast").textContent = logs[logs.length - 1].message;
      const dock = $("#logdock");
      if (dock.classList.contains("is-open")) {
        const body = $("#logBody");
        body.scrollTop = body.scrollHeight;
      }
    }
  } catch (e) {
    /* 忽略轮询错误 */
  }
}

/* ----------------------------- 事件绑定 ----------------------------- */

function bind() {
  $("#domains").addEventListener("input", renderChips);

  $$("#challengeOptions .option").forEach((opt) => {
    opt.addEventListener("click", () => {
      $$("#challengeOptions .option").forEach((o) => o.classList.remove("is-selected"));
      opt.classList.add("is-selected");
      setTimeout(syncConditionalFields, 0);
    });
  });

  $$('input[name="challenge"]').forEach((r) => {
    r.addEventListener("change", syncConditionalFields);
  });

  $("#staging").addEventListener("change", syncEnvBadge);

  $("#btnSubmit").addEventListener("click", submitForm);

  $("#btnBack1").addEventListener("click", () => {
    stopLogPolling();
    gotoStep(1);
  });

  $("#btnValidate").addEventListener("click", validate);
  $("#btnCheckDns").addEventListener("click", checkDns);

  $("#btnRetryPrepare").addEventListener("click", async () => {
    await prepare();
  });

  $("#btnStopHttp").addEventListener("click", async () => {
    try {
      state.session = await api(`/api/sessions/${state.session.id}/stop-http`, {});
      renderStep2();
      toast("临时验证服务已关闭", "warn");
    } catch (e) {
      toast("关闭失败：" + e.message);
    }
  });

  $("#btnRestart").addEventListener("click", () => {
    state.session = null;
    $("#domains").value = "";
    $("#email").value = "";
    $("#webroot").value = "";
    $("#httpPort").value = "80";
    $("#staging").checked = false;
    renderChips();
    syncEnvBadge();
    syncConditionalFields();
    $("#logLines").innerHTML = `<p class="muted small">暂无日志</p>`;
    $("#logLast").textContent = "等待开始…";
    gotoStep(1);
  });

  // 部署代码 tab
  $$("#deployTabs .tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$("#deployTabs .tab").forEach((t) => t.classList.remove("is-active"));
      tab.classList.add("is-active");
      state.deployTab = tab.dataset.tab;
      renderDeployCode();
    });
  });

  // 日志坞展开
  $("#logToggle").addEventListener("click", () => {
    $("#logdock").classList.toggle("is-open");
    const body = $("#logBody");
    if ($("#logdock").classList.contains("is-open")) body.scrollTop = body.scrollHeight;
  });

  // 复制按钮（动态生成，用事件委托）
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest(".copy-btn");
    if (!btn) return;
    const elId = btn.dataset.copyEl;
    if (elId) {
      const el = document.getElementById(elId);
      if (el) copyText(el.textContent, btn);
      return;
    }
    const targetId = btn.dataset.copyTarget;
    if (targetId) {
      const el = document.getElementById(targetId);
      if (el) copyText(el.textContent, btn);
    }
  });

  // 下载失败提示
  document.addEventListener("click", (ev) => {
    if (ev.target.closest(".dl") && !state.session) ev.preventDefault();
  });

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) {
      if (state.step === 1) submitForm();
      else if (state.step === 2) validate();
    }
  });
}

/* ----------------------------- 启动 ----------------------------- */

function init() {
  bind();
  renderChips();
  syncConditionalFields();
  syncEnvBadge();
}

init();

// 暴露内部状态，便于调试与自动化测试（不影响正常使用）
window.__le = { state, gotoStep, renderStep2, renderStep3, renderDeployCode, renderChips };

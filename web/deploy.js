/* ============================================================
   阿里云 ALB 证书部署 —— 页面逻辑
   ============================================================ */

const $ = (sel) => document.querySelector(sel);

const state = {
  certs: [],
  current: null,
  cred: { saved: false, masked: "", updated_at: "" },
  jobId: null,
  polling: false,
  running: false,
};

const REGION_KEY = "le-alb-region";

/* ----------------------------- 基础工具 ----------------------------- */

function escapeHtml(str) {
  return String(str == null ? "" : str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function toast(message, type = "info", title = "") {
  const wrap = $("#toastWrap");
  if (!wrap) return;
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  const head = title ? `<b>${escapeHtml(title)}</b>` : "";
  el.innerHTML = `${head}<span>${escapeHtml(message)}</span>`;
  wrap.appendChild(el);
  setTimeout(() => {
    el.classList.add("is-out");
    setTimeout(() => el.remove(), 300);
  }, type === "error" ? 7000 : 3600);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  let payload = null;
  try {
    payload = await res.json();
  } catch (e) {
    throw new Error(`服务返回异常（HTTP ${res.status}）`);
  }
  if (!payload || payload.ok !== true) {
    const msg = (payload && payload.error && payload.error.message) || `请求失败（HTTP ${res.status}）`;
    const err = new Error(msg);
    err.payload = payload;
    throw err;
  }
  return payload.data;
}

/* ----------------------------- 日志坞 ----------------------------- */

let logOpen = false;

function setLogOpen(open) {
  logOpen = open;
  const dock = $("#logdock");
  if (!dock) return;
  dock.classList.toggle("is-open", open);
}

function renderLogs(logs) {
  const box = $("#logLines");
  if (!box) return;
  if (!logs || !logs.length) {
    box.innerHTML = `<p class="muted small">暂无日志</p>`;
    return;
  }
  const scroller = $("#logBody");
  const nearBottom = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 80;

  box.innerHTML = logs.map((l) => {
    const lv = l.level || "info";
    return `<div class="log-line ${lv}">` +
      `<span class="t">${escapeHtml(l.time || "")}</span>` +
      `<span class="m">${escapeHtml(l.message || "")}</span>` +
      `</div>`;
  }).join("");

  if (nearBottom) {
    scroller.scrollTop = scroller.scrollHeight;
  }

  const last = logs[logs.length - 1];
  if (last) $("#logLast").textContent = last.message || "";
}

/* ----------------------------- 步骤指示 ----------------------------- */

function updateSteps() {
  const hasCert = !!state.current;
  const hasCred = state.cred.saved || ($("#akId").value.trim() && $("#akSecret").value.trim());
  const hasListener = $("#listeners").value.trim().length > 0;

  const done = [hasCert, hasCred && hasListener, false];
  if (state.running) {
    done[2] = true;
  }

  document.querySelectorAll("#steps .step").forEach((li, idx) => {
    li.classList.toggle("is-active", state.running ? idx === 2 : idx === done.findIndex((d) => !d));
    li.style.opacity = done[idx] ? "1" : "0.55";
  });

  const btn = $("#btnRun");
  const ready = hasCert && hasCred && hasListener && !state.running;
  btn.disabled = !ready;
  btn.style.opacity = ready ? "1" : "0.5";
  btn.style.cursor = ready ? "pointer" : "not-allowed";
}

/* ----------------------------- 证书列表 ----------------------------- */

function sanCovers(host, san) {
  const h = String(host || "").toLowerCase();
  if (!h) return false;
  return (san || []).some((raw) => {
    const s = String(raw).toLowerCase();
    if (s === h) return true;
    if (s.startsWith("*.")) {
      const suffix = s.slice(1);
      if (!h.endsWith(suffix)) return false;
      const left = h.slice(0, h.length - suffix.length);
      return left.length > 0 && !left.includes(".");
    }
    return false;
  });
}

function renderCertMeta() {
  const meta = $("#certMeta");
  const warn = $("#certWarn");
  const c = state.current;

  if (!c) {
    meta.innerHTML = "";
    warn.classList.add("hidden");
    return;
  }

  if (!c.usable) {
    meta.innerHTML = `
      <div class="kv"><dt>状态</dt><dd style="color:var(--danger)">不可部署</dd></div>
      <div class="kv"><dt>签发时间</dt><dd>${escapeHtml(c.saved_at)}</dd></div>
    `;
    warn.classList.remove("hidden");
    warn.innerHTML = `<b>这张证书暂时不能用：</b>${escapeHtml(c.error)}`;
    return;
  }

  const days = Number(c.days_left || 0);
  const dayColor = days <= 14 ? "var(--danger)" : days <= 30 ? "var(--warn)" : "var(--ink)";
  meta.innerHTML = `
    <div class="kv"><dt>域名（CN）</dt><dd>${escapeHtml(c.cn)}</dd></div>
    <div class="kv"><dt>覆盖域名（SAN）</dt><dd class="mono">${escapeHtml((c.san || []).join("  ")) || "-"}</dd></div>
    <div class="kv"><dt>到期日</dt><dd>${escapeHtml(c.not_after)}</dd></div>
    <div class="kv"><dt>剩余</dt><dd style="color:${dayColor};font-weight:600">${days} 天</dd></div>
    <div class="kv"><dt>证书链</dt><dd>${c.cert_count} 张</dd></div>
    <div class="kv"><dt>密钥</dt><dd class="mono">${escapeHtml(c.key_type)}</dd></div>
    <div class="kv"><dt>序列号</dt><dd class="mono">${escapeHtml(c.serial)}</dd></div>
  `;

  const notes = [];
  if ((c.san || []).every((s) => s.startsWith("*."))) {
    const apex = (c.san[0] || "").replace("*.", "");
    notes.push(`这是纯泛域名证书，不覆盖 <code>${escapeHtml(apex)}</code> 本身。校验域名请填 <code>www.${escapeHtml(apex)}</code> 这类一级子域，填裸域名会被拒绝。`);
  }
  if (days <= 30) {
    notes.push(`距离到期只剩 ${days} 天，建议先续期再部署，避免刚上线又要更换。`);
  }
  if (notes.length) {
    warn.classList.remove("hidden");
    warn.innerHTML = notes.map((n) => `<div>· ${n}</div>`).join("");
  } else {
    warn.classList.add("hidden");
  }
}

async function loadCerts() {
  const select = $("#certSelect");
  try {
    const data = await api("/api/deploy/certs");
    state.certs = data.certs || [];
  } catch (err) {
    select.innerHTML = `<option value="">读取失败</option>`;
    toast(err.message, "error", "无法读取证书列表");
    return;
  }

  if (!state.certs.length) {
    select.innerHTML = `<option value="">certs/ 下没有可用证书</option>`;
    state.current = null;
    renderCertMeta();
    updateSteps();
    toast("还没有签发过证书，请先回到申请页完成签发", "error", "没有可选证书");
    return;
  }

  select.innerHTML = state.certs.map((c) => {
    const flag = c.usable ? "" : "（不可用）";
    return `<option value="${escapeHtml(c.path)}">${escapeHtml(c.name)}${flag}</option>`;
  }).join("");

  const firstUsable = state.certs.find((c) => c.usable) || state.certs[0];
  select.value = firstUsable.path;
  selectCert(firstUsable.path);
}

function selectCert(path) {
  state.current = state.certs.find((c) => c.path === path) || null;
  renderCertMeta();
  suggestVerifyHost();
  updateSteps();
}

function suggestVerifyHost() {
  const input = $("#verifyHost");
  const c = state.current;
  if (!c || !c.usable || input.value.trim()) return;
  const san = c.san || [];
  const plain = san.find((s) => !s.includes("*"));
  if (plain) {
    input.value = plain;
    return;
  }
  const wild = san.find((s) => s.startsWith("*."));
  if (wild) input.placeholder = `例如 sub.${wild.slice(2)}`;
}

/* ----------------------------- 凭证 ----------------------------- */

function renderCredBar() {
  const bar = $("#credBar");
  const text = $("#credText");
  const clearBtn = $("#btnClearCred");
  const useSaved = $("#useSaved");

  if (state.cred.saved) {
    bar.classList.remove("is-empty");
    text.innerHTML = `已保存凭证 <b>${escapeHtml(state.cred.masked)}</b>` +
      (state.cred.updated_at ? ` <span class="muted">· ${escapeHtml(state.cred.updated_at)}</span>` : "");
    clearBtn.classList.remove("hidden");
    useSaved.checked = true;
    useSaved.disabled = false;
    setCredInputsDisabled(true);
  } else {
    bar.classList.add("is-empty");
    text.textContent = "尚未保存凭证，请在下方填写";
    clearBtn.classList.add("hidden");
    useSaved.checked = false;
    useSaved.disabled = true;
    setCredInputsDisabled(false);
  }
  updateSteps();
}

function setCredInputsDisabled(disabled) {
  ["#akId", "#akSecret"].forEach((sel) => {
    const el = $(sel);
    el.disabled = disabled;
    el.style.opacity = disabled ? "0.45" : "1";
  });
  $("#remember").disabled = disabled;
}

async function loadCredential() {
  try {
    state.cred = await api("/api/deploy/credential");
  } catch (err) {
    state.cred = { saved: false, masked: "", updated_at: "" };
  }
  renderCredBar();
}

async function saveCredentialIfNeeded() {
  const remember = $("#remember");
  if (remember.disabled || !remember.checked) return;
  const ak = $("#akId").value.trim();
  const sk = $("#akSecret").value.trim();
  if (!ak || !sk) return;
  const data = await api("/api/deploy/credential", {
    method: "POST",
    body: JSON.stringify({ access_key_id: ak, access_key_secret: sk }),
  });
  state.cred = data;
  renderCredBar();
}

async function clearCredential() {
  try {
    const data = await api("/api/deploy/credential/clear", { method: "POST", body: "{}" });
    state.cred = data;
    renderCredBar();
    toast("已清除本机保存的凭证", "ok");
  } catch (err) {
    toast(err.message, "error", "清除失败");
  }
}

/* ----------------------------- 验证与探测 ----------------------------- */

function currentCredentialPayload() {
  const useSaved = $("#useSaved").checked && state.cred.saved;
  const payload = { region: $("#region").value, use_saved: useSaved };
  if (!useSaved) {
    payload.access_key_id = $("#akId").value.trim();
    payload.access_key_secret = $("#akSecret").value.trim();
  }
  return payload;
}

async function probe() {
  const btn = $("#btnProbe");
  const errBox = $("#probeError");
  const box = $("#probeBox");

  const payload = currentCredentialPayload();
  if (!payload.use_saved && (!payload.access_key_id || !payload.access_key_secret)) {
    toast("请先填写 AccessKey ID 与 Secret", "error", "缺少凭证");
    return;
  }

  btn.disabled = true;
  btn.textContent = "正在验证…";
  errBox.classList.add("hidden");
  box.classList.add("hidden");

  try {
    const data = await api("/api/deploy/probe", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    box.classList.remove("hidden");
    const listeners = data.listeners || [];
    const httpsCount = listeners.filter((l) => (l.protocol || "").toUpperCase() === "HTTPS").length;

    $("#probeOk").innerHTML =
      `<b>凭证有效。</b>地域 ${escapeHtml($("#region").value)} 下共 ${listeners.length} 个监听，其中 HTTPS ${httpsCount} 个。`;

    const warnBox = $("#probeWarn");
    if (data.cas_error) {
      warnBox.classList.remove("hidden");
      warnBox.innerHTML = `<b>证书服务（CAS）读取受限：</b>${escapeHtml(data.cas_error)}<br>` +
        `不影响部署尝试，但若上传时报权限错误，请检查 RAM 是否已授予 <code>cas:UploadUserCertificate</code>。`;
    } else if (typeof data.cas_total === "number") {
      warnBox.classList.remove("hidden");
      warnBox.innerHTML = `证书服务可读，账号下已有 ${data.cas_total} 张上传证书。`;
    } else {
      warnBox.classList.add("hidden");
    }

    const list = $("#listenerList");
    if (!listeners.length) {
      list.innerHTML = `<p class="muted small">该地域没有查询到监听。请确认地域是否选对，或 ALB 是否已创建 HTTPS 监听。</p>`;
    } else {
      list.innerHTML = listeners.map((l) => {
        const proto = (l.protocol || "").toUpperCase();
        const isHttps = proto === "HTTPS";
        return `<div class="listener-item" data-lsr="${escapeHtml(l.listener_id)}">` +
          `<span class="lsr-id">${escapeHtml(l.listener_id)}</span>` +
          `<span class="lsr-meta">${escapeHtml(proto || "-")}:${escapeHtml(l.port == null ? "-" : l.port)}` +
          (l.description ? ` · ${escapeHtml(l.description)}` : "") + `</span>` +
          (isHttps ? `<span class="lsr-pick">填入</span>` : `<span class="lsr-pick muted">非 HTTPS</span>`) +
          `</div>`;
      }).join("");
    }
  } catch (err) {
    errBox.classList.remove("hidden");
    errBox.innerHTML = `<b>验证失败：</b>${escapeHtml(err.message)}`;
    toast(err.message, "error", "凭证验证失败");
  } finally {
    btn.disabled = false;
    btn.textContent = "验证凭证并读取监听";
    updateSteps();
  }
}

function fillListener(id) {
  const input = $("#listeners");
  const parts = input.value.split(/[,;\s]+/).map((s) => s.trim()).filter(Boolean);
  if (parts.includes(id)) {
    toast("该监听已在列表中", "info");
    return;
  }
  parts.push(id);
  input.value = parts.join(", ");
  updateSteps();
  toast(`已填入 ${id}`, "ok");
}

/* ----------------------------- 部署 ----------------------------- */

async function run() {
  if (state.running) return;

  const cert = state.current;
  if (!cert || !cert.usable) {
    toast("请先选择一张可用证书", "error");
    return;
  }
  const listeners = $("#listeners").value.split(/[,;\s]+/).map((s) => s.trim()).filter(Boolean);
  if (!listeners.length) {
    toast("请填写监听 ID", "error");
    return;
  }

  const verifyHost = $("#verifyHost").value.trim();
  if (verifyHost && !sanCovers(verifyHost, cert.san)) {
    toast(`证书不覆盖 ${verifyHost}。纯泛域名不包含裸域名，请填写一级子域。`, "error", "校验域名无效");
    return;
  }

  const dryRun = $("#dryRun").checked;
  if (!dryRun) {
    const ok = window.confirm(
      `即将把证书 ${cert.cn} 上传到阿里云，并替换以下监听的证书：\n\n${listeners.join("\n")}\n\n` +
      `此操作会立即改变线上 HTTPS 使用的证书。确认继续？`
    );
    if (!ok) return;
  }

  const btn = $("#btnRun");
  const payload = Object.assign(currentCredentialPayload(), {
    listeners: listeners.join(","),
    role: document.querySelector('input[name="role"]:checked').value,
    cert_dir: cert.path,
    verify_host: verifyHost,
    dry_run: dryRun,
    force_upload: $("#forceUpload").checked,
    prune_old_cert: $("#pruneOldCert").checked,
    prune_additional: $("#pruneAdditional").checked,
    verbose: $("#verbose").checked,
  });

  state.running = true;
  btn.disabled = true;
  btn.textContent = "正在部署…";
  $("#runResult").classList.add("hidden");
  $("#envBadge").textContent = dryRun ? "预演中" : "部署中";
  setLogOpen(true);
  renderLogs([]);
  updateSteps();

  try {
    if (!payload.use_saved) {
      await saveCredentialIfNeeded();
    }
    const job = await api("/api/deploy/run", { method: "POST", body: JSON.stringify(payload) });
    state.jobId = job.id;
    renderLogs(job.logs || []);
    pollJob(job.id);
  } catch (err) {
    state.running = false;
    btn.disabled = false;
    btn.innerHTML = `开始部署`;
    $("#envBadge").textContent = "先预演，再执行";
    updateSteps();
    toast(err.message, "error", "启动失败");
  }
}

function pollJob(jobId) {
  if (state.polling) return;
  state.polling = true;

  const tick = async () => {
    try {
      const job = await api(`/api/deploy/runs/${jobId}`);
      renderLogs(job.logs || []);
      if (job.running) {
        setTimeout(tick, 900);
        return;
      }
      finishJob(job);
    } catch (err) {
      state.polling = false;
      state.running = false;
      toast(err.message, "error", "获取任务状态失败");
      resetRunButton();
    }
  };

  setTimeout(tick, 600);
}

function resetRunButton() {
  const btn = $("#btnRun");
  btn.disabled = false;
  btn.innerHTML = `开始部署
    <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>`;
  $("#envBadge").textContent = "先预演，再执行";
  updateSteps();
}

function finishJob(job) {
  state.polling = false;
  state.running = false;
  resetRunButton();

  const ok = job.exit_code === 0;
  const dryRun = (job.params && job.params.dry_run) || $("#dryRun").checked;
  const box = $("#runResult");
  box.classList.remove("hidden");

  let title, detail;
  if (ok && dryRun) {
    title = "预演完成，未产生任何变更";
    detail = "确认上面的日志符合预期后，取消勾选「预演模式」再次执行，才会真正上传并替换。";
  } else if (ok) {
    title = "部署完成";
    detail = `证书 ${job.params.cert_name} 已生效，耗时 ${job.elapsed} 秒。建议用浏览器访问一次确认证书正确。`;
  } else {
    title = `部署未完成：${job.exit_hint || "未知错误"}`;
    detail = "请看下方日志中最后一条红色记录，那里是具体原因。";
  }

  box.innerHTML = `<div class="result-bar ${ok ? "is-ok" : "is-bad"}">
      <b>${escapeHtml(title)}</b>
      <span class="muted small">${escapeHtml(detail)}</span>
    </div>`;

  setLogOpen(true);
  toast(ok ? (dryRun ? "预演完成，未改动线上" : "证书已部署") : title,
    ok ? "ok" : "error", ok ? "" : "部署失败");
}

/* ----------------------------- 事件绑定 ----------------------------- */

function bind() {
  $("#certSelect").addEventListener("change", (e) => {
    $("#verifyHost").value = "";
    selectCert(e.target.value);
  });

  $("#useSaved").addEventListener("change", (e) => {
    setCredInputsDisabled(e.target.checked && state.cred.saved);
    updateSteps();
  });

  ["#akId", "#akSecret"].forEach((sel) => {
    $(sel).addEventListener("input", updateSteps);
  });

  $("#listeners").addEventListener("input", updateSteps);
  $("#verifyHost").addEventListener("input", () => {
    const host = $("#verifyHost").value.trim();
    const c = state.current;
    const el = $("#verifyHost");
    if (host && c && c.usable && !sanCovers(host, c.san)) {
      el.style.borderColor = "var(--danger)";
    } else {
      el.style.borderColor = "";
    }
  });

  $("#btnProbe").addEventListener("click", probe);
  $("#btnClearCred").addEventListener("click", clearCredential);
  $("#btnRun").addEventListener("click", run);

  function syncMode() {
    const dry = $("#dryRun").checked;
    $("#runHint").textContent = dry
      ? "预演模式下不会产生变更"
      : "将真实上传证书并替换监听证书";
    $("#runHint").style.color = dry ? "" : "var(--danger)";
    $("#envBadge").textContent = dry ? "先预演，再执行" : "执行模式";
    $("#modeDesc").textContent = dry
      ? "只查询监听现状并打印将要执行的动作，不上传、不替换。建议第一次先跑这个。"
      : "关闭后点「开始部署」会真实上传证书并替换监听证书，改动立即对线上生效。";
    $("#modeCard").classList.toggle("is-live", !dry);
  }

  $("#dryRun").addEventListener("change", syncMode);
  syncMode();

  $("#listenerList").addEventListener("click", (e) => {
    const item = e.target.closest(".listener-item");
    if (!item) return;
    const id = item.getAttribute("data-lsr");
    const pick = item.querySelector(".lsr-pick");
    if (pick && pick.classList.contains("muted")) return;
    fillListener(id);
  });

  $("#logToggle").addEventListener("click", () => setLogOpen(!logOpen));

  $("#region").addEventListener("change", (e) => {
    localStorage.setItem(REGION_KEY, e.target.value);
    $("#probeBox").classList.add("hidden");
  });
}

async function init() {
  const savedRegion = localStorage.getItem(REGION_KEY);
  if (savedRegion) $("#region").value = savedRegion;

  bind();
  setLogOpen(false);
  await loadCredential();
  await loadCerts();
  updateSteps();
}

init();

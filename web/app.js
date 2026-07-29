const $ = (selector, root = document) => root.querySelector(selector);
const ADMIN_SESSION_STORAGE = "admin-session";
const savedAdminSession = (() => {
  try {
    const session = JSON.parse(localStorage.getItem(ADMIN_SESSION_STORAGE) || "null");
    if (session?.username && Number(session.expiresAt) * 1000 > Date.now()) return session;
  } catch {
    // Invalid or unavailable storage falls back to the login screen.
  }
  localStorage.removeItem(ADMIN_SESSION_STORAGE);
  return null;
})();
const state = {
  config: null,
  username: savedAdminSession?.username || "",
  password: "",
  sessionExpiresAt: Number(savedAdminSession?.expiresAt) || 0,
  timer: null,
  adminUsers: [],
  trafficSamples: new Map(),
  trafficHistory: [],
  networkCapabilities: null,
  shareShortLinks: new Map(),
  shareShortLinkErrors: new Map(),
  shareShortLinksPending: new Set(),
  shareRulePreset: "balanced",
  shareAdBlock: false,
  converter: {
    source: localStorage.getItem("sublink-source") || "",
    rulePreset: localStorage.getItem("sublink-rule-preset") || "balanced",
    adBlock: localStorage.getItem("sublink-adblock") === "true",
    whitelist: localStorage.getItem("sublink-whitelist") || "",
    blacklist: localStorage.getItem("sublink-blacklist") || "",
    links: null,
    busy: false
  }
};

const PAGE_TITLES = {
  overview: "概览",
  service: "服务配置",
  users: "用户与链接",
  admin: "管理账户",
  converter: "订阅转换"
};
const PAGE_ALIASES = { overview: "overview", network: "service", transport: "service", masquerade: "service", service: "service", users: "users", links: "users", admin: "admin", "admin-users": "admin", converter: "converter" };

function basicAuthorization(username, password) {
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  let binary = "";
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return `Basic ${btoa(binary)}`;
}

function authHeaders(json = false) {
  const headers = {};
  if (state.username && state.password) headers.Authorization = basicAuthorization(state.username, state.password);
  if (json) headers["Content-Type"] = "application/json";
  return headers;
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { ...authHeaders(Boolean(options.body)), ...(options.headers || {}) } });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    const message = state.password ? "用户名或密码错误" : "";
    clearAdminSession();
    openLoginScreen(message);
    throw new Error("需要登录");
  }
  if (!response.ok) throw new Error(payload.error || `请求失败 (${response.status})`);
  return payload;
}

function saveAdminSession(username, expiresAt) {
  state.username = username;
  state.password = "";
  state.sessionExpiresAt = expiresAt;
  localStorage.setItem(ADMIN_SESSION_STORAGE, JSON.stringify({ username, expiresAt }));
}

function clearAdminSession() {
  state.username = "";
  state.password = "";
  state.sessionExpiresAt = 0;
  localStorage.removeItem(ADMIN_SESSION_STORAGE);
}

async function createAdminSession(username, password) {
  const response = await fetch("/api/v1/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || "用户名或密码错误");
  saveAdminSession(payload.username, payload.expires_at);
}

function openLoginScreen(message = "") {
  const alreadyVisible = loginScreenVisible();
  stopStatusPolling();
  document.body.classList.add("auth-pending");
  $("#login-screen").classList.remove("hidden");
  document.body.classList.remove("auth-booting");
  if (message || !alreadyVisible) {
    $("#login-error").textContent = message;
    $("#login-error").classList.toggle("hidden", !message);
  }
  if (!alreadyVisible) {
    $("#login-username").value = "";
    $("#login-password").value = "";
    $("#login-username").focus();
  }
}

function closeLoginScreen() {
  $("#login-screen").classList.add("hidden");
  document.body.classList.remove("auth-pending", "auth-booting");
}

function loginScreenVisible() {
  return document.body.classList.contains("auth-pending")
    && !document.body.classList.contains("auth-booting");
}

function startStatusPolling() {
  if (state.timer !== null) return;
  state.timer = setInterval(loadStatus, 5000);
}

function stopStatusPolling() {
  if (state.timer === null) return;
  clearInterval(state.timer);
  state.timer = null;
}

function pageFromHash() {
  return PAGE_ALIASES[window.location.hash.slice(1)] || "overview";
}

function activatePage(page, updateHash = true) {
  const activePage = PAGE_TITLES[page] ? page : "overview";
  document.querySelectorAll(".page-panel").forEach(panel => {
    panel.classList.toggle("active", panel.dataset.page === activePage);
  });
  document.querySelectorAll("nav a[data-page]").forEach(link => {
    link.classList.toggle("active", link.dataset.page === activePage);
  });
  $("#page-title").textContent = PAGE_TITLES[activePage];
  $("#save").classList.toggle("hidden", !["service", "users"].includes(activePage));
  if (updateHash && window.location.hash !== `#${activePage}`) history.replaceState(null, "", `#${activePage}`);
  if (activePage === "overview") requestAnimationFrame(drawTrafficChart);
}

function toast(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.classList.add("show");
  clearTimeout(node._timer);
  node._timer = setTimeout(() => node.classList.remove("show"), 3200);
}

async function copyText(value) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }
  } catch {
    // HTTP pages may reject the modern clipboard API; use the selection fallback below.
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("clipboard unavailable");
}

function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}天 ${hours}小时`;
  if (hours) return `${hours}小时 ${minutes}分`;
  if (minutes) return `${minutes}分 ${seconds % 60}秒`;
  return `${seconds}秒`;
}

function formatBytes(value) {
  let amount = Math.max(0, Number(value) || 0);
  if (amount < 1024) return `${Math.round(amount)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let unit = 0;
  amount /= 1024;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  const digits = amount >= 100 ? 0 : amount >= 10 ? 1 : 2;
  return `${amount.toFixed(digits)} ${units[unit]}`;
}

function drawTrafficChart() {
  const canvas = $("#traffic-chart-canvas");
  const bounds = canvas.getBoundingClientRect();
  if (bounds.width < 1 || bounds.height < 1) return;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const width = Math.round(bounds.width);
  const height = Math.round(bounds.height);
  const pixelWidth = Math.round(width * ratio);
  const pixelHeight = Math.round(height * ratio);
  if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
    canvas.width = pixelWidth;
    canvas.height = pixelHeight;
  }
  const context = canvas.getContext("2d");
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);

  const styles = getComputedStyle(document.documentElement);
  const gridColor = styles.getPropertyValue("--line").trim();
  const textColor = styles.getPropertyValue("--subtle").trim();
  const uploadColor = styles.getPropertyValue("--status").trim();
  const downloadColor = styles.getPropertyValue("--red").trim();
  const plot = { left: 48, right: width - 8, top: 8, bottom: height - 8 };
  const plotWidth = Math.max(plot.right - plot.left, 1);
  const plotHeight = Math.max(plot.bottom - plot.top, 1);
  const peak = Math.max(
    1024,
    ...state.trafficHistory.flatMap(sample => [sample.upload, sample.download])
  );
  const maximum = peak * 1.12;

  context.lineWidth = 1;
  context.font = '9px Inter, ui-sans-serif, system-ui, sans-serif';
  context.textAlign = "right";
  context.textBaseline = "middle";
  for (let index = 0; index <= 3; index += 1) {
    const y = plot.top + (plotHeight * index) / 3;
    const value = maximum * (1 - index / 3);
    context.strokeStyle = gridColor;
    context.beginPath();
    context.moveTo(plot.left, y);
    context.lineTo(plot.right, y);
    context.stroke();
    context.fillStyle = textColor;
    context.fillText(`${formatBytes(value)}/s`, plot.left - 6, y);
  }

  const now = Date.now();
  const windowStart = now - 5 * 60 * 1000;
  const drawLine = (key, color) => {
    context.strokeStyle = color;
    context.lineWidth = 1.8;
    context.lineJoin = "round";
    context.lineCap = "round";
    context.beginPath();
    state.trafficHistory.forEach((sample, index) => {
      const x = plot.left + Math.max(0, Math.min(1, (sample.at - windowStart) / (now - windowStart))) * plotWidth;
      const y = plot.bottom - Math.min(sample[key] / maximum, 1) * plotHeight;
      if (index === 0) context.moveTo(x, y);
      else context.lineTo(x, y);
    });
    context.stroke();
    const latest = state.trafficHistory[state.trafficHistory.length - 1];
    if (latest) {
      const x = plot.left + Math.max(0, Math.min(1, (latest.at - windowStart) / (now - windowStart))) * plotWidth;
      const y = plot.bottom - Math.min(latest[key] / maximum, 1) * plotHeight;
      context.fillStyle = color;
      context.beginPath();
      context.arc(x, y, 2.5, 0, Math.PI * 2);
      context.fill();
    }
  };
  drawLine("upload", uploadColor);
  drawLine("download", downloadColor);
}

function updateTrafficChart(upload, download, now) {
  state.trafficHistory.push({ upload, download, at: now });
  const cutoff = now - 5 * 60 * 1000;
  state.trafficHistory = state.trafficHistory
    .filter(sample => sample.at >= cutoff)
    .slice(-61);
  $("#traffic-upload-rate").textContent = `${formatBytes(upload)}/s`;
  $("#traffic-download-rate").textContent = `${formatBytes(download)}/s`;
  drawTrafficChart();
}

function renderTraffic(users) {
  const target = $("#traffic-list");
  const now = Date.now();
  const nextSamples = new Map();
  if (!users.length) {
    target.innerHTML = '<div class="empty traffic-empty">暂无认证用户</div>';
    state.trafficSamples = nextSamples;
    updateTrafficChart(0, 0, now);
    return;
  }
  let totalUploadRate = 0;
  let totalDownloadRate = 0;
  target.innerHTML = users.map(user => {
    const uploaded = Number(user.uploaded_bytes) || 0;
    const downloaded = Number(user.downloaded_bytes) || 0;
    const previous = state.trafficSamples.get(user.username);
    const elapsed = previous ? Math.max((now - previous.at) / 1000, 0.001) : 0;
    const uploadRate = previous && uploaded >= previous.uploaded
      ? (uploaded - previous.uploaded) / elapsed
      : 0;
    const downloadRate = previous && downloaded >= previous.downloaded
      ? (downloaded - previous.downloaded) / elapsed
      : 0;
    const active = Number(user.active_connections) || 0;
    totalUploadRate += uploadRate;
    totalDownloadRate += downloadRate;
    nextSamples.set(user.username, { uploaded, downloaded, at: now });
    return `
      <div class="traffic-row">
        <div class="traffic-user">
          <strong>${escapeHtml(user.username)}</strong>
          <span class="${active ? "active" : ""}">${active ? `${active} 个活动连接` : "无活动连接"}</span>
        </div>
        <div class="traffic-value">
          <strong>${formatBytes(uploaded)}</strong>
          <span>${formatBytes(uploadRate)}/s</span>
        </div>
        <div class="traffic-value">
          <strong>${formatBytes(downloaded)}</strong>
          <span>${formatBytes(downloadRate)}/s</span>
        </div>
      </div>
    `;
  }).join("");
  state.trafficSamples = nextSamples;
  updateTrafficChart(totalUploadRate, totalDownloadRate, now);
}

function listenAddressPair(value) {
  const address = String(value || "");
  const port = address.match(/^\[::\]:(\d+)$/);
  if (port) return { ipv4: `0.0.0.0:${port[1]}`, ipv6: address };
  if (address === "[::]") return { ipv4: "0.0.0.0", ipv6: address };
  const ipv4Port = address.match(/^0\.0\.0\.0:(\d+)$/);
  if (ipv4Port) return { ipv4: address, ipv6: `[::]:${ipv4Port[1]}` };
  return { ipv4: address || "--", ipv6: "--" };
}

function setShareAddress(selector, value) {
  const target = $(selector);
  target.value = String(value || "").trim();
}

function networkScopeLabel(scope) {
  return { public: "公网", private: "私网", local: "本地", unavailable: "未检测到" }[scope] || "未知";
}

function renderNetworkCapabilities(capabilities) {
  state.networkCapabilities = capabilities;
  const ipv4Address = capabilities.ipv4_address || "";
  const ipv6Address = capabilities.ipv6_address || "";
  $("#ipv4-outbound-status").textContent = capabilities.ipv4_outbound
    ? `可用 · ${networkScopeLabel(capabilities.ipv4_scope)}${ipv4Address ? ` ${ipv4Address}` : ""}`
    : "不可用";
  $("#ipv6-outbound-status").textContent = capabilities.ipv6_outbound
    ? `可用 · ${networkScopeLabel(capabilities.ipv6_scope)}${ipv6Address ? ` ${ipv6Address}` : ""}`
    : "不可用";
  const message = $("#network-capability-message");
  message.textContent = capabilities.message;
  message.classList.toggle("warning", !capabilities.ipv4_outbound);
  $("#outbound-mode option[value='ipv4_only']").disabled = !capabilities.ipv4_outbound;
  $("#outbound-mode option[value='ipv6_only']").disabled = !capabilities.ipv6_outbound;
}

async function loadNetworkCapabilities() {
  try {
    renderNetworkCapabilities(await api("/api/v1/network-capabilities"));
  } catch (error) {
    $("#ipv4-outbound-status").textContent = "检测失败";
    $("#ipv6-outbound-status").textContent = "检测失败";
    $("#network-capability-message").textContent = error.message;
    $("#network-capability-message").classList.add("warning");
  }
}

async function loadStatus() {
  try {
    const status = await api("/api/v1/status");
    $("#version").textContent = `v${status.version}`;
    const service = $("#service-state");
    service.className = `service-state ${status.running ? "online" : "offline"}`;
    service.lastElementChild.textContent = status.running ? "运行中" : "已停止";
    const listen = listenAddressPair(status.listen);
    $("#metric-ipv4-listen").textContent = listen.ipv4;
    $("#metric-ipv6-listen").textContent = listen.ipv6;
    $("#metric-service-listen").textContent = status.service_address || status.listen || "--";
    $("#metric-webui-listen").textContent = status.webui_listen || "--";
    $("#metric-users").textContent = String(status.users);
    $("#metric-uptime").textContent = formatUptime(status.uptime_secs);
    renderTraffic(status.traffic || []);
    $("#flag-udp").textContent = `UDP ${status.udp_enabled ? "ON" : "OFF"}`;
    $("#flag-obfs").textContent = `Salamander ${status.obfs ? "ON" : "OFF"}`;
    $("#flag-generation").textContent = `Generation ${status.generation}`;
    $("#updated-at").textContent = `同步于 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`;
    $("#runtime-error").textContent = status.last_error || "";
    $("#runtime-error").classList.toggle("hidden", !status.last_error);
  } catch (error) {
    if (!loginScreenVisible()) toast(error.message, true);
  }
}

async function loadConfig() {
  const config = await api("/api/v1/config");
  state.config = config;
  $("#listen-port").value = listenPort(config.listen) ?? 443;
  $("#certificate").value = config.tls?.certificate || "";
  $("#private-key").value = config.tls?.private_key || "";
  setShareAddress("#share-ipv4-server", config.share?.server);
  setShareAddress("#share-ipv6-server", config.share?.ipv6_server);
  $("#share-port").value = config.share?.port ?? listenPort(config.listen) ?? 443;
  $("#share-sni").value = config.share?.sni || "";
  $("#share-insecure").checked = Boolean(config.share?.insecure);
  state.shareRulePreset = config.share?.rule_preset || "balanced";
  state.shareAdBlock = Boolean(config.share?.ad_block);
  $("#share-whitelist").value = (config.share?.whitelist || []).join("\n");
  $("#share-blacklist").value = (config.share?.blacklist || []).join("\n");
  $("#up-mbps").value = config.bandwidth?.up_mbps ?? 0;
  $("#down-mbps").value = config.bandwidth?.down_mbps ?? 0;
  $("#ignore-bandwidth").checked = Boolean(config.bandwidth?.ignore_client_bandwidth);
  $("#udp-enabled").checked = config.udp?.enabled !== false;
  $("#udp-timeout").value = config.udp?.timeout_secs ?? 300;
  $("#outbound-mode").value = config.outbound?.mode || "prefer_ipv4";
  $("#obfs-enabled").checked = Boolean(config.obfs);
  $("#obfs-password").value = config.obfs?.password || "";
  toggleObfs();
  renderUsers(config.users || []);
  const type = config.masquerade?.type || "none";
  $("#masquerade-type").value = type;
  renderMasquerade(type, config.masquerade);
  renderShareRuleOptions();
  await generateShareShortLinks();
}

async function loadAdminUsers() {
  const response = await api("/api/v1/admin-users");
  state.adminUsers = response.users || [];
  renderAdminUsers();
}

function renderStartup(status) {
  const manager = { openrc: "OpenRC", systemd: "systemd", unsupported: "不支持" }[status.manager] || status.manager || "--";
  let summary = "未安装";
  if (!status.supported) summary = "不支持";
  else if (status.enabled) summary = "已启用";
  else if (status.installed) summary = "已安装，未启用";
  $("#startup-summary").textContent = summary;
  $("#startup-manager").textContent = manager;
  $("#startup-enabled").textContent = status.enabled ? "已启用" : "未启用";
  $("#startup-service-path").textContent = status.service_path || "--";
  $("#startup-executable-path").textContent = status.executable_path || "--";
  $("#startup-config-path").textContent = status.config_path || "--";
  const button = $("#startup-action");
  button.disabled = !status.supported;
  button.dataset.installed = String(status.installed);
  button.className = `button compact ${status.installed ? "danger" : "secondary"}`;
  button.textContent = status.installed ? "卸载启动项" : "安装启动项";
}

async function loadStartup() {
  try {
    renderStartup(await api("/api/v1/startup"));
  } catch (error) {
    $("#startup-summary").textContent = "检测失败";
    $("#startup-action").disabled = true;
  }
}

async function manageStartup() {
  const button = $("#startup-action");
  const uninstalling = button.dataset.installed === "true";
  button.disabled = true;
  try {
    const status = await api("/api/v1/startup", { method: uninstalling ? "DELETE" : "POST" });
    renderStartup(status);
    toast(uninstalling ? "启动项已卸载，当前服务继续运行" : "启动项已安装并启用");
  } catch (error) {
    toast(error.message, true);
  } finally {
    if ($("#startup-summary").textContent !== "不支持") button.disabled = false;
  }
}

function renderAdminUsers() {
  const target = $("#admin-user-list");
  $("#admin-user-count").textContent = `${state.adminUsers.length} 个账户`;
  if (!state.adminUsers.length) {
    target.innerHTML = '<div class="empty">没有管理账户</div>';
    return;
  }
  target.innerHTML = state.adminUsers.map(username => `
    <div class="admin-user-row" data-admin-username="${escapeHtml(username)}">
      <div class="admin-user-name"><strong>${escapeHtml(username)}</strong>${username === state.username ? '<span class="current-user">当前</span>' : ""}</div>
      <label class="field"><span>新密码</span><input data-admin-password type="password" autocomplete="new-password" maxlength="256" placeholder="输入后修改"></label>
      <button class="button secondary compact" data-change-admin-password type="button">修改密码</button>
      <button class="button danger compact" data-delete-admin-user type="button">删除</button>
    </div>`).join("");
  target.querySelectorAll("[data-change-admin-password]").forEach(button => button.addEventListener("click", changeAdminPassword));
  target.querySelectorAll("[data-delete-admin-user]").forEach(button => button.addEventListener("click", deleteAdminUser));
}

async function changeAdminPassword(event) {
  const row = event.currentTarget.closest("[data-admin-username]");
  const username = row.dataset.adminUsername;
  const input = $("[data-admin-password]", row);
  const password = input.value;
  if (!password) {
    toast("请输入新密码", true);
    input.focus();
    return;
  }
  event.currentTarget.disabled = true;
  try {
    await api(`/api/v1/admin-users/${encodeURIComponent(username)}`, {
      method: "PUT",
      body: JSON.stringify({ password })
    });
    if (username === state.username) state.password = password;
    input.value = "";
    toast("管理密码已修改");
  } catch (error) {
    toast(error.message, true);
  } finally {
    event.currentTarget.disabled = false;
  }
}

async function deleteAdminUser(event) {
  const row = event.currentTarget.closest("[data-admin-username]");
  const username = row.dataset.adminUsername;
  if (!window.confirm(`删除管理账户 ${username}？`)) return;
  event.currentTarget.disabled = true;
  try {
    await api(`/api/v1/admin-users/${encodeURIComponent(username)}`, { method: "DELETE" });
    if (username === state.username) {
      state.password = "";
      openLoginScreen("当前账户已删除，请使用其他账户登录");
    } else {
      await loadAdminUsers();
      toast("管理账户已删除");
    }
  } catch (error) {
    toast(error.message, true);
    event.currentTarget.disabled = false;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}

function renderUsers(users) {
  const list = $("#user-list");
  if (!users.length) {
    list.innerHTML = '<div class="empty">没有认证用户</div>';
    renderShareLinks();
    return;
  }
  list.innerHTML = users.map((user, index) => `
    <div class="user-row" data-user-row>
      <label class="field"><span class="user-index">USER ${String(index + 1).padStart(2, "0")}</span><input data-user-name required value="${escapeHtml(user.name || "")}" placeholder="用户名"></label>
      <label class="field"><span>密码</span><input data-user-password required type="password" value="${escapeHtml(user.password || "")}" placeholder="HY2 密码"></label>
      <div class="user-row-actions">
        <button class="button secondary compact" data-generate-user-password type="button">随机密码</button>
        <button class="button danger compact" data-remove-user type="button">移除</button>
      </div>
    </div>`).join("");
  list.querySelectorAll("[data-generate-user-password]").forEach(button => button.addEventListener("click", generateUserPassword));
  list.querySelectorAll("[data-remove-user]").forEach(button => button.addEventListener("click", () => {
    button.closest("[data-user-row]").remove();
    renumberUsers();
  }));
  applyPasswordVisibility();
  renderShareLinks();
}

function generateUserPassword(event) {
  if (!globalThis.crypto?.getRandomValues) {
    toast("当前浏览器不支持安全随机密码生成", true);
    return;
  }
  const bytes = new Uint8Array(24);
  globalThis.crypto.getRandomValues(bytes);
  const password = [...bytes].map(byte => byte.toString(16).padStart(2, "0")).join("");
  const input = $("[data-user-password]", event.currentTarget.closest("[data-user-row]"));
  input.value = password;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  toast("已生成随机密码，保存后生效");
}

function renumberUsers() {
  $("#user-list").querySelectorAll("[data-user-row]").forEach((row, index) => {
    $(".user-index", row).textContent = `USER ${String(index + 1).padStart(2, "0")}`;
  });
  if (!$("#user-list").querySelector("[data-user-row]")) renderUsers([]);
}

function addUser() {
  const users = collectUsers(false);
  users.push({ name: "", password: "" });
  renderUsers(users);
  const rows = $("#user-list").querySelectorAll("[data-user-row]");
  rows[rows.length - 1].querySelector("input").focus();
}

function collectUsers(requireValues = true) {
  return [...$("#user-list").querySelectorAll("[data-user-row]")].map(row => {
    const user = { name: $("[data-user-name]", row).value.trim(), password: $("[data-user-password]", row).value };
    if (requireValues && (!user.name || !user.password)) throw new Error("用户名和密码不能为空");
    return user;
  });
}

function listenPort(listen) {
  const match = String(listen || "").match(/:(\d+)$/);
  return match ? Number(match[1]) : null;
}

function encodeUserInfo(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function shareHost(value) {
  const host = value.trim();
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function buildShareLink(user, server) {
  const port = Number($("#share-port").value);
  if (!server || !port || !user.password) return "";
  const query = new URLSearchParams();
  const sni = $("#share-sni").value.trim();
  if (sni) query.set("sni", sni);
  if ($("#share-insecure").checked) query.set("insecure", "1");
  if ($("#obfs-enabled").checked) {
    query.set("obfs", "salamander");
    query.set("obfs-password", $("#obfs-password").value);
  }
  const parameters = query.toString();
  const fragment = user.name ? `#${encodeURIComponent(user.name)}` : "";
  return `hysteria2://${encodeUserInfo(user.password)}@${shareHost(server)}:${port}/?${parameters}${fragment}`;
}

function currentShareLinks() {
  const servers = [
    { family: "IPv4", server: $("#share-ipv4-server").value.trim() },
    { family: "IPv6", server: $("#share-ipv6-server").value.trim() }
  ].filter(item => item.server);
  return collectUsers(false).flatMap(user => servers.map(({ family, server }) => ({
    user,
    family,
    link: buildShareLink(user, server)
  }))).filter(item => item.link);
}

function renderShareRuleOptions() {
  $("#share-rule-preset").value = state.shareRulePreset;
  $("#share-adblock").checked = state.shareAdBlock || state.shareRulePreset === "comprehensive";
  $("#share-adblock").disabled = state.shareRulePreset === "comprehensive";
}

function renderShareLinks() {
  const target = $("#share-links");
  if (!target) return;
  const links = currentShareLinks();
  $("#link-count").textContent = `${links.length} 个链接`;
  if (!$("#share-ipv4-server").value.trim() && !$("#share-ipv6-server").value.trim()) {
    target.innerHTML = '<div class="empty">未检测到可用于客户端链接的 IPv4 或 IPv6 地址</div>';
    return;
  }
  if (!links.length) {
    target.innerHTML = '<div class="empty">没有可生成链接的认证用户</div>';
    return;
  }
  target.innerHTML = links.map((item, index) => `
    <article class="share-link-card">
      <header class="share-link-user"><strong>${escapeHtml(item.user.name || "未命名用户")}</strong></header>
      <div class="share-protocol">
        <div class="share-protocol-name">HY2</div>
        <div class="share-link-fields">
          <div class="share-link-line">
            <span>${item.family} 连接</span>
            <input aria-label="${escapeHtml(item.user.name || "用户")} HY2 ${item.family} 连接" readonly value="${escapeHtml(item.link)}">
            <button class="button secondary compact" data-copy-link="${index}" data-link-kind="source" type="button">复制</button>
          </div>
          <div class="share-link-line">
            <span>${item.family} 订阅</span>
            <input aria-label="${escapeHtml(item.user.name || "用户")} HY2 ${item.family} 订阅" readonly
              value="${escapeHtml(state.shareShortLinks.get(item.link) || "")}"
              placeholder="${state.shareShortLinksPending.has(item.link) ? "正在生成" : escapeHtml(state.shareShortLinkErrors.get(item.link) || "保存后生成")}">
            <button class="button secondary compact" data-copy-link="${index}" data-link-kind="short" type="button" ${state.shareShortLinks.has(item.link) ? "" : "disabled"}>复制</button>
          </div>
        </div>
      </div>
    </article>`).join("");
  target.querySelectorAll("[data-copy-link]").forEach(button => button.addEventListener("click", async () => {
    const source = links[Number(button.dataset.copyLink)].link;
    const link = button.dataset.linkKind === "short" ? state.shareShortLinks.get(source) : source;
    if (!link) return;
    try {
      await copyText(link);
      toast(button.dataset.linkKind === "short" ? "短链接已复制" : "HY2 连接已复制");
    } catch {
      toast("复制失败，请手动选择链接", true);
    }
  }));
}

async function generateShareShortLinks() {
  const missing = currentShareLinks().filter(item =>
    !state.shareShortLinks.has(item.link) && !state.shareShortLinksPending.has(item.link)
  );
  if (!missing.length) return;
  missing.forEach(item => state.shareShortLinksPending.add(item.link));
  renderShareLinks();
  await Promise.all(missing.map(async item => {
    try {
      const longUrl = new URL("/xray", window.location.origin);
      longUrl.searchParams.set("config", item.link);
      longUrl.searchParams.set("selectedRules", state.shareRulePreset);
      if (state.shareAdBlock && state.shareRulePreset !== "comprehensive") {
        longUrl.searchParams.set("adblock", "true");
      }
      const whitelist = $("#share-whitelist").value.trim();
      const blacklist = $("#share-blacklist").value.trim();
      if (whitelist) longUrl.searchParams.set("whitelist", whitelist);
      if (blacklist) longUrl.searchParams.set("blacklist", blacklist);
      const shorten = new URL("/shorten-hy2", window.location.origin);
      shorten.searchParams.set("url", longUrl.toString());
      const response = await fetch(shorten);
      if (!response.ok) throw new Error(await response.text() || "短链接生成失败");
      const code = (await response.text()).trim();
      state.shareShortLinks.set(item.link, `${window.location.origin}/sub/${encodeURIComponent(code)}`);
      state.shareShortLinkErrors.delete(item.link);
    } catch (error) {
      state.shareShortLinkErrors.set(item.link, error.message || "短链接生成失败");
    } finally {
      state.shareShortLinksPending.delete(item.link);
    }
  }));
  renderShareLinks();
}

function toggleObfs() {
  const enabled = $("#obfs-enabled").checked;
  $("#obfs-fields").classList.toggle("hidden", !enabled);
  $("#obfs-password").required = enabled;
  renderShareLinks();
}

function applyPasswordVisibility() {
  const type = $("#show-passwords").checked ? "text" : "password";
  document.querySelectorAll("[data-user-password], #obfs-password").forEach(input => { input.type = type; });
}

function renderConverter() {
  const source = state.converter.source;
  const lines = source.split(/\r?\n/).filter(line => line.trim()).length;
  const bytes = new TextEncoder().encode(source).length;
  $("#converter-stats").textContent = `${lines} 行 / ${bytes} B`;
  $("#converter-source").value = source;
  $("#converter-rule-preset").value = state.converter.rulePreset;
  $("#converter-adblock").checked = state.converter.adBlock || state.converter.rulePreset === "comprehensive";
  $("#converter-adblock").disabled = state.converter.rulePreset === "comprehensive";
  $("#converter-whitelist").value = state.converter.whitelist;
  $("#converter-blacklist").value = state.converter.blacklist;
  $("#converter-generate").disabled = state.converter.busy;
  $("#converter-generate").textContent = state.converter.busy ? "生成中" : "生成订阅";
  renderConverterResults();
}

function setConverterStatus(message = "", error = false) {
  const target = $("#converter-status");
  target.textContent = message;
  target.classList.toggle("error", error);
}

function renderConverterResults() {
  const target = $("#converter-results");
  const links = state.converter.links;
  target.classList.toggle("hidden", !links);
  if (!links) {
    target.replaceChildren();
    return;
  }
  target.innerHTML = `
    <div class="converter-result preferred">
      <strong>自动匹配</strong>
      <input aria-label="通用订阅地址" readonly value="${escapeHtml(links)}">
      <button class="button secondary compact" data-converter-copy type="button">复制</button>
      <a class="button secondary compact converter-open" href="${escapeHtml(links)}" target="_blank" rel="noreferrer">打开</a>
    </div>`;
  target.querySelectorAll("[data-converter-copy]").forEach(button => button.addEventListener("click", async () => {
    try {
      await copyText(links);
      setConverterStatus("订阅地址已复制");
    } catch {
      setConverterStatus("无法写入剪贴板", true);
    }
  }));
}

async function generateConverterLinks() {
  const source = state.converter.source.replace(/\r\n?/g, "\n").trim();
  if (!source) {
    setConverterStatus("请先输入节点或 Base64 订阅", true);
    return;
  }
  if (source.split(/\r?\n/).some(line => /^https?:\/\//i.test(line.trim()))) {
    setConverterStatus("不支持远程 HTTP(S) 订阅地址", true);
    return;
  }
  state.converter.busy = true;
  renderConverter();
  setConverterStatus();
  try {
    const longUrl = new URL("/xray", window.location.origin);
    longUrl.searchParams.set("config", source);
    longUrl.searchParams.set("selectedRules", state.converter.rulePreset);
    if (state.converter.adBlock && state.converter.rulePreset !== "comprehensive") {
      longUrl.searchParams.set("adblock", "true");
    }
    if (state.converter.whitelist.trim()) longUrl.searchParams.set("whitelist", state.converter.whitelist);
    if (state.converter.blacklist.trim()) longUrl.searchParams.set("blacklist", state.converter.blacklist);
    const shorten = new URL("/shorten-auto", window.location.origin);
    shorten.searchParams.set("url", longUrl.toString());
    const response = await fetch(shorten);
    if (!response.ok) throw new Error(await response.text() || "短链接生成失败");
    const code = (await response.text()).trim();
    state.converter.links = `${window.location.origin}/sub/${encodeURIComponent(code)}`;
    setConverterStatus("已生成通用订阅地址");
  } catch (error) {
    state.converter.links = null;
    setConverterStatus(error.message || "订阅生成失败", true);
  } finally {
    state.converter.busy = false;
    renderConverter();
  }
}

function renderMasquerade(type, value = {}) {
  const target = $("#masquerade-fields");
  if (type === "none") { target.innerHTML = ""; return; }
  if (type === "string") {
    target.innerHTML = `<div class="masquerade-panel masquerade-string-grid">
      <label class="field"><span>HTTP 状态码</span><input id="masq-status" type="number" min="100" max="599" value="${value?.status_code ?? 200}"></label>
      <label class="field"><span>响应头 JSON</span><textarea id="masq-headers" spellcheck="false">${escapeHtml(JSON.stringify(value?.headers || { "content-type": ["text/plain; charset=utf-8"] }, null, 2))}</textarea></label>
      <label class="field"><span>响应正文</span><textarea id="masq-content">${escapeHtml(value?.content || "")}</textarea></label>
    </div>`;
  } else if (type === "file") {
    target.innerHTML = `<div class="masquerade-panel field-grid two"><label class="field"><span>站点目录</span><input id="masq-directory" required value="${escapeHtml(value?.directory || "")}" placeholder="/var/www"></label></div>`;
  } else {
    target.innerHTML = `<div class="masquerade-panel field-grid two">
      <label class="field"><span>代理目标 URL</span><input id="masq-url" required value="${escapeHtml(value?.url || "")}" placeholder="http://127.0.0.1:8080"></label>
      <label class="check"><input id="masq-rewrite-host" type="checkbox" ${value?.rewrite_host ? "checked" : ""}><span>重写 Host 请求头</span></label>
    </div>`;
  }
}

function collectMasquerade() {
  const type = $("#masquerade-type").value;
  if (type === "none") return null;
  if (type === "file") return { type, directory: $("#masq-directory").value.trim() };
  if (type === "proxy") return { type, url: $("#masq-url").value.trim(), rewrite_host: $("#masq-rewrite-host").checked };
  let headers;
  try { headers = JSON.parse($("#masq-headers").value || "{}"); }
  catch { throw new Error("响应头必须是有效 JSON"); }
  return { type, status_code: Number($("#masq-status").value), headers, content: $("#masq-content").value };
}

function collectConfig() {
  const obfsEnabled = $("#obfs-enabled").checked;
  const shareIpv4Server = $("#share-ipv4-server").value.trim();
  const shareIpv6Server = $("#share-ipv6-server").value.trim();
  const listenPortValue = Number($("#listen-port").value);
  return {
    listen: `[::]:${listenPortValue}`,
    tls: { certificate: $("#certificate").value.trim(), private_key: $("#private-key").value.trim() },
    users: collectUsers(),
    bandwidth: {
      up_mbps: Number($("#up-mbps").value || 0),
      down_mbps: Number($("#down-mbps").value || 0),
      ignore_client_bandwidth: $("#ignore-bandwidth").checked
    },
    udp: { enabled: $("#udp-enabled").checked, timeout_secs: Number($("#udp-timeout").value) },
    outbound: { mode: $("#outbound-mode").value },
    obfs: obfsEnabled ? { type: "salamander", password: $("#obfs-password").value } : null,
    masquerade: collectMasquerade(),
    share: {
      server: shareIpv4Server,
      ipv6_server: shareIpv6Server,
      port: Number($("#share-port").value),
      sni: $("#share-sni").value.trim(),
      insecure: $("#share-insecure").checked,
      rule_preset: state.shareRulePreset,
      ad_block: state.shareAdBlock,
      whitelist: ruleListValues($("#share-whitelist").value),
      blacklist: ruleListValues($("#share-blacklist").value)
    }
  };
}

function ruleListValues(value) {
  return value.split(/\r?\n/).map(item => item.trim()).filter(Boolean);
}

async function saveConfig(event) {
  event?.preventDefault();
  const visibleFields = [...$("#config-form").elements].filter(field => field.getClientRects().length > 0);
  const invalidField = visibleFields.find(field => !field.checkValidity());
  if (invalidField) {
    invalidField.reportValidity();
    return;
  }
  const button = $("#save");
  button.disabled = true;
  try {
    const payload = collectConfig();
    await api("/api/v1/config", { method: "PUT", body: JSON.stringify(payload) });
    state.config = payload;
    state.shareShortLinks.clear();
    state.shareShortLinkErrors.clear();
    await generateShareShortLinks();
    toast("配置已保存，HY2 服务正在重新加载");
    setTimeout(loadStatus, 450);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}

async function reloadService() {
  const button = $("#reload");
  button.disabled = true;
  try {
    await api("/api/v1/reload", { method: "POST" });
    toast("重新加载请求已提交");
    setTimeout(loadStatus, 450);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}

function bindEvents() {
  $("#config-form").addEventListener("submit", saveConfig);
  $("#save").addEventListener("click", saveConfig);
  $("#reload").addEventListener("click", reloadService);
  $("#startup-action").addEventListener("click", manageStartup);
  $("#add-user").addEventListener("click", addUser);
  $("#obfs-enabled").addEventListener("change", toggleObfs);
  $("#show-passwords").addEventListener("change", applyPasswordVisibility);
  $("#config-form").addEventListener("input", renderShareLinks);
  $("#share-rule-preset").addEventListener("change", event => {
    state.shareRulePreset = event.target.value;
    renderShareRuleOptions();
  });
  $("#share-adblock").addEventListener("change", event => {
    state.shareAdBlock = event.target.checked;
    renderShareRuleOptions();
  });
  $("#masquerade-type").addEventListener("change", event => renderMasquerade(event.target.value));
  $("#converter-source").addEventListener("input", event => {
    state.converter.source = event.target.value;
    state.converter.links = null;
    localStorage.setItem("sublink-source", state.converter.source);
    renderConverter();
    setConverterStatus();
  });
  $("#converter-rule-preset").addEventListener("change", event => {
    state.converter.rulePreset = event.target.value;
    state.converter.links = null;
    localStorage.setItem("sublink-rule-preset", state.converter.rulePreset);
    renderConverter();
    setConverterStatus();
  });
  $("#converter-adblock").addEventListener("change", event => {
    state.converter.adBlock = event.target.checked;
    state.converter.links = null;
    localStorage.setItem("sublink-adblock", String(state.converter.adBlock));
    renderConverter();
    setConverterStatus();
  });
  for (const [selector, key, storage] of [
    ["#converter-whitelist", "whitelist", "sublink-whitelist"],
    ["#converter-blacklist", "blacklist", "sublink-blacklist"]
  ]) {
    $(selector).addEventListener("input", event => {
      state.converter[key] = event.target.value;
      state.converter.links = null;
      localStorage.setItem(storage, state.converter[key]);
      setConverterStatus();
    });
  }
  $("#converter-generate").addEventListener("click", generateConverterLinks);
  $("#converter-clear").addEventListener("click", () => {
    state.converter.source = "";
    state.converter.links = null;
    localStorage.removeItem("sublink-source");
    renderConverter();
    setConverterStatus();
  });
  $("#converter-paste").addEventListener("click", async () => {
    try {
      state.converter.source = await navigator.clipboard.readText();
      state.converter.links = null;
      localStorage.setItem("sublink-source", state.converter.source);
      renderConverter();
      setConverterStatus();
    } catch {
      setConverterStatus("无法读取剪贴板", true);
    }
  });
  $("#add-admin-user").addEventListener("click", () => {
    $("#new-admin-username").value = "";
    $("#new-admin-password").value = "";
    $("#admin-user-error").classList.add("hidden");
    $("#admin-user-dialog").showModal();
  });
  $("#admin-user-cancel").addEventListener("click", () => $("#admin-user-dialog").close());
  $("#admin-user-form").addEventListener("submit", async event => {
    event.preventDefault();
    const username = $("#new-admin-username").value.trim();
    const password = $("#new-admin-password").value;
    try {
      await api("/api/v1/admin-users", {
        method: "POST",
        body: JSON.stringify({ username, password })
      });
      $("#admin-user-dialog").close();
      await loadAdminUsers();
      toast("管理账户已添加");
    } catch (error) {
      $("#admin-user-error").textContent = error.message;
      $("#admin-user-error").classList.remove("hidden");
    }
  });
  $("#change-user").addEventListener("click", async () => {
    await fetch("/api/v1/logout", { method: "POST" }).catch(() => {});
    clearAdminSession();
    openLoginScreen();
  });
  $("#login-form").addEventListener("submit", async event => {
    event.preventDefault();
    const username = $("#login-username").value.trim();
    const password = $("#login-password").value;
    $("#login-error").textContent = "";
    $("#login-error").classList.add("hidden");
    try {
      await createAdminSession(username, password);
      await Promise.all([loadConfig(), loadAdminUsers(), loadStartup(), loadNetworkCapabilities()]);
      closeLoginScreen();
      await loadStatus();
      startStatusPolling();
    } catch (error) {
      if (!$("#login-error").textContent) {
        $("#login-error").textContent = error.message;
        $("#login-error").classList.remove("hidden");
      }
    }
  });
  document.querySelectorAll("nav a[data-page]").forEach(link => link.addEventListener("click", event => {
    event.preventDefault();
    activatePage(link.dataset.page);
  }));
  window.addEventListener("hashchange", () => activatePage(pageFromHash(), false));
  window.addEventListener("resize", () => requestAnimationFrame(drawTrafficChart));
}

async function initialize() {
  bindEvents();
  renderConverter();
  activatePage(pageFromHash(), false);
  if (state.username && state.sessionExpiresAt * 1000 > Date.now()) {
    try {
      await Promise.all([loadConfig(), loadAdminUsers(), loadStartup(), loadNetworkCapabilities()]);
      closeLoginScreen();
      await loadStatus();
      startStatusPolling();
    } catch (error) {
      if (document.body.classList.contains("auth-booting")) openLoginScreen(error.message);
    }
  } else {
    openLoginScreen();
  }
}

initialize();

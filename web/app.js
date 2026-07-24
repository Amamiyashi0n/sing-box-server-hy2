const $ = (selector, root = document) => root.querySelector(selector);
const state = { config: null, username: sessionStorage.getItem("admin-username") || "admin", password: "", timer: null };

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
    const message = state.password ? "用户名或密码错误" : "请使用管理账户登录";
    state.password = "";
    openLoginDialog(message);
    throw new Error("需要登录");
  }
  if (!response.ok) throw new Error(payload.error || `请求失败 (${response.status})`);
  return payload;
}

function openLoginDialog(message = "") {
  const dialog = $("#login-dialog");
  $("#login-error").textContent = message;
  $("#login-error").classList.toggle("hidden", !message);
  $("#login-username").value = state.username;
  $("#login-password").value = "";
  if (!dialog.open) dialog.showModal();
}

function toast(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.classList.add("show");
  clearTimeout(node._timer);
  node._timer = setTimeout(() => node.classList.remove("show"), 3200);
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

async function loadStatus() {
  try {
    const status = await api("/api/v1/status");
    $("#version").textContent = `v${status.version}`;
    const service = $("#service-state");
    service.className = `service-state ${status.running ? "online" : "offline"}`;
    service.lastElementChild.textContent = status.running ? "运行中" : "已停止";
    $("#metric-listen").textContent = status.listen || "--";
    $("#metric-users").textContent = String(status.users);
    $("#metric-bandwidth").textContent = `${status.up_mbps} / ${status.down_mbps} Mbps`;
    $("#metric-uptime").textContent = formatUptime(status.uptime_secs);
    $("#flag-udp").textContent = `UDP ${status.udp_enabled ? "ON" : "OFF"}`;
    $("#flag-obfs").textContent = `Salamander ${status.obfs ? "ON" : "OFF"}`;
    $("#flag-generation").textContent = `Generation ${status.generation}`;
    $("#updated-at").textContent = `同步于 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`;
    $("#runtime-error").textContent = status.last_error || "";
    $("#runtime-error").classList.toggle("hidden", !status.last_error);
  } catch (error) {
    if (!$("#login-dialog").open) toast(error.message, true);
  }
}

async function loadConfig() {
  const config = await api("/api/v1/config");
  state.config = config;
  $("#listen").value = config.listen || "";
  $("#certificate").value = config.tls?.certificate || "";
  $("#private-key").value = config.tls?.private_key || "";
  $("#share-server").value = config.share?.server || "";
  $("#share-port").value = config.share?.port ?? listenPort(config.listen) ?? 443;
  $("#share-sni").value = config.share?.sni || "";
  $("#share-insecure").checked = Boolean(config.share?.insecure);
  $("#up-mbps").value = config.bandwidth?.up_mbps ?? 0;
  $("#down-mbps").value = config.bandwidth?.down_mbps ?? 0;
  $("#ignore-bandwidth").checked = Boolean(config.bandwidth?.ignore_client_bandwidth);
  $("#udp-enabled").checked = config.udp?.enabled !== false;
  $("#udp-timeout").value = config.udp?.timeout_secs ?? 300;
  $("#obfs-enabled").checked = Boolean(config.obfs);
  $("#obfs-password").value = config.obfs?.password || "";
  toggleObfs();
  renderUsers(config.users || []);
  const type = config.masquerade?.type || "none";
  $("#masquerade-type").value = type;
  renderMasquerade(type, config.masquerade);
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
      <button class="button danger compact" data-remove-user type="button">移除</button>
    </div>`).join("");
  list.querySelectorAll("[data-remove-user]").forEach(button => button.addEventListener("click", () => {
    button.closest("[data-user-row]").remove();
    renumberUsers();
  }));
  applyPasswordVisibility();
  renderShareLinks();
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

function buildShareLink(user) {
  const server = $("#share-server").value.trim();
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

function renderShareLinks() {
  const target = $("#share-links");
  if (!target) return;
  const users = collectUsers(false);
  const links = users.map(user => ({ user, link: buildShareLink(user) })).filter(item => item.link);
  $("#link-count").textContent = `${links.length} 个链接`;
  if (!$("#share-server").value.trim()) {
    target.innerHTML = '<div class="empty">填写公网服务器后生成链接</div>';
    return;
  }
  if (!links.length) {
    target.innerHTML = '<div class="empty">没有可生成链接的认证用户</div>';
    return;
  }
  target.innerHTML = links.map((item, index) => `
    <div class="share-link-row">
      <div class="share-link-user"><strong>${escapeHtml(item.user.name || "未命名用户")}</strong><span>Hysteria 2</span></div>
      <input aria-label="${escapeHtml(item.user.name || "用户")} 配置链接" readonly value="${escapeHtml(item.link)}">
      <button class="button secondary compact" data-copy-link="${index}" type="button">复制</button>
    </div>`).join("");
  target.querySelectorAll("[data-copy-link]").forEach(button => button.addEventListener("click", async () => {
    const link = links[Number(button.dataset.copyLink)].link;
    try {
      await navigator.clipboard.writeText(link);
      toast("配置链接已复制");
    } catch {
      toast("复制失败，请手动选择链接", true);
    }
  }));
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

function renderMasquerade(type, value = {}) {
  const target = $("#masquerade-fields");
  if (type === "none") { target.innerHTML = ""; return; }
  if (type === "string") {
    target.innerHTML = `<div class="masquerade-panel field-grid two">
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
  const shareServer = $("#share-server").value.trim();
  return {
    listen: $("#listen").value.trim(),
    tls: { certificate: $("#certificate").value.trim(), private_key: $("#private-key").value.trim() },
    users: collectUsers(),
    bandwidth: {
      up_mbps: Number($("#up-mbps").value || 0),
      down_mbps: Number($("#down-mbps").value || 0),
      ignore_client_bandwidth: $("#ignore-bandwidth").checked
    },
    udp: { enabled: $("#udp-enabled").checked, timeout_secs: Number($("#udp-timeout").value) },
    obfs: obfsEnabled ? { type: "salamander", password: $("#obfs-password").value } : null,
    masquerade: collectMasquerade(),
    share: shareServer ? {
      server: shareServer,
      port: Number($("#share-port").value),
      sni: $("#share-sni").value.trim(),
      insecure: $("#share-insecure").checked
    } : null
  };
}

async function saveConfig(event) {
  event?.preventDefault();
  if (!$("#config-form").reportValidity()) return;
  const button = $("#save");
  button.disabled = true;
  try {
    const payload = collectConfig();
    await api("/api/v1/config", { method: "PUT", body: JSON.stringify(payload) });
    state.config = payload;
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
  $("#add-user").addEventListener("click", addUser);
  $("#obfs-enabled").addEventListener("change", toggleObfs);
  $("#show-passwords").addEventListener("change", applyPasswordVisibility);
  $("#config-form").addEventListener("input", renderShareLinks);
  $("#masquerade-type").addEventListener("change", event => renderMasquerade(event.target.value));
  $("#change-user").addEventListener("click", () => {
    state.password = "";
    openLoginDialog();
  });
  $("#login-cancel").addEventListener("click", () => $("#login-dialog").close());
  $("#login-form").addEventListener("submit", async event => {
    event.preventDefault();
    state.username = $("#login-username").value.trim();
    state.password = $("#login-password").value;
    sessionStorage.setItem("admin-username", state.username);
    try {
      await loadConfig();
      $("#login-dialog").close();
      await loadStatus();
    } catch (error) {
      $("#login-error").textContent = error.message;
      $("#login-error").classList.remove("hidden");
    }
  });
  document.querySelectorAll("nav a").forEach(link => link.addEventListener("click", () => {
    document.querySelectorAll("nav a").forEach(item => item.classList.remove("active"));
    link.classList.add("active");
  }));
}

async function initialize() {
  bindEvents();
  try {
    await Promise.all([loadConfig(), loadStatus()]);
  } catch (error) {
    if (!$("#login-dialog").open) toast(error.message, true);
  }
  state.timer = setInterval(loadStatus, 5000);
}

initialize();

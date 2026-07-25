const $ = (selector, root = document) => root.querySelector(selector);
const state = {
  config: null,
  username: "",
  password: "",
  timer: null,
  adminUsers: [],
  shareShortLinks: new Map(),
  shareShortLinkErrors: new Map(),
  shareShortLinksPending: new Set(),
  converter: {
    source: localStorage.getItem("sublink-source") || "",
    format: localStorage.getItem("sublink-format") || "singbox",
    links: null,
    busy: false
  }
};

const CONVERTER_FORMATS = ["singbox", "clash", "surge", "xray"];
const CONVERTER_LABELS = { singbox: "Sing-Box", clash: "Clash", surge: "Surge", xray: "Xray" };
const CONVERTER_PREFIXES = { singbox: "b", clash: "c", surge: "s", xray: "x" };
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
    state.password = "";
    openLoginScreen(message);
    throw new Error("需要登录");
  }
  if (!response.ok) throw new Error(payload.error || `请求失败 (${response.status})`);
  return payload;
}

function openLoginScreen(message = "") {
  const alreadyVisible = loginScreenVisible();
  stopStatusPolling();
  document.body.classList.add("auth-pending");
  $("#login-screen").classList.remove("hidden");
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
  document.body.classList.remove("auth-pending");
}

function loginScreenVisible() {
  return document.body.classList.contains("auth-pending");
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

function displayListenAddress(value) {
  const address = String(value || "");
  const port = address.match(/^\[::\]:(\d+)$/);
  if (port) return `0.0.0.0:${port[1]} / [::]:${port[1]}`;
  if (address === "[::]") return "0.0.0.0 / [::]";
  return address;
}

async function loadStatus() {
  try {
    const status = await api("/api/v1/status");
    $("#version").textContent = `v${status.version}`;
    const service = $("#service-state");
    service.className = `service-state ${status.running ? "online" : "offline"}`;
    service.lastElementChild.textContent = status.running ? "运行中" : "已停止";
    $("#metric-listen").textContent = displayListenAddress(status.listen) || "--";
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
    if (!loginScreenVisible()) toast(error.message, true);
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
  await generateShareShortLinks();
}

async function loadAdminUsers() {
  const response = await api("/api/v1/admin-users");
  state.adminUsers = response.users || [];
  renderAdminUsers();
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

function currentShareLinks() {
  return collectUsers(false)
    .map(user => ({ user, link: buildShareLink(user) }))
    .filter(item => item.link);
}

function renderShareLinks() {
  const target = $("#share-links");
  if (!target) return;
  const links = currentShareLinks();
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
    <article class="share-link-card">
      <header class="share-link-user"><strong>${escapeHtml(item.user.name || "未命名用户")}</strong></header>
      <div class="share-protocol">
        <div class="share-protocol-name">HY2</div>
        <div class="share-link-fields">
          <div class="share-link-line">
            <span>连接</span>
            <input aria-label="${escapeHtml(item.user.name || "用户")} HY2 连接" readonly value="${escapeHtml(item.link)}">
            <button class="button secondary compact" data-copy-link="${index}" data-link-kind="source" type="button">复制</button>
          </div>
          <div class="share-link-line">
            <span>短链接</span>
            <input aria-label="${escapeHtml(item.user.name || "用户")} HY2 短链接" readonly
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
      await navigator.clipboard.writeText(link);
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
      const shorten = new URL("/shorten-hy2", window.location.origin);
      shorten.searchParams.set("url", longUrl.toString());
      const response = await fetch(shorten);
      if (!response.ok) throw new Error(await response.text() || "短链接生成失败");
      const code = (await response.text()).trim();
      state.shareShortLinks.set(item.link, `${window.location.origin}/x/${encodeURIComponent(code)}`);
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
  document.querySelectorAll("[data-converter-format]").forEach(button => {
    const active = button.dataset.converterFormat === state.converter.format;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  $("#converter-generate").disabled = state.converter.busy;
  $("#converter-generate").textContent = state.converter.busy ? "生成中" : "生成订阅";
  renderConverterResults();
}

function setConverterStatus(message = "", error = false) {
  const target = $("#converter-status");
  target.textContent = message;
  target.classList.toggle("error", error);
}

function orderedConverterFormats() {
  return [state.converter.format, ...CONVERTER_FORMATS.filter(format => format !== state.converter.format)];
}

function renderConverterResults() {
  const target = $("#converter-results");
  const links = state.converter.links;
  target.classList.toggle("hidden", !links);
  if (!links) {
    target.replaceChildren();
    return;
  }
  target.innerHTML = orderedConverterFormats().map(format => `
    <div class="converter-result ${format === state.converter.format ? "preferred" : ""}">
      <strong>${CONVERTER_LABELS[format]}</strong>
      <input aria-label="${CONVERTER_LABELS[format]} 订阅地址" readonly value="${escapeHtml(links[format])}">
      <button class="button secondary compact" data-converter-copy="${format}" type="button">复制</button>
      <a class="button secondary compact converter-open" href="${escapeHtml(links[format])}" target="_blank" rel="noreferrer">打开</a>
    </div>`).join("");
  target.querySelectorAll("[data-converter-copy]").forEach(button => button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(links[button.dataset.converterCopy]);
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
    const pairs = await Promise.all(CONVERTER_FORMATS.map(async format => {
      const longUrl = new URL(`/${format}`, window.location.origin);
      longUrl.searchParams.set("config", source);
      const shorten = new URL("/shorten-v2", window.location.origin);
      shorten.searchParams.set("url", longUrl.toString());
      const response = await fetch(shorten);
      if (!response.ok) throw new Error(await response.text() || "短链接生成失败");
      const code = (await response.text()).trim();
      return [format, `${window.location.origin}/${CONVERTER_PREFIXES[format]}/${encodeURIComponent(code)}`];
    }));
    state.converter.links = Object.fromEntries(pairs);
    setConverterStatus("已生成 4 个客户端订阅地址");
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
  $("#add-user").addEventListener("click", addUser);
  $("#obfs-enabled").addEventListener("change", toggleObfs);
  $("#show-passwords").addEventListener("change", applyPasswordVisibility);
  $("#config-form").addEventListener("input", renderShareLinks);
  $("#masquerade-type").addEventListener("change", event => renderMasquerade(event.target.value));
  $("#converter-source").addEventListener("input", event => {
    state.converter.source = event.target.value;
    state.converter.links = null;
    localStorage.setItem("sublink-source", state.converter.source);
    renderConverter();
    setConverterStatus();
  });
  document.querySelectorAll("[data-converter-format]").forEach(button => button.addEventListener("click", () => {
    state.converter.format = button.dataset.converterFormat;
    localStorage.setItem("sublink-format", state.converter.format);
    renderConverter();
  }));
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
  $("#change-user").addEventListener("click", () => {
    state.password = "";
    openLoginScreen();
  });
  $("#login-form").addEventListener("submit", async event => {
    event.preventDefault();
    state.username = $("#login-username").value.trim();
    state.password = $("#login-password").value;
    $("#login-error").textContent = "";
    $("#login-error").classList.add("hidden");
    try {
      await Promise.all([loadConfig(), loadAdminUsers()]);
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
}

async function initialize() {
  bindEvents();
  renderConverter();
  activatePage(pageFromHash(), false);
}

initialize();

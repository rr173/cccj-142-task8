// 公共 API 层：令牌与角色存 localStorage；所有写调用带幂等键（同一签名双终端重放取首次结果）
const TOKEN_KEY = "consent_token";
const USER_KEY = "consent_user";

const OP_LABELS = {
  blood_draw: "采血", imaging: "影像检查", medication: "用药", sample_reuse: "留存材料再次利用",
};
const ROLE_LABELS = { subject: "参与人", witness: "见证者", site_owner: "现场负责人" };
const STATUS_LABELS = {
  open: ["办理中", "wait"], completed: ["已完成", "ok"], withdrawn: ["已撤销", "no"],
  blocked: ["已冻结", "no"], active: ["现行", "ok"], retired: ["已停用", "no"],
  revoked: ["已撤销", "no"],
};

function getUser() { return JSON.parse(localStorage.getItem(USER_KEY) || "null"); }
function getToken() { return localStorage.getItem(TOKEN_KEY); }
function setAuth(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}
function logout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  location.href = "/index.html";
}

async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  const tok = getToken();
  if (tok) headers.Authorization = "Bearer " + tok;
  if (body && method !== "GET") {
    body.idempotency_key = body.idempotency_key
      || (method + ":" + path + ":" + crypto.randomUUID());
  }
  const resp = await fetch(path, {
    method, headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await resp.json(); } catch { /* 非 JSON */ }
  if (!resp.ok) {
    const e = new Error(data?.message || ("HTTP " + resp.status));
    e.code = data?.error; e.body = data;
    throw e;
  }
  return data;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function pill(status) {
  const [label, cls] = STATUS_LABELS[status] || [status, "info"];
  return `<span class="pill ${cls}">${label}</span>`;
}
function opList(ops) {
  return (ops || []).map(o => OP_LABELS[o] || o).join("、") || "—";
}
function roleList(roles) {
  return (roles || []).map(r => ROLE_LABELS[r] || r).join("、");
}
function toast(box, err) {
  box.innerHTML = `<div class="err">${esc(err.message)}${err.code ? ` <span class="muted">[${esc(err.code)}]</span>` : ""}</div>`;
}
function okbox(box, msg) {
  box.innerHTML = `<div class="okbox">${esc(msg)}</div>`;
}
function headerHtml(title) {
  const u = getUser();
  return `<header><h1>电子知情同意与许可引擎 · ${title}</h1><span class="sp"></span>
    <span class="me">${u ? esc(u.name) + "（" + ({admin: "规则维护员", site: "现场办理", subject: "参与人"}[u.role]) + "）" : ""}</span>
    ${u ? '<a href="#" onclick="logout();return false;">退出</a>' : ""}
  </header>`;
}

async function boot(role, mountId, render) {
  const mount = document.getElementById(mountId);
  if (!getToken()) { location.href = "/index.html"; return; }
  const u = getUser();
  if (u.role !== role) { location.href = "/index.html"; return; }
  mount.innerHTML = headerHtml({ admin: "规则维护", site: "现场办理", subject: "参与人自助" }[role]);
  const main = document.createElement("main");
  mount.appendChild(main);
  await render(main);
}

async function renderLogin() {
  const mount = document.getElementById("app");
  if (getToken()) {
    const u = getUser();
    location.href = { admin: "admin.html", site: "site.html", subject: "subject.html" }[u.role]
      || "index.html";
    return;
  }
  mount.innerHTML = `
  <div class="login-card card">
    <h2>登录</h2>
    <label>账号</label><input id="login" value="">
    <label>密码</label><input id="pw" type="password" value="">
    <div style="margin-top:10px"><button id="btn">登录</button></div>
    <div id="msg"></div>
    <p class="muted">演示账号：admin/admin-pass（规则维护员）、sitea/site-pass（A院现场）、
    wang/wang-pass（参与人·王）、zhao/zhao-pass（B院参与人）。<br>
    见证者无需账号，由现场提供一次性签名链接。</p>
  </div>`;
  const doLogin = async () => {
    const msg = document.getElementById("msg");
    try {
      const r = await api("POST", "/api/auth/login", {
        login: document.getElementById("login").value.trim(),
        password: document.getElementById("pw").value,
      });
      setAuth(r.token, r.user);
      location.href = { admin: "admin.html", site: "site.html", subject: "subject.html" }[r.user.role];
    } catch (e) { toast(msg, e); }
  };
  document.getElementById("btn").onclick = doLogin;
  document.getElementById("pw").onkeydown = e => e.key === "Enter" && doLogin();
}

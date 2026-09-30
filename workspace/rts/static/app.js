// 公共工具：令牌存 localStorage，所有 API 请求带 X-Authorization
const Auth = {
  get() { return JSON.parse(localStorage.getItem('rts_session') || 'null'); },
  set(s) { localStorage.setItem('rts_session', JSON.stringify(s)); },
  clear() { localStorage.removeItem('rts_session'); },
  token() { const s = this.get(); return s ? s.token : null; },
};

async function api(method, url, body) {
  const opt = { method, headers: { 'Content-Type': 'application/json' } };
  if (Auth.token()) opt.headers['X-Authorization'] = 'Bearer ' + Auth.token();
  if (body !== undefined) opt.body = JSON.stringify(body);
  const res = await fetch(url, opt);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    Auth.clear();
    location.href = '/static/index.html';
    throw new Error('会话失效');
  }
  if (!res.ok) {
    const e = new Error(data.message || ('HTTP ' + res.status));
    e.code = data.error;
    throw e;
  }
  return data;
}

function el(id) { return document.getElementById(id); }

function toast(msg, ok) {
  const box = el('toast');
  if (!box) return alert(msg);
  box.textContent = msg;
  box.className = 'toast show ' + (ok ? 'ok' : 'err');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => box.className = 'toast', 3500);
}

function headerBlock(roleLabel) {
  const s = Auth.get();
  return `
    <header class="topbar">
      <div class="brand">多中心 RCT 随机/盲态药盒平台 <span class="role-tag">${roleLabel}</span></div>
      <div class="who">${s.display}（${s.username} · 中心 ${s.center_code || '—'}）
        <button class="btn small" onclick="doLogout()">退出</button></div>
    </header>`;
}

async function doLogout() {
  try { await api('POST', '/api/logout'); } catch (e) {}
  Auth.clear();
  location.href = '/static/index.html';
}

function guard(role) {
  const s = Auth.get();
  if (!s) { location.href = '/static/index.html'; return null; }
  if (s.role !== role) {
    const map = { investigator: 'investigator.html', pharmacy: 'pharmacy.html', safety: 'safety.html' };
    location.href = '/static/' + map[s.role];
    return null;
  }
  return s;
}

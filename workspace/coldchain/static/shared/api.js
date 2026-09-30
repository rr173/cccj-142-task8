/* 极简 API 客户端：Bearer 会话存 sessionStorage，错误统一弹 toast。 */
const TOKEN_KEY = 'cc_token';

export function getToken() { return sessionStorage.getItem(TOKEN_KEY); }
export function setToken(t) { sessionStorage.setItem(TOKEN_KEY, t); }
export function clearToken() { sessionStorage.removeItem(TOKEN_KEY); }

export function toast(message, kind = '') {
  let box = document.getElementById('toast');
  if (!box) {
    box = document.createElement('div');
    box.id = 'toast';
    document.body.appendChild(box);
  }
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = message;
  box.appendChild(el);
  setTimeout(() => el.remove(), kind === 'error' ? 7000 : 3500);
}

export async function api(method, url, body = undefined) {
  const headers = { 'content-type': 'application/json' };
  const t = getToken();
  if (t) headers['X-Authorization'] = 'Bearer ' + t;
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  const text = await res.text();
  if (text) {
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
  }
  if (res.status === 401) {
    clearToken();
    if (!location.pathname.endsWith('index.html') && location.pathname !== '/') {
      location.href = '/static/index.html';
    }
    throw new Error('请先登录');
  }
  if (!res.ok) {
    const msg = data?.message || ('请求失败 ' + res.status);
    const err = new Error(msg);
    err.payload = data;
    err.status = res.status;
    throw err;
  }
  return data;
}

export async function requireRole(role) {
  if (!getToken()) location.href = '/static/index.html';
  try {
    const me = await api('GET', '/api/me');
    if (role && me.role !== role) {
      toast('当前账号角色无权访问该页面（' + me.role + '）', 'error');
      setTimeout(() => (location.href = '/static/index.html'), 1200);
    }
    return me;
  } catch {
    location.href = '/static/index.html';
  }
}

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const STATE_LABEL = {
  collecting: '待补传',
  ready: '待质量处置',
  decided: '已最终处置',
  revoking: '撤销复核中',
  revoked: '已撤销·待重处',
};

export function badgeClass(state) {
  return 'badge b-' + state.replace(/_/g, '-');
}

export const fmt = (iso) => iso ? iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z') : '';

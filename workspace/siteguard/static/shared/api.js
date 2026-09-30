/* 极简 fetch 封装：统一 JSON、Bearer 令牌、错误展示。 */
(function (global) {
  const TOKEN_KEY = 'sg.token';
  const IDENTITY_KEY = 'sg.identity';

  const api = async function (method, url, body, token) {
    const res = await fetch(url, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(token ? { 'X-Authorization': 'Bearer ' + token } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    const json = text ? JSON.parse(text) : {};
    if (!res.ok) {
      const err = new Error(json.message || ('HTTP ' + res.status));
      err.code = json.error;
      err.status = res.status;
      err.body = json;
      throw err;
    }
    return json;
  };

  global.SG = global.SG || {};
  global.SG.api = api;
  global.SG.getToken = () => localStorage.getItem(TOKEN_KEY);
  global.SG.setSession = (login) => {
    localStorage.setItem(TOKEN_KEY, login.token);
    localStorage.setItem(IDENTITY_KEY, JSON.stringify({
      username: login.username, role: login.role,
      site_code: login.site_code, display: login.display,
    }));
  };
  global.SG.clearSession = () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(IDENTITY_KEY);
  };
  global.SG.identity = () => {
    const raw = localStorage.getItem(IDENTITY_KEY);
    return raw ? JSON.parse(raw) : null;
  };

  global.SG.escapeHtml = (s) => String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  global.SG.flash = (el, kind, msg) => {
    el.className = 'flash ' + kind;
    el.textContent = msg;
  };
})(window);

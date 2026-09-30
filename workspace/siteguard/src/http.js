/**
 * 原生 http 接口 + 安全管理页 / 终端自检页 / 中性审计页 / 电子知情同意页（无框架）。
 *
 * 数据目录 SIGUARD_DATA（默认 ../data），其中 siteguard.wal.log 为 fsync 追加日志；
 * SIGUARD_CHALLENGE_TTL 可改挑战短截止（默认 60s）。重启进程即重放日志，
 * 已消费注册码/随机数不复活，隔离、轮换、历史验签信息不丢失。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { Store } from './storage.js';
import { SiteGuardService, ServiceError, CONSENT, ACTION_CATALOG } from './service.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DATA_DIR = process.env.SIGUARD_DATA ||
  path.join(__dirname, '..', 'data');
const STATIC_DIR = path.join(__dirname, '..', 'static');
const PORT = Number(process.env.SIGUARD_PORT || 8090);
const CHALLENGE_TTL = Number(process.env.SIGUARD_CHALLENGE_TTL || 60_000);
const CERT_MINUTES = Number(process.env.SIGUARD_CERT_MINUTES || 5 * 24 * 60);
const MAX_BODY = 2 * 1024 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
};

export function createApp({ dataDir = DATA_DIR, challengeTtlMs = CHALLENGE_TTL,
                            certMinutes = CERT_MINUTES } = {}) {
  const store = new Store(dataDir);
  const svc = new SiteGuardService(store, { challengeTtlMs, certMinutes });

  function send(res, code, body) {
    const buf = Buffer.from(JSON.stringify(body));
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8',
      'content-length': buf.length });
    res.end(buf);
  }

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) {
          reject(new HttpError(413, 'BODY_TOO_LARGE', '请求体过大'));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        if (!chunks.length) return resolve({});
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new HttpError(400, 'BAD_JSON', '请求体不是合法 JSON')); }
      });
      req.on('error', reject);
    });
  }

  const bearer = (req) => {
    const h = req.headers['x-authorization'] || req.headers['authorization'];
    return h ? String(h).replace(/^Bearer\s+/i, '').trim() || null : null;
  };

  const routes = [];
  const route = (method, pattern, roles, fn) => {
    const keys = [];
    const rx = new RegExp('^' + pattern.replace(/:([a-z_]+)/g, (_, k) => {
      keys.push(k); return '([^/]+)';
    }) + '$');
    routes.push({ method, rx, keys, roles, fn });
  };

  // ------------------------------------------------------------- 会话
  route('POST', '/api/login', null, async (_p, body) => svc.login(body.username, body.password));
  route('POST', '/api/logout', null, async (_p, _b, _u, req) => {
    svc.logout(bearer(req)); return { ok: true };
  });
  route('GET', '/api/me', null, async (_p, _b, _u, req) => {
    const u = svc.userForToken(bearer(req));
    if (!u) throw new HttpError(401, 'UNAUTHENTICATED', '未登录');
    return { username: u.username, role: u.role, site_code: u.site_code, display: u.display };
  });

  // 公开材料：服务端公钥（库外验签用）、电子知情同意当前版本、业务动作目录
  route('GET', '/api/server-key', null, async () => ({
    alg: 'SG-CA-ECDSA-P256-SHA256/v1', public_jwk: store.state.serverPublicJwk }));
  route('GET', '/api/consent', null, async () => CONSENT);
  route('GET', '/api/actions', null, async () => ({ actions: ACTION_CATALOG }));
  route('POST', '/api/verify-record', null, async (_p, body) =>
    svc.verifyRecordEnvelope(body.envelope ?? body));

  // ------------------------------------------------------------- 终端（无登录，持证书）
  route('POST', '/api/terminal/register', null, async (_p, body) => svc.registerTerminal(body));
  route('POST', '/api/terminal/challenge', null, async (_p, body) => svc.issueChallenge(body));
  route('POST', '/api/terminal/submit', null, async (_p, body) => svc.submitSignedAction(body));
  route('POST', '/api/terminal/inspect', null, async (_p, body) => svc.inspectTerminal(body));
  route('POST', '/api/terminal/rotate', null, async (_p, body) => svc.rotateTerminal(body));
  route('POST', '/api/terminal/record', null, async (_p, body) => svc.collectRecord(body));

  // ------------------------------------------------------------- 安全管理员（站点隔离）
  route('POST', '/api/admin/register-codes', ['admin'], async (_p, body, u) =>
    svc.createRegisterCode(u, body));
  route('GET', '/api/admin/register-codes', ['admin'], async (_p, _b, u) =>
    svc.listRegisterCodes(u));
  route('GET', '/api/admin/devices', ['admin'], async (_p, _b, u) =>
    svc.listDevices(u));
  route('POST', '/api/admin/devices/quarantine', ['admin'], async (_p, body, u) =>
    svc.quarantineDevice(u, body));
  route('POST', '/api/admin/certificates/rotate', ['admin'], async (_p, body, u) =>
    svc.prepareRotation(u, body));
  route('GET', '/api/admin/records', ['admin'], async (_p, body, u) =>
    svc.listRecords(u, body));

  // ------------------------------------------------------------- 中性审计员
  route('GET', '/api/audit', ['auditor'], async (_p, body, u) =>
    svc.listAudit(u, body));

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;
    try {
      if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
        return serveFile(res, path.join(STATIC_DIR, 'index.html'));
      }
      if (pathname.startsWith('/static/')) {
        const safe = path.normalize(pathname.slice('/static/'.length)).replace(/^([/\\]|\.\.)+/, '');
        return serveFile(res, path.join(STATIC_DIR, safe));
      }
      // 浏览器侧与 service 共用的规范化算法（确保两端字节一致）
      if (pathname === '/vendor/canonical.js') {
        return serveFile(res, path.join(__dirname, 'canonical.js'));
      }
      const r = routes.find((x) => x.method === req.method && x.rx.test(pathname));
      if (!r) return send(res, 404, { error: 'NOT_FOUND', message: '接口不存在' });
      const m = r.rx.exec(pathname);
      const params = Object.fromEntries(r.keys.map((k, i) => [k, m[i + 1]]));
      const query = Object.fromEntries(url.searchParams);
      const body = req.method === 'GET' ? query : await readBody(req);
      const user = r.roles ? svc.requireUser(bearer(req), r.roles) : null;
      const data = await r.fn(params, body, user, req);
      return send(res, 200, data);
    } catch (e) {
      if (e instanceof ServiceError || e instanceof HttpError) {
        return send(res, e.http, { error: e.code, message: e.message,
          ...(e.extra && Object.keys(e.extra).length ? e.extra : {}) });
      }
      console.error('[unhandled]', e);
      return send(res, 500, { error: 'INTERNAL', message: '服务器内部错误' });
    }
  });

  function serveFile(res, filePath) {
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'content-type': MIME[path.extname(filePath)] ||
        'application/octet-stream' });
      res.end(data);
    });
  }

  return { server, store, svc };
}

class HttpError extends Error {
  constructor(http, code, message, extra = {}) {
    super(message);
    this.http = http; this.code = code; this.extra = extra;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const app = createApp();
  app.server.listen(PORT, () => {
    console.log(`建设现场签署终端可信登记模块已启动: http://localhost:${PORT}/  (data=${DATA_DIR})`);
    console.log('演示账号：safeA/safeB（安全管理员，甲/乙站）、auditor（中性审计员），密码 demo1234');
  });
}

/**
 * 原生 http 持久化接口 + 三类角色页面（无 Web 框架依赖）。
 *
 * 数据落盘于 COLDCHAIN_DB（默认 data/coldchain.db），WAL + synchronous=FULL，
 * 进程重启后未完成的上传、待复核撤销与登录会话全部继续可用。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { initDb } from './db.js';
import { ColdChainService, ServiceError } from './service.js';
import { verifyCredential } from './credential.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DB_PATH = process.env.COLDCHAIN_DB ||
  path.join(__dirname, '..', 'data', 'coldchain.db');
const STATIC_DIR = path.join(__dirname, '..', 'static');
const PORT = Number(process.env.COLDCHAIN_PORT || 8080);
const MAX_BODY = 8 * 1024 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
};

export const db = initDb(DB_PATH);
const svc = new ColdChainService(db);

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
        reject(new ServiceError('BODY_TOO_LARGE', '请求体过大', 413));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new ServiceError('BAD_JSON', '请求体不是合法 JSON', 400));
      }
    });
    req.on('error', reject);
  });
}

const bearer = (req) => {
  const h = req.headers['x-authorization'] || req.headers['authorization'];
  if (!h) return null;
  return String(h).replace(/^Bearer\s+/i, '').trim() || null;
};

/**
 * 路由表：[method, pattern, roles, handler]。
 * 角色：device 运输设备 / quality 质量管理员 / site 研究站点。
 * handler 收到 (params, body, user, req)。
 */
const routes = [];
function route(method, pattern, roles, fn) {
  const keys = [];
  const rx = new RegExp('^' + pattern.replace(/:([a-z_]+)/g, (_, k) => {
    keys.push(k);
    return '([^/]+)';
  }) + '$');
  routes.push({ method, rx, keys, roles, fn });
}

// --------------------------------------------------------------- 认证
route('POST', '/api/login', null, async (_p, body) => svc.login(body.username, body.password));
route('POST', '/api/logout', null, async (_p, _b, _u, req) => {
  svc.logout(bearer(req));
  return { ok: true };
});
route('GET', '/api/me', null, async (_p, _b, _u, req) => {
  const u = svc.userForToken(bearer(req));
  if (!u) throw new ServiceError('UNAUTHENTICATED', '未登录', 401);
  return { username: u.username, display: u.display, role: u.role };
});

// 模块公钥：凭据校验方在数据库之外使用（无鉴权，公钥本来公开）
route('GET', '/api/public-key', null, async () => {
  const jwk = db.prepare("SELECT value FROM app_meta WHERE key='signing_public_jwk'").get().value;
  return { algorithm: 'CC-EVIDENCE-ED25519-SHA256/v1', public_jwk: JSON.parse(jwk) };
});

// 库外校验：贴入凭据信封即可重算（同样不查库，只验签+重算）
route('POST', '/api/verify-credential', null, async (_p, body) => {
  const jwkRow = db.prepare("SELECT value FROM app_meta WHERE key='signing_public_jwk'").get();
  return verifyCredential(body.envelope ?? body, JSON.parse(jwkRow.value));
});

// --------------------------------------------------------------- 温控规则（质量管理员）
route('POST', '/api/quality/rules', ['quality'], async (_p, body, user) =>
  svc.createRule(user, body));
route('GET', '/api/quality/rules', ['quality'], async () => svc.listRules());

// --------------------------------------------------------------- 运单
route('POST', '/api/device/waybills', ['device', 'quality'], async (_p, body, user) =>
  svc.createWaybill(user, body));
route('GET', '/api/device/waybills', ['device', 'quality'], async () => svc.listWaybills());
route('GET', '/api/device/waybills/:no', ['device', 'quality'], async (p, _b, user) =>
  svc.waybillDetailByNo(p.no, user));
route('POST', '/api/device/waybills/:no/fragments', ['device', 'quality'],
  async (p, body, user) => svc.uploadFragment(user, p.no, body));

// --------------------------------------------------------------- 质量管理员
route('GET', '/api/quality/waybills', ['quality'], async () => svc.listWaybills());
route('GET', '/api/quality/waybills/:id', ['quality'], async (p, _b, user) =>
  svc.waybillDetailById(Number(p.id), user));
route('POST', '/api/quality/waybills/:id/confirm', ['quality'], async (p, body, user) =>
  svc.confirmDecision(user, Number(p.id), body));
route('POST', '/api/quality/waybills/:id/revoke', ['quality'], async (p, body, user) =>
  svc.requestRevocation(user, Number(p.id), body));
route('GET', '/api/quality/revocations', ['quality'], async (_p, body) =>
  svc.listRevocations(body?.all === true));
route('POST', '/api/quality/revocations/:id/review', ['quality'], async (p, body, user) =>
  svc.reviewRevocation(user, Number(p.id), body));
route('POST', '/api/quality/waybills/:id/credential', ['quality'], async (p, _b, user) =>
  svc.issueCredential(user, Number(p.id)));
route('GET', '/api/quality/audit', ['quality'], async (_p, body) =>
  svc.auditLog(body?.limit));

// --------------------------------------------------------------- 研究站点（只读）
route('GET', '/api/site/waybills', ['site'], async () => svc.siteListView());
route('GET', '/api/site/waybills/:no', ['site'], async (p) => svc.siteViewByNo(p.no));

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url === '/' || req.url === '//' ? '/' : req.url, 'http://localhost');
  const pathname = url.pathname;

  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    return serveFile(res, path.join(STATIC_DIR, 'index.html'));
  }
  if (pathname.startsWith('/static/')) {
    const rel = pathname.slice('/static/'.length);
    const safe = path.normalize(rel).replace(/^([/\\]|\.\.)+/, '');
    return serveFile(res, path.join(STATIC_DIR, safe));
  }
  // 纯函数引擎（无数据库、无密钥）：供库外浏览器校验页重算时间线
  if (pathname === '/vendor/engine.js') {
    return serveFile(res, path.join(__dirname, 'engine.js'));
  }

  const r = routes.find((x) => x.method === req.method && x.rx.test(pathname));
  if (!r || (req.method !== 'GET' && req.method !== 'POST')) {
    return send(res, 404, { error: 'NOT_FOUND', message: '接口不存在' });
  }
  try {
    const m = r.rx.exec(pathname);
    const params = Object.fromEntries(r.keys.map((k, i) => [k, m[i + 1]]));
    const body = req.method === 'GET'
      ? Object.fromEntries(url.searchParams)
      : await readBody(req);
    const user = r.roles ? svc.requireUser(bearer(req), r.roles) : null;
    const data = await r.fn(params, body, user, req);
    return send(res, 200, data);
  } catch (e) {
    if (e instanceof ServiceError) {
      return send(res, e.http, { error: e.code, message: e.message,
        ...(e.conflicts ? { conflicts: e.conflicts } : {}) });
    }
    console.error('[unhandled]', e);
    return send(res, 500, { error: 'INTERNAL', message: '服务器内部错误' });
  }
});

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('not found');
    }
    res.writeHead(200, { 'content-type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  server.listen(PORT, () => {
    console.log(`冷链证据模块已启动: http://localhost:${PORT}/  (db=${DB_PATH})`);
  });
}

export { server, svc };

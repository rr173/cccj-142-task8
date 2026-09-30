/**
 * 附加安全边界：注册码 TTL、CSR 自证、证书篡改、角色越权、非目录动作、输入校验。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { startApp, httpJson, login, sha256Hex, BrowserTerminal, sleep } from './helpers.js';

const { subtle } = webcrypto;

async function csrFor(base, code, label, keys, consentVersion) {
  const cv = consentVersion ??
    (await httpJson(base, 'GET', '/api/consent')).json.version;
  const jwk = await subtle.exportKey('jwk', keys.publicKey);
  const pub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  const csr = { alg: 'SG-REGISTER-CSR/v1', code, device_label: label,
    public_jwk: pub, consent_version: cv };
  const enc = new TextEncoder();
  const { canonicalize } = await import('../src/canonical.js');
  const sig = Buffer.from(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' },
    keys.privateKey, enc.encode(canonicalize(csr)))).toString('base64url');
  return { body: { code, device_label: label, consent_version: cv,
    public_jwk: pub, csr_sig: sig } };
}

test('边界：注册码到期后不能登记；到期前可以', async () => {
  const run = await startApp({ challengeTtlMs: 60_000 });
  try {
    const safe = await login(run.url, 'safeA');
    const issued = await httpJson(run.url, 'POST', '/api/admin/register-codes',
      { token: safe, body: { roles: ['supervisor'], minutes: 1 } });
    const code = issued.json.code;
    const issuedAt = Date.parse(issued.json.created_at);

    const keys1 = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    // 服务层以"未来 61 分钟"调用：码已过期
    const body1 = (await csrFor(run.url, code, '过期机', keys1)).body;
    assert.throws(
      () => run.app.svc.registerTerminal(body1, issuedAt + 61 * 60_000),
      (e) => e.code === 'REGISTER_CODE_EXPIRED');

    // 另一张码：在签发后 30 秒登记，正常通过
    const issued2 = await httpJson(run.url, 'POST', '/api/admin/register-codes',
      { token: safe, body: { roles: ['supervisor'], minutes: 1 } });
    const at2 = Date.parse(issued2.json.created_at);
    const keys2 = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const body2 = (await csrFor(run.url, issued2.json.code, '踩点机', keys2)).body;
    assert.doesNotThrow(
      () => run.app.svc.registerTerminal(body2, at2 + 30 * 1000));

    // 非法 TTL
    const bad1 = await httpJson(run.url, 'POST', '/api/admin/register-codes',
      { token: safe, body: { roles: ['supervisor'], minutes: 0 } });
    assert.equal(bad1.json.error, 'BAD_TTL');
    const bad2 = await httpJson(run.url, 'POST', '/api/admin/register-codes',
      { token: safe, body: { roles: ['supervisor'], minutes: 99999 } });
    assert.equal(bad2.json.error, 'BAD_TTL');
  } finally { await run.close(); }
});

test('边界：CSR 必须由提交公钥对应的私钥签名（公钥冒充即拒）', async () => {
  const run = await startApp();
  try {
    const safe = await login(run.url, 'safeA');
    const code = (await httpJson(run.url, 'POST', '/api/admin/register-codes',
      { token: safe, body: { roles: ['supervisor'] } })).json.code;
    const owner = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const attacker = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

    const body = await csrFor(run.url, code, '冒名机', owner);
    // 用攻击者私钥给"受害者公钥"签名
    const enc = new TextEncoder();
    const { canonicalize } = await import('../src/canonical.js');
    const forgedCsr = { alg: 'SG-REGISTER-CSR/v1', code, device_label: '冒名机',
      public_jwk: body.body.public_jwk,
      consent_version: body.body.consent_version };
    body.body.csr_sig = Buffer.from(await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, attacker.privateKey,
      enc.encode(canonicalize(forgedCsr)))).toString('base64url');

    const r = await httpJson(run.url, 'POST', '/api/terminal/register', body);
    assert.equal(r.status, 401);
    assert.equal(r.json.error, 'CSR_SIG_INVALID');
  } finally { await run.close(); }
});

test('边界：公钥 JWK 不得携带私钥字段 d；非 P-256 拒绝', async () => {
  const run = await startApp();
  try {
    const safe = await login(run.url, 'safeA');
    const code = (await httpJson(run.url, 'POST', '/api/admin/register-codes',
      { token: safe, body: { roles: ['supervisor'] } })).json.code;
    const keys = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const body = (await csrFor(run.url, code, '机', keys)).body;

    body.public_jwk.d = 'leaked';
    let r = await httpJson(run.url, 'POST', '/api/terminal/register', { body });
    assert.equal(r.json.error, 'BAD_PUBLIC_KEY');

    const code2 = (await httpJson(run.url, 'POST', '/api/admin/register-codes',
      { token: safe, body: { roles: ['supervisor'] } })).json.code;
    const body2 = (await csrFor(run.url, code2, '机2', keys)).body;
    // 去掉 crv：结构校验先于签名验证
    delete body2.public_jwk.crv;
    const r2 = await httpJson(run.url, 'POST', '/api/terminal/register', { body: body2 });
    assert.equal(r2.json.error, 'BAD_PUBLIC_KEY');
  } finally { await run.close(); }
});

test('边界：未知动作/非法会话/非法摘要/越权角色都拒绝', async () => {
  const run = await startApp();
  try {
    const safe = await login(run.url, 'safeA');
    const code = (await httpJson(run.url, 'POST', '/api/admin/register-codes',
      { token: safe, body: { roles: ['supervisor'] } })).json.code;
    const term = new BrowserTerminal(run.url);
    await term.registerOk(code);
    const bd = await sha256Hex({ x: 1 });

    let r = await term.challenge({ action: 'demolish.building',
      sessionId: 'SESS-B-1', role: 'supervisor', bodyDigest: bd });
    assert.equal(r.json.error, 'ACTION_UNKNOWN');

    r = await term.challenge({ action: 'shift.handoff',
      sessionId: 'bad session', role: 'supervisor', bodyDigest: bd });
    assert.equal(r.json.error, 'BAD_SESSION');

    r = await term.challenge({ action: 'shift.handoff',
      sessionId: 'SESS-B-2', role: 'supervisor', bodyDigest: 'not-a-hex-digest' });
    assert.equal(r.json.error, 'BAD_DIGEST');

    // inspector 不在该证书角色集
    r = await term.challenge({ action: 'steel.acceptance',
      sessionId: 'SESS-B-3', role: 'inspector', bodyDigest: bd });
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'ROLE_NOT_ALLOWED');
  } finally { await run.close(); }
});

test('边界：管理接口必须登录且角色正确；审计接口拒绝站点管理员', async () => {
  const run = await startApp();
  try {
    const noAuth = await httpJson(run.url, 'GET', '/api/admin/devices');
    assert.equal(noAuth.status, 401);
    const safe = await login(run.url, 'safeA');
    const aud = await login(run.url, 'auditor');
    // 审计员不能访问管理接口
    const cross = await httpJson(run.url, 'GET', '/api/admin/devices', { token: aud });
    assert.equal(cross.status, 403);
    // 管理员不能访问审计接口
    const cross2 = await httpJson(run.url, 'GET', '/api/audit', { token: safe });
    assert.equal(cross2.status, 403);
    // 错误密码
    const bad = await httpJson(run.url, 'POST', '/api/login',
      { body: { username: 'safeA', password: 'wrong' } });
    assert.equal(bad.status, 401);
  } finally { await run.close(); }
});

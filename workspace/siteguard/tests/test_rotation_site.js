/**
 * 场景 8：证书轮换——旧密钥只能核对历史、不能领新挑战；新密钥正常落款；
 *         轮换授权一次性、重启后代次信息存活。
 * 场景 10：跨站点账号不能查看或管理别处设备（含枚举防护与中性审计）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  startApp, httpJson, login, sha256Hex, genTerminalKeys, BrowserTerminal,
} from './helpers.js';

async function issueCode(base, token, roles = ['supervisor', 'inspector']) {
  const r = await httpJson(base, 'POST', '/api/admin/register-codes',
    { token, body: { roles, minutes: 60 } });
  assert.equal(r.status, 200);
  return r.json.code;
}

async function registerOne(base, code, label = '现场平板') {
  const term = new BrowserTerminal(base, { label });
  const reg = await term.registerOk(code);
  assert.equal(reg.status, 200);
  return term;
}

test('场景8a：轮换后新证书代次+1，旧密钥不能领挑战但可核对历史，新密钥可落款', async () => {
  const app = await startApp();
  try {
    const safe = await login(app.url, 'safeA');
    const term = await registerOne(app.url, await issueCode(app.url, safe));
    const bd = await sha256Hex({ doc: '轮换前的浇筑', k: 1 });

    // 轮换前先落一笔历史记录
    const tok0 = (await term.challenge({ action: 'concrete.pour',
      sessionId: 'SESS-ROT-PRE', role: 'supervisor', bodyDigest: bd })).json;
    const pre = await term.signSubmit(tok0);
    assert.equal(pre.status, 200);
    const oldCert = term.cert;
    const oldKeys = term.keys;

    // 管理员生成一次性轮换授权
    const prep = await httpJson(app.url, 'POST', '/api/admin/certificates/rotate',
      { token: safe, body: { cert_id: term.cert.payload.cert_id } });
    assert.equal(prep.status, 200);
    assert.match(prep.json.rotation_nonce, /^[0-9a-f]{24}$/);

    // 终端用旧私钥+新私钥双签完成轮换
    const newKeys = await genTerminalKeys();
    const rot = await term.rotate(prep.json.rotation_nonce, newKeys);
    assert.equal(rot.status, 200);
    assert.equal(rot.json.gen, 2);
    assert.equal(term.cert.payload.gen, 2);

    // 旧密钥不能再领取挑战
    const oldCh = await httpJson(app.url, 'POST', '/api/terminal/challenge', { body: {
      cert: oldCert, action: 'concrete.pour', session_id: 'SESS-OLD-NEW',
      role: 'supervisor', body_digest: bd,
    } });
    assert.equal(oldCh.status, 403);
    assert.equal(oldCh.json.error, 'CERT_ROTATED');

    // 旧密钥仍能核对轮换前的历史记录，且库外验签全部通过
    const hist = await term.fetchRecord(pre.json.record_id, oldKeys, oldCert);
    assert.equal(hist.status, 200);
    assert.equal(hist.json.verification.ok, true);

    // 旧密钥不能取别人/新证书的记录
    const newBd = await sha256Hex({ doc: '轮换后的浇筑', k: 2 });
    const tok1 = (await term.challenge({ action: 'concrete.pour',
      sessionId: 'SESS-ROT-POST', role: 'supervisor', bodyDigest: newBd })).json;
    const post = await term.signSubmit(tok1);
    assert.equal(post.status, 200);
    const cross = await term.fetchRecord(post.json.record_id, oldKeys, oldCert);
    assert.equal(cross.status, 404);

    // 轮换授权只能成功使用一次：再交一次即稳定拒绝
    const again = await httpJson(app.url, 'POST', '/api/terminal/rotate', { body: {
      rotation_nonce: prep.json.rotation_nonce,
      new_public_jwk: rot.json.cert.payload.public_jwk,
      old_sig: 'x', new_sig: 'y',
    } });
    assert.equal(again.status, 409);
    assert.equal(again.json.error, 'ROTATION_NONCE_USED');

    // 管理端设备视图含两代证书，状态分别为 rotated / active
    const devs = await httpJson(app.url, 'GET', '/api/admin/devices', { token: safe });
    const d = devs.json.find((x) => x.device_id === term.deviceId);
    assert.equal(d.certificates.length, 2);
    assert.equal(d.certificates.find((c) => c.gen === 1).status, 'rotated');
    assert.equal(d.certificates.find((c) => c.gen === 2).status, 'active');
  } finally { await app.close(); }
});

test('场景8b：轮换必须同时证明旧私钥与新私钥；伪造授权码/已隔离设备均拒绝', async () => {
  const app = await startApp();
  try {
    const safe = await login(app.url, 'safeA');
    const term = await registerOne(app.url, await issueCode(app.url, safe));
    const newKeys = await genTerminalKeys();

    // 不存在的授权码
    const bad = await httpJson(app.url, 'POST', '/api/terminal/rotate', { body: {
      rotation_nonce: 'deadbeef'.repeat(3),
      new_public_jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
      old_sig: 'a', new_sig: 'b',
    } });
    assert.equal(bad.status, 404);
    assert.equal(bad.json.error, 'ROTATION_NONCE_INVALID');

    const prep = (await httpJson(app.url, 'POST', '/api/admin/certificates/rotate',
      { token: safe, body: { cert_id: term.cert.payload.cert_id } })).json;

    // 持有效授权但新私钥签名是伪造的 → 拒绝，且授权不被消费
    const jwk = await (await import('node:crypto')).webcrypto.subtle
      .exportKey('jwk', newKeys.publicKey);
    const newPub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
    const csrObj = { alg: 'SG-ROTATION-CSR/v1', rotation_nonce: prep.rotation_nonce,
      old_cert_id: term.cert.payload.cert_id, device_id: term.deviceId,
      new_public_jwk: newPub };
    const { subtle } = await import('node:crypto').then((m) => m.webcrypto);
    const enc = new TextEncoder();
    const { canonicalize } = await import('../src/canonical.js');
    const oldSig = Buffer.from(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' },
      term.keys.privateKey, enc.encode(canonicalize(csrObj)))).toString('base64url');
    const tampered = await httpJson(app.url, 'POST', '/api/terminal/rotate', { body: {
      rotation_nonce: prep.rotation_nonce, new_public_jwk: newPub,
      old_sig: oldSig, new_sig: 'Z'.repeat(43),
    } });
    assert.equal(tampered.status, 401);
    assert.equal(tampered.json.error, 'ROTATION_SIG_INVALID');

    // 双签补齐后成功（证明伪造尝试没有消费一次性授权）
    const ok = await term.rotate(prep.rotation_nonce, newKeys);
    assert.equal(ok.status, 200);
    assert.equal(ok.json.gen, 2);

    // 隔离后不可再颁发轮换授权
    await httpJson(app.url, 'POST', '/api/admin/devices/quarantine',
      { token: safe, body: { device_id: term.deviceId, reason: '遗失' } });
    const prep2 = await httpJson(app.url, 'POST', '/api/admin/certificates/rotate',
      { token: safe, body: { cert_id: term.cert.payload.cert_id } });
    assert.equal(prep2.status, 403);
    assert.equal(prep2.json.error, 'DEVICE_QUARANTINED');
  } finally { await app.close(); }
});

test('场景10：跨站点管理员看不到/列不到/操作不了别处设备，错误信息不可枚举', async () => {
  const app = await startApp();
  try {
    const safeA = await login(app.url, 'safeA');
    const safeB = await login(app.url, 'safeB');

    const termA = await registerOne(app.url, await issueCode(app.url, safeA), '甲站平板');
    const termB = await registerOne(app.url, await issueCode(app.url, safeB,
      ['supervisor']), '乙站平板');

    // 设备列表严格按站点
    const devsA = await httpJson(app.url, 'GET', '/api/admin/devices', { token: safeA });
    const devsB = await httpJson(app.url, 'GET', '/api/admin/devices', { token: safeB });
    assert.deepEqual(devsA.json.map((d) => d.device_id), [termA.deviceId]);
    assert.deepEqual(devsB.json.map((d) => d.device_id), [termB.deviceId]);

    // B 站管理员操作 A 站设备：404（不是 403，避免暴露存在性）
    const q = await httpJson(app.url, 'POST', '/api/admin/devices/quarantine',
      { token: safeB, body: { device_id: termA.deviceId, reason: '越权' } });
    assert.equal(q.status, 404);
    assert.equal(q.json.error, 'DEVICE_NOT_FOUND');

    // B 站管理员对 A 站证书准备轮换：404
    const rot = await httpJson(app.url, 'POST', '/api/admin/certificates/rotate',
      { token: safeB, body: { cert_id: termA.cert.payload.cert_id } });
    assert.equal(rot.status, 404);
    assert.equal(rot.json.error, 'CERT_NOT_FOUND');

    // B 站管理员看不到 A 站记录
    const bd = await sha256Hex({ x: 1 });
    const tok = (await termA.challenge({ action: 'shift.handoff',
      sessionId: 'SESS-SITE-A-1', role: 'supervisor', bodyDigest: bd })).json;
    await termA.signSubmit(tok);
    const recsB = await httpJson(app.url, 'GET', '/api/admin/records', { token: safeB });
    assert.equal(recsB.json.length, 0);

    // 注册码列表也不互见（且不回显明文码与站点编码）
    const codesB = await httpJson(app.url, 'GET', '/api/admin/register-codes', { token: safeB });
    assert.equal(codesB.json.length, 1);
    assert.ok(codesB.json.every((c) => c.code_ref));
    assert.ok(!JSON.stringify(codesB.json).includes('SITE-'));

    // 普通站点管理员不能访问中性审计
    const auditA = await httpJson(app.url, 'GET', '/api/audit', { token: safeA });
    assert.equal(auditA.status, 403);
  } finally { await app.close(); }
});

test('场景10补充：审计页面只显示中性编号（分区/编号），不含站点、账号、正文', async () => {
  const app = await startApp();
  try {
    const safeA = await login(app.url, 'safeA');
    const auditor = await login(app.url, 'auditor');
    const term = await registerOne(app.url, await issueCode(app.url, safeA));
    const bd = await sha256Hex({ secret: '本句正文不应出现在审计里', n: 9 });
    const tok = (await term.challenge({ action: 'safety.briefing',
      sessionId: 'SESS-AUDIT-01', role: 'supervisor', bodyDigest: bd })).json;
    const sub = await term.signSubmit(tok);
    assert.equal(sub.status, 200);

    const audit = await httpJson(app.url, 'GET', '/api/audit?limit=20', { token: auditor });
    assert.equal(audit.status, 200);
    const flat = JSON.stringify(audit.json);
    // 永不出现：站点编码、管理员账号、原始正文
    assert.ok(!flat.includes('SITE-A'), '审计中不得出现站点编码');
    assert.ok(!flat.includes('safeA'), '审计中不得出现管理员账号');
    assert.ok(!flat.includes('本句正文'), '审计中不得出现正文内容');
    assert.ok(!flat.includes(bd), '审计中不得出现正文摘要原文');
    // 出现的是中性分区 P-1/P-2 与编号
    assert.ok(audit.json.some((a) => a.partition === 'P-1'));
    assert.ok(audit.json.some((a) => a.type === 'actionSigned' &&
      a.refs.record === sub.json.record_id));
  } finally { await app.close(); }
});

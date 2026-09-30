import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeContext, startServer, httpJson } from './helpers.js';
import { verifyCredential } from '../src/credential.js';

async function seededServer() {
  const c = makeContext();
  c.createRule();
  c.createWaybill('WB-1', c.dev);
  c.svc.uploadFragment(c.dev, 'WB-1',
    c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5)));
  c.svc.uploadFragment(c.dev, 'WB-1',
    c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5)));
  c.db.close();
  const srv = await startServer(c.dbPath);
  const login = async (u) => (await httpJson(srv.url, 'POST', '/api/login',
    { body: { username: u, password: 'demo1234' } })).json.token;
  return { ...srv, ...c, login };
}

test('未登录 401；角色越权 403；错误密码 401', async () => {
  const s = await seededServer();
  try {
    let r = await httpJson(s.url, 'GET', '/api/quality/waybills');
    assert.equal(r.status, 401);
    const site = await s.login('site1');
    r = await httpJson(s.url, 'GET', '/api/quality/waybills', { token: site });
    assert.equal(r.status, 403);
    r = await httpJson(s.url, 'POST', '/api/login',
      { body: { username: 'qm1', password: 'wrong' } });
    assert.equal(r.status, 401);
    const me = await httpJson(s.url, 'GET', '/api/me', { token: await s.login('qm1') });
    assert.equal(me.json.role, 'quality');
  } finally { await s.close(); }
});

test('设备不能访问站点/质量接口；站点拿不到温度明细', async () => {
  const s = await seededServer();
  try {
    const dev = await s.login('dev1');
    assert.equal((await httpJson(s.url, 'GET', '/api/site/waybills', { token: dev })).status, 403);
    assert.equal((await httpJson(s.url, 'GET', '/api/quality/audit', { token: dev })).status, 403);
    const site = await s.login('site1');
    const r = await httpJson(s.url, 'GET', '/api/site/waybills', { token: site });
    assert.equal(r.status, 200);
    const blob = JSON.stringify(r.json);
    for (const w of ['rule', 'points', 'temp', 'fragment', 'gap', 'offset']) {
      assert.ok(!blob.toLowerCase().includes(w), '站点响应不得含 ' + w);
    }
  } finally { await s.close(); }
});

test('两个审核终端并发同时确认：恰好一个最终决定，另一方幂等返回原决定', async () => {
  const s = await seededServer();
  try {
    const t1 = await s.login('qm1');
    const wid = (await httpJson(s.url, 'GET', '/api/device/waybills', { token: t1 }))
      .json.find((w) => w.waybill_no === 'WB-1').id;
    // 两个审核终端 = 两个不同账号的会话
    const t2 = await s.login('qm2');
    const [a, b] = await Promise.all([
      httpJson(s.url, 'POST', `/api/quality/waybills/${wid}/confirm`,
        { token: t1, body: { disposition: 'accept', reason: '终端一' } }),
      httpJson(s.url, 'POST', `/api/quality/waybills/${wid}/confirm`,
        { token: t2, body: { disposition: 'quarantine', reason: '终端二' } }),
    ]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    const flags = [a.json.idempotent, b.json.idempotent].sort();
    assert.deepEqual(flags, [false, true]);
    const winner = a.json.idempotent ? b.json : a.json;
    const loser = a.json.idempotent ? a.json : b.json;
    assert.equal(loser.decision.disposition, winner.decision.disposition);
    assert.notEqual(winner.decision.reason, undefined);
  } finally { await s.close(); }
});

test('撤销复核并发：部分唯一索引保证同一运单只有一个待复核申请', async () => {
  const s = await seededServer();
  try {
    const q1 = await s.login('qm1');
    const wid = (await httpJson(s.url, 'GET', '/api/quality/waybills', { token: q1 }))
      .json.find((w) => w.waybill_no === 'WB-1').id;
    await httpJson(s.url, 'POST', `/api/quality/waybills/${wid}/confirm`,
      { token: q1, body: { disposition: 'accept', reason: 'ok' } });
    const [a, b] = await Promise.all([
      httpJson(s.url, 'POST', `/api/quality/waybills/${wid}/revoke`,
        { token: q1, body: { reason: '理由甲' } }),
      httpJson(s.url, 'POST', `/api/quality/waybills/${wid}/revoke`,
        { token: q1, body: { reason: '理由甲' } }),
    ]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.notEqual(a.json.idempotent, b.json.idempotent);
  } finally { await s.close(); }
});

test('凭据签发后可下载并在库外校验；分别篡改片段/规则/决定均失败', async () => {
  const s = await seededServer();
  try {
    const q1 = await s.login('qm1');
    const wid = (await httpJson(s.url, 'GET', '/api/quality/waybills', { token: q1 }))
      .json.find((w) => w.waybill_no === 'WB-1').id;
    await httpJson(s.url, 'POST', `/api/quality/waybills/${wid}/confirm`,
      { token: q1, body: { disposition: 'accept', reason: '全程合规' } });
    const issued = await httpJson(s.url, 'POST', `/api/quality/waybills/${wid}/credential`,
      { token: q1, body: {} });
    assert.equal(issued.status, 200);
    const env1 = issued.json.credential;
    // 重复签发幂等返回同一信封
    const issued2 = await httpJson(s.url, 'POST', `/api/quality/waybills/${wid}/credential`,
      { token: q1, body: {} });
    assert.equal(issued2.json.idempotent, true);
    assert.deepEqual(issued2.json.credential, env1);

    // 库外（只用模块公钥，不碰数据库）
    const pk = (await httpJson(s.url, 'GET', '/api/public-key')).json.public_jwk;
    const ok = verifyCredential(structuredClone(env1), pk);
    assert.equal(ok.ok, true);
    assert.equal(ok.final_disposition, 'accept');

    // HTTP 校验端点同样不查库（可传任意信封）
    const hr = await httpJson(s.url, 'POST', '/api/verify-credential', { body: { envelope: env1 } });
    assert.equal(hr.json.ok, true);

    const tamperCases = [
      (e) => { e.payload.fragments[0].points[0][1] = -99; },
      (e) => { e.payload.waybill.temperature_rule.temp_max_c = 20; },
      (e) => { e.payload.decision_versions[0].disposition = 'quarantine'; },
      (e) => { e.payload.analysis.n_breaches = 9; },
      (e) => { e.signature = Buffer.from('x').toString('base64'); },
    ];
    for (const t of tamperCases) {
      const bad = structuredClone(env1);
      t(bad);
      const r = verifyCredential(bad, pk);
      assert.equal(r.ok, false);
      assert.ok(Object.values(r.checks).some((v) => v === false) || r.reason);
    }
  } finally { await s.close(); }
});

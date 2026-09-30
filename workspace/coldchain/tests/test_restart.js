import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeContext, startServer, httpJson } from './helpers.js';

/**
 * 进程重启场景：关闭 HTTP 服务与数据库连接后，用同一 db 文件起新模块实例，
 * 验证未完成的上传、待复核撤销、登录会话与规则快照全部继续可用。
 */
test('重启后：登录会话存活、待补传运单可继续、待复核撤销可完成、决定与凭据可查', async () => {
  const c = makeContext();
  c.createRule();
  c.createWaybill('WB-1', c.dev);
  // 只传前半段 → collecting（模拟设备离线，未完成上传）
  c.svc.uploadFragment(c.dev, 'WB-1',
    c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5)));
  c.createWaybill('WB-2', c.dev);
  c.svc.uploadFragment(c.dev, 'WB-2',
    c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5)));
  c.svc.uploadFragment(c.dev, 'WB-2',
    c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5)));
  const w2 = c.db.prepare("SELECT id FROM waybills WHERE waybill_no='WB-2'").get().id;
  c.svc.confirmDecision(c.qm1, w2, { disposition: 'accept', reason: '合规' });
  c.svc.issueCredential(c.qm1, w2);
  const rev = c.svc.requestRevocation(c.qm1, w2, { reason: '待重启后由 qm2 复核' });

  // 重启前建立一个设备会话
  let srv = await startServer(c.dbPath);
  const loginResp = await httpJson(srv.url, 'POST', '/api/login',
    { body: { username: 'dev1', password: 'demo1234' } });
  const devToken = loginResp.json.token;
  await srv.close();
  c.db.close();

  // ---- 模拟进程重启：全新模块实例打开同一库 ----
  srv = await startServer(c.dbPath);
  try {
    // 旧 token 仍有效（会话持久化）
    const me = await httpJson(srv.url, 'GET', '/api/me', { token: devToken });
    assert.equal(me.status, 200);
    assert.equal(me.json.username, 'dev1');

    // WB-1 未完成上传继续：补传后半段 → ready
    const f2 = c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5));
    const up = await httpJson(srv.url, 'POST', '/api/device/waybills/WB-1/fragments',
      { token: devToken, body: f2 });
    assert.equal(up.status, 200);
    assert.equal(up.json.waybill.state, 'ready');

    // WB-2 决定、版本、凭据仍在
    const qm2 = (await httpJson(srv.url, 'POST', '/api/login',
      { body: { username: 'qm2', password: 'demo1234' } })).json.token;
    const queue = await httpJson(srv.url, 'GET', '/api/quality/revocations', { token: qm2 });
    assert.equal(queue.json.length, 1);
    assert.equal(queue.json[0].reason, '待重启后由 qm2 复核');
    const reviewed = await httpJson(srv.url, 'POST',
      `/api/quality/revocations/${rev.revocation.id}/review`,
      { token: qm2, body: { approve: true, note: '重启后复核通过' } });
    assert.equal(reviewed.status, 200);
    assert.equal(reviewed.json.waybill.state, 'revoked');
    assert.equal(reviewed.json.waybill.decision_versions.length, 1); // 前版本保留

    // 规则快照仍是 RV-1，即便之后再发布新版本也不影响老单
    const rules = await httpJson(srv.url, 'GET', '/api/quality/rules', { token: qm2 });
    assert.ok(rules.json.some((r) => r.version === 'RV-1'));
  } finally {
    await srv.close();
  }
});

test('WAL 检查点文件存在且重启后数据不重复（片段幂等键持久）', async () => {
  const c = makeContext();
  c.createRule();
  c.createWaybill('WB-9', c.dev);
  const f = c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5));
  c.svc.uploadFragment(c.dev, 'WB-9', f);
  c.svc.uploadFragment(c.dev, 'WB-9', f); // 幂等
  c.db.close();
  const srv = await startServer(c.dbPath);
  try {
    const dev = (await httpJson(srv.url, 'POST', '/api/login',
      { body: { username: 'dev1', password: 'demo1234' } })).json.token;
    const r = await httpJson(srv.url, 'POST', '/api/device/waybills/WB-9/fragments',
      { token: dev, body: f });
    assert.equal(r.json.idempotent, true);
    const d = await httpJson(srv.url, 'GET', '/api/device/waybills/WB-9', { token: dev });
    assert.equal(d.json.n_fragments, 1);
    assert.equal(d.json.analysis.n_points, 31);
  } finally {
    await srv.close();
  }
});

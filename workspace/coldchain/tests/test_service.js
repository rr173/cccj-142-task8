import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeContext } from './helpers.js';

function fresh() {
  const ctx = makeContext();
  ctx.createRule();
  return ctx;
}

test('创建运单即固化规则快照；之后发布新版本不影响老运单', () => {
  const c = fresh();
  c.createWaybill('WB-OLD', c.dev, { end: c.S + 30 * c.MIN });
  const old = c.svc.waybillDetailByNo('WB-OLD', c.dev);
  c.svc.createRule(c.qm2, {
    version: 'RV-2', temp_min_c: 3, temp_max_c: 7, max_breach_sec: 120,
    calib_offset_c: 0.5, active: true,
  });
  c.createWaybill('WB-NEW', c.dev, { end: c.S + 30 * c.MIN });
  const n = c.svc.waybillDetailByNo('WB-NEW', c.dev);
  assert.deepEqual(old.rule_snapshot, {
    version: 'RV-1', temp_min_c: 2, temp_max_c: 8, max_breach_sec: 300, calib_offset_c: 0 });
  assert.equal(n.rule_snapshot.version, 'RV-2');
  assert.equal(n.rule_snapshot.max_breach_sec, 120);
});

test('创建运单幂等：同号重试返回原单；同号不同参数冲突', () => {
  const c = fresh();
  const a = c.createWaybill('WB-1', c.dev, { end: c.S + 30 * c.MIN });
  const b = c.createWaybill('WB-1', c.dev, { end: c.S + 30 * c.MIN });
  assert.equal(a.id, b.id);
  assert.throws(() => c.createWaybill('WB-1', c.dev, { end: c.S + 40 * c.MIN }),
    (e) => e.code === 'WAYBILL_NO_CONFLICT');
});

test('同标识同正文幂等返回原结果（乱序补传）；同标识不同正文拒绝', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev, { end: c.S + 60 * c.MIN });
  const f = c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5));
  const r1 = c.svc.uploadFragment(c.dev, 'WB-1', f);
  assert.equal(r1.idempotent, false);
  const r2 = c.svc.uploadFragment(c.dev2, 'WB-1', f); // 另一台设备重传
  assert.equal(r2.idempotent, true);
  assert.equal(r2.fragment_id, r1.fragment_id);
  const evil = { ...f, points: f.points.map((p, i) => (i === 2 ? [p[0], 9.9] : p)) };
  assert.throws(() => c.svc.uploadFragment(c.dev, 'WB-1', evil),
    (e) => e.code === 'FRAGMENT_CONTENT_CONFLICT');
  // 被拒后原数据未被覆盖
  const d = c.svc.waybillDetailByNo('WB-1', c.dev);
  assert.equal(d.fragments[0].content_hash, r1.waybill.fragments[0].content_hash);
  assert.equal(d.fragments[0].points[2][1], 5);
});

test('重叠区间只在逐点相同时合并；不同温度冲突且片段不落库', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev, { end: c.S + 60 * c.MIN });
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F1', 0, 20, c.series(c.S, c.S + 20 * c.MIN, 5)));
  // 与 F1 在 10..20 分钟重叠，温度一致 → 合并，点数收敛
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F2', 10, 40, c.series(c.S + 10 * c.MIN, c.S + 40 * c.MIN, 5)));
  let d = c.svc.waybillDetailByNo('WB-1', c.dev);
  assert.equal(d.analysis.n_points, 41); // 0..40 分钟共 41 个唯一时刻
  assert.equal(d.fragments.length, 2);
  // F3 与已有点在 15 分钟温度冲突
  const badPts = c.series(c.S + 10 * c.MIN, c.S + 20 * c.MIN, 5);
  badPts[5][1] = 1.1;
  assert.throws(() => c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F3', 10, 20, badPts)),
    (e) => e.code === 'POINT_CONFLICT' && e.conflicts.length === 1);
  d = c.svc.waybillDetailByNo('WB-1', c.dev);
  assert.equal(d.fragments.length, 2); // 冲突片段整体未落库
});

test('片段未齐只能待补传；齐后转 ready，缺口不补温度', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev, { end: c.S + 60 * c.MIN });
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F1', 0, 20, c.series(c.S, c.S + 20 * c.MIN, 5)));
  let d = c.svc.waybillDetailByNo('WB-1', c.dev);
  assert.equal(d.state, 'collecting');
  assert.equal(d.analysis.complete, false);
  assert.equal(d.analysis.suggested_disposition, null);
  // 未齐不能确认
  assert.throws(() => c.svc.confirmDecision(c.qm1, d.id, { disposition: 'accept', reason: 'x' }),
    (e) => e.code === 'TIMELINE_INCOMPLETE');
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F2', 20, 60, c.series(c.S + 20 * c.MIN, c.S + 60 * c.MIN, 5)));
  d = c.svc.waybillDetailByNo('WB-1', c.dev);
  assert.equal(d.state, 'ready');
  assert.equal(d.analysis.complete, true);
});

test('重复确认只产生一个最终决定；重复返回原结果', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev);
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5)));
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5)));
  const w = c.db.prepare("SELECT id FROM waybills WHERE waybill_no='WB-1'").get();
  const r1 = c.svc.confirmDecision(c.qm1, w.id, { disposition: 'accept', reason: '合规' });
  assert.equal(r1.idempotent, false);
  assert.equal(r1.decision.revision, 1);
  const r2 = c.svc.confirmDecision(c.qm2, w.id, { disposition: 'quarantine', reason: '另一终端相反意见' });
  assert.equal(r2.idempotent, true);
  assert.equal(r2.decision.disposition, 'accept'); // 原决定不变
  assert.equal(c.db.prepare('SELECT COUNT(*) n FROM decision_versions WHERE waybill_id=?').get(w.id).n, 1);
});

test('已有最终决定后补传新片段 → 冲突；幂等重传仍允许', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev);
  const f1 = c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5));
  c.svc.uploadFragment(c.dev, 'WB-1', f1);
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5)));
  const w = c.db.prepare("SELECT id FROM waybills WHERE waybill_no='WB-1'").get();
  c.svc.confirmDecision(c.qm1, w.id, { disposition: 'accept', reason: '合规' });
  assert.throws(
    () => c.svc.uploadFragment(c.dev, 'WB-1',
      c.frag('F3', 25, 28, c.series(c.S + 25 * c.MIN, c.S + 28 * c.MIN, 5))),
    (e) => e.code === 'EVIDENCE_SEALED');
  // 原片段同正文重传仍然幂等
  assert.equal(c.svc.uploadFragment(c.dev, 'WB-1', f1).idempotent, true);
});

test('撤销必须另一名质量管理员复核，前后版本都保留；驳回恢复原决定', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev);
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5)));
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5)));
  const w = c.db.prepare("SELECT id FROM waybills WHERE waybill_no='WB-1'").get();
  c.svc.confirmDecision(c.qm1, w.id, { disposition: 'accept', reason: '初判合规' });
  const rr = c.svc.requestRevocation(c.qm1, w.id, { reason: '新证据线索' });
  assert.equal(rr.idempotent, false);
  // 重复申请幂等
  assert.equal(c.svc.requestRevocation(c.qm1, w.id, { reason: '新证据线索' }).idempotent, true);
  // 复核期间不能做新决定
  assert.throws(() => c.svc.confirmDecision(c.qm2, w.id, { disposition: 'quarantine', reason: '抢决定' }),
    (e) => e.code === 'REVOCATION_IN_REVIEW');
  // 同人复核被拒
  assert.throws(() => c.svc.reviewRevocation(c.qm1, rr.revocation.id, { approve: true }),
    (e) => e.code === 'REVIEWER_MUST_DIFFER');
  // 另一人驳回 → 回到 decided，原决定有效
  const rej = c.svc.reviewRevocation(c.qm2, rr.revocation.id, { approve: false, note: '理由不足' });
  assert.equal(rej.revocation.state, 'rejected');
  assert.equal(rej.waybill.state, 'decided');
  // 再次申请并批准 → revoked → 重新决定产生 r2，r1 保留
  const rr2 = c.svc.requestRevocation(c.qm2, w.id, { reason: '设备校准证书过期' });
  const ap = c.svc.reviewRevocation(c.qm1, rr2.revocation.id, { approve: true, note: '同意' });
  assert.equal(ap.waybill.state, 'revoked');
  const r2 = c.svc.confirmDecision(c.qm2, w.id, { disposition: 'quarantine', reason: '重新判定隔离' });
  assert.equal(r2.decision.revision, 2);
  assert.equal(r2.decision.revokes_revision, 1);
  const d = c.svc.waybillDetailById(w.id, c.qm1);
  assert.equal(d.decision_versions.length, 2);
  assert.equal(d.decision_versions[0].disposition, 'accept');
  assert.equal(d.decision_versions[1].disposition, 'quarantine');
});

test('撤销批准后证据集仍封冻：新片段冲突（版本链不靠补片段改写）', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev);
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5)));
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5)));
  const w = c.db.prepare("SELECT id FROM waybills WHERE waybill_no='WB-1'").get();
  c.svc.confirmDecision(c.qm1, w.id, { disposition: 'accept', reason: '合规' });
  const rr = c.svc.requestRevocation(c.qm1, w.id, { reason: 'x' });
  c.svc.reviewRevocation(c.qm2, rr.revocation.id, { approve: true });
  assert.throws(
    () => c.svc.uploadFragment(c.dev, 'WB-1',
      c.frag('F9', 25, 28, c.series(c.S + 25 * c.MIN, c.S + 28 * c.MIN, 5))),
    (e) => e.code === 'EVIDENCE_SEALED');
});

test('越界超阈值形成 quarantine 建议，质量页可见全部明细，站点只见三态', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev);
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5)));
  const hot = {};
  for (let m = 10; m <= 16; m++) hot[m] = 9; // F2 相对 0..30 内 10..16
  c.svc.uploadFragment(c.dev, 'WB-1',
    c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5, hot)));
  const d = c.svc.waybillDetailByNo('WB-1', c.qm1);
  assert.equal(d.analysis.complete, true);
  assert.equal(d.analysis.suggested_disposition, 'quarantine');
  assert.equal(d.analysis.n_breaches, 1);
  assert.equal(d.analysis.events[0].duration_sec, 360);
  const site = c.svc.siteViewByNo('WB-1');
  assert.deepEqual(Object.keys(site).sort(), ['reason', 'receivable', 'status', 'waybill_no']);
  assert.equal(site.status, 'PENDING_REVIEW');
  assert.equal(site.receivable, null);
  // 确认后站点变为不可接收，且无温度/规则字段
  const w = c.db.prepare("SELECT id FROM waybills WHERE waybill_no='WB-1'").get();
  c.svc.confirmDecision(c.qm1, w.id, { disposition: 'quarantine', reason: '超限' });
  const s2 = c.svc.siteViewByNo('WB-1');
  assert.equal(s2.receivable, false);
  assert.ok(!JSON.stringify(s2).includes('9'));
});

test('盲态守门：治疗组/分配臂/批号等词在任何输入中被拒', () => {
  const c = fresh();
  for (const bad of ['WB-arm-A', 'WB-治疗组', 'lot-123 批次']) {
    assert.throws(() => c.createWaybill(bad, c.dev), (e) => e.code === 'NON_NEUTRAL_CONTENT');
  }
  c.createWaybill('WB-1', c.dev);
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F1', 0, 30, c.series(c.S, c.S + 30 * c.MIN, 5)));
  c.svc.uploadFragment(c.dev, 'WB-1', c.frag('F2', 30, 60, c.series(c.S + 30 * c.MIN, c.S + 60 * c.MIN, 5)));
  const w = c.db.prepare("SELECT id FROM waybills WHERE waybill_no='WB-1'").get();
  assert.throws(() => c.svc.confirmDecision(c.qm1, w.id,
    { disposition: 'accept', reason: '按批号兼容放行' }), (e) => e.code === 'NON_NEUTRAL_CONTENT');
});

test('传感器编号不一致的片段拒绝', () => {
  const c = fresh();
  c.createWaybill('WB-1', c.dev, { sensor: 'SN-1' });
  assert.throws(() => c.svc.uploadFragment(c.dev, 'WB-1',
    { ...c.frag('F1', 0, 10, c.series(c.S, c.S + 10 * c.MIN, 5)), sensor_no: 'SN-OTHER' }),
  (e) => e.code === 'SENSOR_MISMATCH');
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeTimeline, canonicalJSON, fragmentContentHash, mergePoints,
  normalizeFragment,
} from '../src/engine.js';

const S = Date.parse('2026-09-27T08:00:00Z');
const MIN = 60_000;
const iso = (ms) => new Date(ms).toISOString();
const pts = (base, n, over = {}, start = S) =>
  Array.from({ length: n }, (_, i) => [start + i * MIN, over[i] ?? base]);
const rule = { temp_min_c: 2, temp_max_c: 8, max_breach_sec: 300, calib_offset_c: 0 };
const wb = { waybill_no: 'WB-X', sensor_no: 'SN', expected_start: iso(S), expected_end: iso(S + 60 * MIN) };

test('规范化 JSON 键序无关，片段哈希与表示差异无关', () => {
  const f1 = normalizeFragment({ fragment_no: 'F', interval_start: iso(S), interval_end: iso(S + 10 * MIN),
    points: [[S, 2], [S + MIN, 2.0]] });
  assert.equal(canonicalJSON({ a: 1, b: 2 }), canonicalJSON({ b: 2, a: 1 }));
  // 2 与 2.0、不同键序的区间写法都得到同哈希
  const f2 = normalizeFragment({ interval_end: iso(S + 10 * MIN), interval_start: iso(S),
    points: [[S + MIN, 2], [S, 2]], fragment_no: 'F' });
  assert.equal(fragmentContentHash(f1), fragmentContentHash(f2));
  // 改一个温度值哈希必变
  const f3 = { ...f1, points: f1.points.map((p, i) => i === 0 ? [p[0], 2.1] : p) };
  assert.notEqual(fragmentContentHash(f1), fragmentContentHash(f3));
});

test('片段校验：空点、乱序时间字符串可排序、重复时刻、非法温度、点越界均拒绝', () => {
  const bad = [
    { fragment_no: 'F', interval_start: iso(S), interval_end: iso(S + MIN), points: [] },
    { fragment_no: 'F', interval_start: iso(S), interval_end: iso(S + 2 * MIN),
      points: [[S, 5], [S, 6]] },
    { fragment_no: 'F', interval_start: iso(S + MIN), interval_end: iso(S),
      points: [[S + MIN, 5]] },
    { fragment_no: 'F', interval_start: iso(S), interval_end: iso(S + MIN),
      points: [[S, NaN]] },
    { fragment_no: 'F', interval_start: iso(S), interval_end: iso(S + MIN),
      points: [[S, 5], [S + 2 * MIN, 5]] }, // 末点超出声明区间
  ];
  for (const b of bad) {
    assert.throws(() => normalizeFragment(b), (e) => e.code === 'BAD_FRAGMENT');
  }
});

test('重叠区间：逐点相同合并收敛为一个点，不同则全部冲突', () => {
  const a = [[S, 5], [S + MIN, 6], [S + 2 * MIN, 7]].map((p) => [...p, 'F1']);
  const f2 = { points: [[S + MIN, 6], [S + 2 * MIN, 7], [S + 3 * MIN, 5]] };
  const r = mergePoints(a, f2, 'F2');
  assert.equal(r.merged.length, 4); // 两个重合点收敛
  assert.throws(() => mergePoints(a, { points: [[S + MIN, 6.5]] }, 'F3'), (e) => {
    assert.equal(e.conflicts.length, 1);
    assert.equal(e.conflicts[0].existing_temp_c, 6);
    assert.equal(e.conflicts[0].incoming_temp_c, 6.5);
    return true;
  });
});

test('缺口类型：前置/中间/尾部，缺测绝不补点', () => {
  const frags = [
    { fragment_no: 'F1', interval_start: iso(S + 5 * MIN), interval_end: iso(S + 15 * MIN),
      points: pts(5, 11, {}, S + 5 * MIN) },
    { fragment_no: 'F2', interval_start: iso(S + 40 * MIN), interval_end: iso(S + 50 * MIN),
      points: pts(5, 11, {}, S + 40 * MIN) },
  ];
  const a = analyzeTimeline(wb, rule, frags);
  assert.equal(a.complete, false);
  assert.equal(a.n_points, 22);
  const types = a.gaps.map((g) => g.type).sort();
  assert.deepEqual(types, ['internal', 'leading', 'trailing']);
  assert.equal(a.suggested_disposition, null); // 不完整不出建议
});

test('连续越界按实际采样时刻计算；缺口打断连续段，超阈值才记 breach', () => {
  // 08:01-08:04 越界 4 分钟（240s ≤ 300s 不超），中间缺 08:20-08:40，
  // 之后 08:41-08:48 越界 7 分钟（420s > 300s 超限）——两段不得跨缺口连成一段
  const over1 = { 1: 9, 2: 9, 3: 9, 4: 9 };
  const over2 = {};
  for (let m = 1; m <= 8; m++) over2[m] = 9; // F2 相对分钟
  const frags = [
    { fragment_no: 'F1', interval_start: iso(S), interval_end: iso(S + 10 * MIN),
      points: pts(5, 11, over1) },
    { fragment_no: 'F2', interval_start: iso(S + 40 * MIN), interval_end: iso(S + 55 * MIN),
      points: pts(5, 16, over2, S + 40 * MIN) },
  ];
  const a = analyzeTimeline(wb, rule, frags);
  assert.equal(a.events.length, 2);
  assert.equal(a.events[0].duration_sec, 180);
  assert.equal(a.events[0].breach, false);
  assert.equal(a.events[1].duration_sec, 420);
  assert.equal(a.events[1].breach, true);
  assert.equal(a.n_breaches, 1);
});

test('校准偏移在判定前加到实测读数', () => {
  const r2 = { ...rule, calib_offset_c: 0.6 };
  const frags = [{ fragment_no: 'F', interval_start: iso(S), interval_end: iso(S + 60 * MIN),
    points: pts(7.6, 61) }]; // 7.6+0.6=8.2 > 8，全程持续 60 分钟 > 300s
  const a = analyzeTimeline(wb, r2, frags);
  assert.equal(a.n_breaches, 1);
  assert.equal(a.suggested_disposition, 'quarantine');
  const a0 = analyzeTimeline(wb, rule, frags); // 无偏移时 7.6 合规
  assert.equal(a0.n_breaches, 0);
  assert.equal(a0.suggested_disposition, 'accept');
});

test('完整合规时间线 → accept 建议；分析结果对片段到达顺序不敏感', () => {
  const mk = () => [
    { fragment_no: 'F2', interval_start: iso(S + 30 * MIN), interval_end: iso(S + 60 * MIN),
      points: pts(5, 31, {}, S + 30 * MIN) },
    { fragment_no: 'F1', interval_start: iso(S), interval_end: iso(S + 30 * MIN),
      points: pts(5, 31) },
  ];
  const a = analyzeTimeline(wb, rule, mk());
  assert.equal(a.complete, true);
  assert.equal(a.gaps.length, 0);
  assert.equal(a.n_points, 61);
  assert.equal(a.suggested_disposition, 'accept');
  const b = analyzeTimeline(wb, rule, mk().reverse());
  assert.deepEqual(JSON.parse(canonicalJSON(a.gaps)), JSON.parse(canonicalJSON(b.gaps)));
  assert.equal(a.suggested_disposition, b.suggested_disposition);
});

test('片段声明区间超出运单区间 → before/beyond 缺口，不完整', () => {
  const frags = [
    { fragment_no: 'F', interval_start: iso(S), interval_end: iso(S + 65 * MIN),
      points: pts(5, 66) },
  ];
  const a = analyzeTimeline(wb, rule, frags);
  assert.deepEqual(a.gaps.map((g) => g.type), ['beyond']);
  assert.equal(a.complete, false);
});

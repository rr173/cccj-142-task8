/**
 * 播种演示数据（幂等：已有用户则跳过）。
 *
 * 账号（密码均 demo1234）：
 *   dev1            运输设备
 *   qm1 / qm2       两名质量管理员（撤销复核必须不同人）
 *   site1           研究站点（只读）
 *
 * 演示运单（基准确时刻 2026-09-27 08:00Z，采样间隔 60s）：
 *   WB-1001 完整合规 → 已决定 accept，凭据已签发
 *   WB-1002 完整、连续越界超阈值 → 已决定 quarantine，qm1 已申请撤销待 qm2 复核
 *   WB-1003 只传了前段 → 缺口、待补传
 *   WB-1004 按新规则版本 RV-2026-09-20 固化（阈值更严），时间线完整待处置
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { initDb } from './db.js';
import { ColdChainService } from './service.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.COLDCHAIN_DB ||
  path.join(__dirname, '..', 'data', 'coldchain.db');

const T = (h, m = 0) => Date.parse(`2026-09-27T0${8 + h}:${String(m).padStart(2, '0')}:00Z`);
const iso = (ms) => new Date(ms).toISOString();

function pwHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.pbkdf2Sync(password, salt, 200_000, 32, 'sha256').toString('hex') };
}

/** 生成 60s 等间隔温度序列；overrides: { 分钟数: 温度 }。 */
function series(startMs, endMs, base, overrides = {}) {
  const pts = [];
  for (let t = startMs; t <= endMs; t += 60_000) {
    const minute = (t - startMs) / 60_000;
    pts.push([t, overrides[minute] ?? base]);
  }
  return pts;
}

export function seed(dbPath = DB_PATH) {
  const db = initDb(dbPath);
  const svc = new ColdChainService(db);
  const existing = db.prepare('SELECT COUNT(*) n FROM users').get().n;
  if (existing) {
    console.log('已有演示数据，跳过。');
    return;
  }
  const addUser = db.transaction((username, display, role) => {
    const { salt, hash } = pwHash('demo1234');
    db.prepare('INSERT INTO users(username,display,role,salt,pwhash) VALUES(?,?,?,?,?)')
      .run(username, display, role, salt, hash);
  });
  addUser('dev1', '运输设备 DEV-01', 'device');
  addUser('qm1', '质量管理员 秦敏一', 'quality');
  addUser('qm2', '质量管理员 秦敏二', 'quality');
  addUser('site1', '研究站点 S-01', 'site');

  const as = (u) => u;
  const dev = { username: 'dev1', role: 'device' };
  const qm1 = { username: 'qm1', role: 'quality' };
  const qm2 = { username: 'qm2', role: 'quality' };

  // 规则版本 1：2..8℃，连续越界容忍 300s，无偏移（WB-1001..1003 固化）
  svc.createRule(qm1, {
    version: 'RV-2026-09-01', temp_min_c: 2, temp_max_c: 8,
    max_breach_sec: 300, calib_offset_c: 0, active: true,
  });

  // ---- WB-1001：两段互补、合规，乱序补传（先传 F2 再传 F1） ----
  svc.createWaybill(dev, { waybill_no: 'WB-1001', sensor_no: 'SN-A100',
    expected_start: iso(T(0)), expected_end: iso(T(1)) });
  const p1b = series(T(0, 16), T(1), 5.0);
  svc.uploadFragment(dev, 'WB-1001', { fragment_no: 'F2',
    interval_start: iso(T(0, 16)), interval_end: iso(T(1)), points: p1b });
  const p1a = series(T(0), T(0, 15), 5.0);
  svc.uploadFragment(dev, 'WB-1001', { fragment_no: 'F1',
    interval_start: iso(T(0)), interval_end: iso(T(0, 16)), points: p1a });
  const w1 = db.prepare('SELECT id FROM waybills WHERE waybill_no=?').get('WB-1001').id;
  svc.confirmDecision(qm1, w1, { disposition: 'accept', reason: '全程温度在允许区间内' });
  svc.issueCredential(qm1, w1);

  // ---- WB-1002：08:18–08:24 持续 9℃（6 分钟 > 300s 阈值）→ 隔离；撤销待复核 ----
  svc.createWaybill(dev, { waybill_no: 'WB-1002', sensor_no: 'SN-A200',
    expected_start: iso(T(0)), expected_end: iso(T(0, 30)) });
  svc.uploadFragment(dev, 'WB-1002', { fragment_no: 'F1',
    interval_start: iso(T(0)), interval_end: iso(T(0, 16)),
    points: series(T(0), T(0, 15), 5.0) });
  const hot2 = {};
  for (let m = 2; m <= 8; m++) hot2[m] = 9.0; // F2 起于 08:16，相对第 2..8 分钟 = 全局 08:18..24
  svc.uploadFragment(dev, 'WB-1002', { fragment_no: 'F2',
    interval_start: iso(T(0, 16)), interval_end: iso(T(0, 30)),
    points: series(T(0, 16), T(0, 30), 5.0, hot2) });
  const w2 = db.prepare('SELECT id FROM waybills WHERE waybill_no=?').get('WB-1002').id;
  svc.confirmDecision(qm1, w2, { disposition: 'quarantine',
    reason: '连续越界 360s 超过 300s 限值' });
  svc.requestRevocation(qm1, w2, { reason: '设备厂商申诉该时段冷链车已启用应急冷源，申请复核' });

  // ---- WB-1003：只传了前 20 分钟 → 大段缺口，待补传 ----
  svc.createWaybill(dev, { waybill_no: 'WB-1003', sensor_no: 'SN-A300',
    expected_start: iso(T(0)), expected_end: iso(T(1)) });
  svc.uploadFragment(dev, 'WB-1003', { fragment_no: 'F1',
    interval_start: iso(T(0)), interval_end: iso(T(0, 20)),
    points: series(T(0), T(0, 20), 5.2) });

  // 规则版本 2：阈值收紧到 180s，校准偏移 +0.2（只影响之后创建的新运单）
  svc.createRule(qm2, {
    version: 'RV-2026-09-20', temp_min_c: 2, temp_max_c: 8,
    max_breach_sec: 180, calib_offset_c: 0.2, active: true,
  });

  // ---- WB-1004：新规则下 4 分钟越界（240s > 180s）→ 建议隔离，待处置 ----
  svc.createWaybill(dev, { waybill_no: 'WB-1004', sensor_no: 'SN-A400',
    expected_start: iso(T(0)), expected_end: iso(T(0, 30)) });
  const hot4 = {};
  for (let m = 10; m <= 14; m++) hot4[m] = 8.6; // F1 内相对分钟=全局分钟；+0.2 偏移后 8.8 > 8
  svc.uploadFragment(dev, 'WB-1004', { fragment_no: 'F1',
    interval_start: iso(T(0)), interval_end: iso(T(0, 16)),
    points: series(T(0), T(0, 15), 7.4, hot4) });
  svc.uploadFragment(dev, 'WB-1004', { fragment_no: 'F2',
    interval_start: iso(T(0, 16)), interval_end: iso(T(0, 30)),
    points: series(T(0, 16), T(0, 30), 7.4) });

  console.log('演示数据已播种:', dbPath);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  seed();
}

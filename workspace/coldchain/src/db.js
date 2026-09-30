/**
 * 数据库 schema、WAL 持久化与签名密钥初始化。
 *
 * 所有状态都落 SQLite（better-sqlite3 同步驱动）：
 *   - journal_mode=WAL + synchronous=FULL，进程被 kill 后已提交事务不丢、
 *     未提交事务不留半成品；
 *   - better-sqlite3 同一连接上的写天然串行，配合 IMMEDIATE 事务与条件 UPDATE，
 *     两个审核终端并发确认时只有一个事务能把状态从 ready 翻走。
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

export const SCHEMA_VERSION = 1;

export const SCHEMA = `
-- 用户与会话（角色：device 运输设备 / quality 质量管理员 / site 研究站点）
CREATE TABLE IF NOT EXISTS users(
  id          INTEGER PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  display     TEXT NOT NULL,
  role        TEXT NOT NULL CHECK(role IN ('device','quality','site')),
  salt        TEXT NOT NULL,
  pwhash      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions(
  token       TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id),
  created_at  TEXT NOT NULL
);

-- 温控规则版本。发布新版本后，老运单继续引用旧版本（rules 快照已固化在运单行），
-- 只有新运单默认引用 active 版本。
CREATE TABLE IF NOT EXISTS temp_rules(
  id              INTEGER PRIMARY KEY,
  version         TEXT NOT NULL UNIQUE,
  temp_min_c      REAL NOT NULL,           -- 允许温度下限（含），℃
  temp_max_c      REAL NOT NULL,           -- 允许温度上限（含），℃
  max_breach_sec  INTEGER NOT NULL,        -- 允许的最长连续越界时长，秒；超过即违规
  calib_offset_c  REAL NOT NULL,           -- 传感器校准偏移，判定前实测值 + 偏移
  active          INTEGER NOT NULL DEFAULT 0,
  created_by      TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  CHECK(temp_min_c < temp_max_c AND max_breach_sec >= 0)
);

-- 运单：运单号全程中性（不含任何药品、分组、批号信息）。
-- state:
--   collecting 收片段中（时间线不完整/有缺口）
--   ready      时间线完整，可复算，等待质量管理员处置
--   decided    已有最终处置（accept 可接收 / quarantine 隔离）
--   revoking   已请求撤销，等待另一名质量管理员复核
--   revoked    撤销通过后的中间态：原决定保留为历史版本，可基于完整时间线重新决定
CREATE TABLE IF NOT EXISTS waybills(
  id              INTEGER PRIMARY KEY,
  waybill_no      TEXT NOT NULL UNIQUE,    -- 中性运单号
  sensor_no       TEXT NOT NULL,           -- 传感器编号
  expected_start  TEXT NOT NULL,           -- 采样区间起点 ISO
  expected_end    TEXT NOT NULL,           -- 采样区间终点 ISO
  rule_id         INTEGER NOT NULL REFERENCES temp_rules(id),
  -- 规则快照：创建时固化，之后规则改版不影响本单
  rule_version    TEXT NOT NULL,
  rule_min_c      REAL NOT NULL,
  rule_max_c      REAL NOT NULL,
  rule_breach_sec INTEGER NOT NULL,
  rule_offset_c   REAL NOT NULL,
  state           TEXT NOT NULL DEFAULT 'collecting'
                  CHECK(state IN ('collecting','ready','decided','revoking','revoked')),
  created_by      TEXT NOT NULL,
  created_at      TEXT NOT NULL
);

-- 上传片段。UNIQUE(waybill_id, fragment_no) 是幂等/冲突判定的落点：
--   标识首次出现 → 插入；
--   标识已存在且 content_hash 相同 → 幂等，返回与上次完全相同的结果；
--   标识已存在但 content_hash 不同 → 409 FRAGMENT_CONTENT_CONFLICT，绝不静默覆盖。
CREATE TABLE IF NOT EXISTS fragments(
  id            INTEGER PRIMARY KEY,
  waybill_id    INTEGER NOT NULL REFERENCES waybills(id),
  fragment_no   TEXT NOT NULL,
  interval_start TEXT NOT NULL,
  interval_end   TEXT NOT NULL,
  n_points      INTEGER NOT NULL,
  points_json   TEXT NOT NULL,             -- [[epochMs, tempC], ...] 原始正文（质量管理员可见）
  content_hash  TEXT NOT NULL,             -- 对"采样正文"的哈希（不含上传顺序/时间）
  uploaded_by   TEXT NOT NULL,
  uploaded_at   TEXT NOT NULL,
  seq_no        INTEGER NOT NULL,          -- 到达顺序（乱序补传时不等于片段时间顺序）
  UNIQUE(waybill_id, fragment_no)
);

-- 逐点采样（拆行存储便于合并、审计与按点明细展示）。
-- 同一时刻（同运单）只允许一个温度值；重叠区间的重合时刻温度必须一致，
-- 否则插入阶段即报 409 POINT_CONFLICT，冲突点完整返回、不静默跳过。
CREATE TABLE IF NOT EXISTS sample_points(
  waybill_id  INTEGER NOT NULL REFERENCES waybills(id),
  t_ms        INTEGER NOT NULL,            -- 采样时刻 epoch 毫秒
  temp_c      REAL NOT NULL,               -- 原始读数（判定时才加校准偏移）
  fragment_id INTEGER NOT NULL REFERENCES fragments(id),
  PRIMARY KEY(waybill_id, t_ms)
);
CREATE INDEX IF NOT EXISTS idx_points_way ON sample_points(waybill_id, t_ms);

-- 最终处置版本：append-only。
--   revision=1 为首个决定；撤销后再次确认 → revision=2，revokes_revision=1。
-- 旧版本永不删除/覆盖（"保留前后版本"）。
CREATE TABLE IF NOT EXISTS decision_versions(
  id               INTEGER PRIMARY KEY,
  waybill_id       INTEGER NOT NULL REFERENCES waybills(id),
  revision         INTEGER NOT NULL,
  disposition      TEXT NOT NULL CHECK(disposition IN ('accept','quarantine')),
  reason           TEXT NOT NULL,
  analysis_json    TEXT NOT NULL,          -- 形成决定时的完整计算明细快照
  decided_by       TEXT NOT NULL,
  decided_at       TEXT NOT NULL,
  revokes_revision INTEGER,                -- 本版本取代的旧版本号（首个决定为 NULL）
  UNIQUE(waybill_id, revision)
);

-- 撤销申请：必须由另一名质量管理员复核。
-- (waybill_id, state='pending') 部分唯一索引：同一运单同时只允许一个待复核撤销，
-- 重复请求幂等返回原申请。
CREATE TABLE IF NOT EXISTS revocation_requests(
  id           INTEGER PRIMARY KEY,
  waybill_id   INTEGER NOT NULL REFERENCES waybills(id),
  revision     INTEGER NOT NULL,           -- 针对的决定版本
  reason       TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  state        TEXT NOT NULL CHECK(state IN ('pending','approved','rejected')),
  reviewed_by  TEXT,
  reviewed_at  TEXT,
  review_note  TEXT
);
-- 部分唯一索引 idx_one_pending_revocation 在 initDb 中按存在性创建（见下）

-- 不可变处置凭据：每个决定版本最多一份（UNIQUE(waybill_id, revision)）。
-- 凭据是自描述 JSON：含片段集合、规则版本、计算明细与决定，外层 Ed25519 签名，
-- 可在数据库之外（verify.js / 页面 / 其他系统）独立重算校验。
CREATE TABLE IF NOT EXISTS credentials(
  id           INTEGER PRIMARY KEY,
  cred_no      TEXT NOT NULL UNIQUE,
  waybill_id   INTEGER NOT NULL REFERENCES waybills(id),
  revision     INTEGER NOT NULL,
  envelope_json TEXT NOT NULL,
  issued_by    TEXT NOT NULL,
  issued_at    TEXT NOT NULL,
  UNIQUE(waybill_id, revision)
);

-- append-only 审计日志：所有写动作留痕。明细中严禁出现药品/分组/批号信息。
CREATE TABLE IF NOT EXISTS audit_log(
  id         INTEGER PRIMARY KEY,
  actor      TEXT,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL,                -- JSON
  created_at TEXT NOT NULL
);

-- 模块自身的 Ed25519 签名密钥（首启生成，随数据库一起持久化）
CREATE TABLE IF NOT EXISTS app_meta(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

export function open(dbPath) {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  }
  const db = new Database(dbPath);
  db.pragma('journal_mode=WAL');
  db.pragma('synchronous=FULL');
  db.pragma('foreign_keys=ON');
  db.pragma('busy_timeout=8000');
  return db;
}

export function initDb(dbPath) {
  const db = open(dbPath);
  try {
    db.exec(SCHEMA);
    // SQLite 解析器不支持 "CREATE INDEX IF NOT EXISTS ... WHERE"，手动幂等
    const hasIdx = db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_one_pending_revocation'").get();
    if (!hasIdx) {
      db.exec(`CREATE UNIQUE INDEX idx_one_pending_revocation
               ON revocation_requests(waybill_id) WHERE state='pending'`);
    }
    const insertMeta = db.prepare('INSERT OR IGNORE INTO app_meta(key,value) VALUES(?,?)');
    const tx = db.transaction(() => {
      insertMeta.run('schema_version', String(SCHEMA_VERSION));
      const hasKey = db.prepare("SELECT 1 FROM app_meta WHERE key='signing_private_jwk'").get();
      if (!hasKey) {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        // Node 的 JWK 私钥构造要求同时带 x，故完整保存私钥 JWK
        insertMeta.run('signing_private_jwk', JSON.stringify(privateKey.export({ format: 'jwk' })));
        insertMeta.run('signing_public_jwk', JSON.stringify(publicKey.export({ format: 'jwk' })));
      }
    });
    tx.immediate();
    return db;
  } catch (e) {
    db.close();
    throw e;
  }
}

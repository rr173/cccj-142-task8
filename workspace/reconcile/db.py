"""SQLite 持久化：许可快照只追加，执行声明只追加，对账版本不可改写。"""
import hashlib
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get(
    "RECONCILE_DB", os.path.join(os.path.dirname(__file__), "reconcile.db")
)
_init_lock = threading.Lock()
_initialized = False

SCHEMA = r"""
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS institutions(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  inst_id TEXT REFERENCES institutions(id),
  role TEXT NOT NULL CHECK(role IN ('compliance','site','subject')),
  login TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subjects(
  id TEXT PRIMARY KEY,
  inst_id TEXT NOT NULL REFERENCES institutions(id),
  name TEXT NOT NULL,
  user_id TEXT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS auth_tokens(
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cycles(
  id TEXT PRIMARY KEY,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK(ends_at > starts_at)
);

-- 许可引擎在发布瞬间导出的不可改写历史快照。
-- snapshot_version 是许可引擎的内容版本（同内容稳定），import_seq 是本模块导入序号。
CREATE TABLE IF NOT EXISTS permit_snapshots(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  permit_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  family TEXT NOT NULL,
  basis_version INTEGER NOT NULL,
  scope_json TEXT NOT NULL,
  allowed_purposes_json TEXT NOT NULL,
  effective_at TEXT NOT NULL,
  snapshot_version INTEGER NOT NULL,
  body_hash TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  UNIQUE(permit_id, basis_version, snapshot_version)
);
CREATE INDEX IF NOT EXISTS idx_permit_snap_query
  ON permit_snapshots(subject_id, family, effective_at);

-- 终止事件同样只能追加；不得用 UPDATE/DELETE 把“终止后执行”洗成当时有效。
CREATE TABLE IF NOT EXISTS permit_terminations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  permit_id TEXT NOT NULL,
  family TEXT NOT NULL,
  basis_version INTEGER NOT NULL,
  subject_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  terminated_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  snapshot_version INTEGER NOT NULL,
  imported_at TEXT NOT NULL,
  UNIQUE(permit_id, terminated_at, reason, snapshot_version)
);
CREATE INDEX IF NOT EXISTS idx_termination_query
  ON permit_terminations(permit_id, terminated_at);

-- 全部接收/拒绝尝试均留痕。同声明 id + 规范正文稳定返回同一接收回执。
CREATE TABLE IF NOT EXISTS claim_attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_id TEXT NOT NULL,
  version_no INTEGER,
  body_hash TEXT NOT NULL,
  accepted INTEGER NOT NULL,
  receipt TEXT,
  reject_code TEXT,
  batch_id TEXT,
  source_system TEXT,
  received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_claim ON claim_attempts(claim_id, body_hash, accepted);

CREATE TABLE IF NOT EXISTS claim_versions(
  claim_id TEXT NOT NULL,
  version_no INTEGER NOT NULL,
  source_system TEXT NOT NULL,
  source_claim_code TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  neutral_op TEXT NOT NULL,
  purpose TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  basis_family TEXT NOT NULL,
  basis_version INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  replaces_version INTEGER,
  received_at TEXT NOT NULL,
  PRIMARY KEY(claim_id, version_no),
  UNIQUE(claim_id, replaces_version)
);
CREATE INDEX IF NOT EXISTS idx_claims_query
  ON claim_versions(subject_id, occurred_at);

CREATE TABLE IF NOT EXISTS claim_current(
  claim_id TEXT PRIMARY KEY,
  current_version INTEGER NOT NULL,
  current_body_hash TEXT NOT NULL,
  receipt TEXT NOT NULL,
  first_received_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS import_batches(
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('accepted','rejected')),
  item_count INTEGER NOT NULL,
  reject_code TEXT,
  operator_id TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reconciliation_jobs(
  id TEXT PRIMARY KEY,
  cycle_id TEXT NOT NULL REFERENCES cycles(id),
  owner TEXT NOT NULL,
  lease_expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','published','failed')),
  published_version_id INTEGER,
  error TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  UNIQUE(cycle_id, id)
);
-- SQLite 部分唯一索引让同周期同时只有一个活动租约；失败/崩溃租约过期后才能接管。
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_job
  ON reconciliation_jobs(cycle_id) WHERE status='running';

CREATE TABLE IF NOT EXISTS reconciliation_versions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cycle_id TEXT NOT NULL REFERENCES cycles(id),
  version_no INTEGER NOT NULL,
  input_watermark_json TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  claim_count INTEGER NOT NULL,
  counts_json TEXT NOT NULL,
  published_at TEXT NOT NULL,
  UNIQUE(cycle_id, version_no)
);

CREATE TABLE IF NOT EXISTS reconciliation_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version_id INTEGER NOT NULL REFERENCES reconciliation_versions(id),
  cycle_id TEXT NOT NULL REFERENCES cycles(id),
  item_no INTEGER NOT NULL,
  claim_id TEXT NOT NULL,
  claim_version_no INTEGER NOT NULL,
  subject_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  neutral_op TEXT NOT NULL,
  purpose TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  basis_family TEXT NOT NULL,
  basis_version INTEGER NOT NULL,
  result TEXT NOT NULL CHECK(result IN (
    'explained','missing_basis','out_of_scope','post_termination','awaiting_late_material'
  )),
  matched_snapshot_id INTEGER,
  matched_basis_version INTEGER,
  matched_permit_id TEXT,
  detail_json TEXT NOT NULL,
  claim_body_hash TEXT NOT NULL,
  basis_snapshot_watermark INTEGER NOT NULL,
  UNIQUE(version_id, claim_id, claim_version_no)
);
CREATE INDEX IF NOT EXISTS idx_items_version ON reconciliation_items(version_id, result);
CREATE INDEX IF NOT EXISTS idx_items_site ON reconciliation_items(cycle_id, inst_id, result);
CREATE INDEX IF NOT EXISTS idx_items_subject ON reconciliation_items(cycle_id, subject_id);

CREATE TABLE IF NOT EXISTS dispositions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL REFERENCES reconciliation_items(id),
  version_id INTEGER NOT NULL,
  cycle_id TEXT NOT NULL,
  claim_id TEXT NOT NULL,
  resolution TEXT NOT NULL CHECK(resolution IN (
    'accepted_justified','documented_exception','corrective_action','escalated','dismissed'
  )),
  reason TEXT NOT NULL,
  adopted_snapshot_version INTEGER NOT NULL,
  decided_by TEXT NOT NULL,
  decided_at TEXT NOT NULL,
  review_status TEXT NOT NULL DEFAULT 'current'
    CHECK(review_status IN ('current','stale_pending_review')),
  stale_reason TEXT,
  marked_stale_at TEXT,
  review_note TEXT,
  reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_dispositions_item ON dispositions(item_id);
CREATE INDEX IF NOT EXISTS idx_dispositions_cycle ON dispositions(cycle_id, review_status);

CREATE TRIGGER IF NOT EXISTS trg_permit_snapshots_no_update
BEFORE UPDATE ON permit_snapshots
BEGIN SELECT RAISE(ABORT,'permit_snapshots are append-only historical records'); END;
CREATE TRIGGER IF NOT EXISTS trg_permit_snapshots_no_delete
BEFORE DELETE ON permit_snapshots
BEGIN SELECT RAISE(ABORT,'permit_snapshots cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS trg_terminations_no_update
BEFORE UPDATE ON permit_terminations
BEGIN SELECT RAISE(ABORT,'permit_terminations are append-only historical records'); END;
CREATE TRIGGER IF NOT EXISTS trg_terminations_no_delete
BEFORE DELETE ON permit_terminations
BEGIN SELECT RAISE(ABORT,'permit_terminations cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS trg_claim_versions_no_update
BEFORE UPDATE ON claim_versions
BEGIN SELECT RAISE(ABORT,'claim versions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_claim_versions_no_delete
BEFORE DELETE ON claim_versions
BEGIN SELECT RAISE(ABORT,'claim versions cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS trg_claim_attempts_no_update
BEFORE UPDATE ON claim_attempts
BEGIN SELECT RAISE(ABORT,'claim receipts cannot be rewritten'); END;
CREATE TRIGGER IF NOT EXISTS trg_claim_attempts_no_delete
BEFORE DELETE ON claim_attempts
BEGIN SELECT RAISE(ABORT,'claim receipts cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS trg_recon_versions_no_update
BEFORE UPDATE ON reconciliation_versions
BEGIN SELECT RAISE(ABORT,'published reconciliation versions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_recon_versions_no_delete
BEFORE DELETE ON reconciliation_versions
BEGIN SELECT RAISE(ABORT,'published reconciliation versions cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS trg_recon_items_no_update
BEFORE UPDATE ON reconciliation_items
BEGIN SELECT RAISE(ABORT,'reconciliation items are immutable version outputs'); END;
CREATE TRIGGER IF NOT EXISTS trg_recon_items_no_delete
BEFORE DELETE ON reconciliation_items
BEGIN SELECT RAISE(ABORT,'reconciliation items cannot be deleted'); END;
"""


def now_ms():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + (
        ".%03dZ" % int(time.time() * 1000 % 1000)
    )


def hash_pw(salt, password):
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def canonical_dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def claim_body_hash(payload):
    """声明正文指纹：传输字段和更正链字段除外，源系统只做语义映射。"""
    keys = (
        "source_system", "source_claim_code", "subject_id", "neutral_op", "purpose",
        "occurred_at", "basis_family", "basis_version", "payload",
    )
    body = {k: payload.get(k) for k in keys}
    return sha256_text(canonical_dumps(body))


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def begin_tx(conn):
    conn.execute("BEGIN IMMEDIATE")


def init_db():
    global _initialized
    with _init_lock:
        if _initialized:
            return
        conn = get_conn()
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()
        _initialized = True

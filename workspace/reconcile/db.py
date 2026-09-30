"""医疗行为事后对账模块的 SQLite 持久化层。

核心表全部围绕“不可改写事实”和“追加式新版本”设计：
- consent_snapshots / snapshot_entries 只追加，不更新、不删除；
- execution_claims 保留每一次声明与更正版本；
- reconciliation_versions / items 一经发布不可变；
- dispositions 保存原判断，后续只把复核状态置为待复核，不覆盖结论。
"""
import hashlib
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("RECONCILE_DB", os.path.join(os.path.dirname(__file__), "reconcile.db"))
_lock = threading.Lock()
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
  role TEXT NOT NULL CHECK(role IN ('compliance','site','participant')),
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

-- 许可引擎在某个时刻被对账模块读取并固化的历史快照。
-- 快照本身不可变；即便许可库后来撤销或修订，也只能再导入下一快照。
CREATE TABLE IF NOT EXISTS consent_snapshots(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_name TEXT NOT NULL,
  source_watermark TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  digest TEXT NOT NULL,
  UNIQUE(source_name, source_watermark)
);
CREATE TABLE IF NOT EXISTS snapshot_entries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id INTEGER NOT NULL REFERENCES consent_snapshots(id),
  entry_key TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  op TEXT NOT NULL,
  purpose TEXT NOT NULL,
  basis_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active','terminated')),
  granted_at TEXT NOT NULL,
  terminated_at TEXT,
  entry_json TEXT NOT NULL,
  UNIQUE(snapshot_id, entry_key)
);
CREATE INDEX IF NOT EXISTS idx_snapshot_lookup
  ON snapshot_entries(subject_id, op, purpose, basis_version, snapshot_id);

CREATE TABLE IF NOT EXISTS cycles(
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  cutoff_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- 同一 claim_id 的每次到达均追加；latest=1 的当前版本只能通过新更正产生。
CREATE TABLE IF NOT EXISTS execution_claims(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  supersedes_revision INTEGER,
  batch_id TEXT,
  source_system TEXT NOT NULL CHECK(source_system IN ('blood','imaging','medication','sample')),
  subject_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  op TEXT NOT NULL,
  purpose TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  arrived_at TEXT NOT NULL,
  basis_version TEXT NOT NULL,
  data_status TEXT NOT NULL DEFAULT 'complete'
    CHECK(data_status IN ('complete','awaiting_materials')),
  body TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  receipt TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('accepted','superseded')),
  created_at TEXT NOT NULL,
  UNIQUE(claim_id, revision),
  UNIQUE(claim_id, body_hash),
  UNIQUE(receipt)
);
CREATE INDEX IF NOT EXISTS idx_claims_cycle_lookup
  ON execution_claims(subject_id, occurred_at, claim_id, revision);

CREATE TABLE IF NOT EXISTS import_batches(
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('accepted','rejected')),
  inst_scope TEXT,
  error_code TEXT,
  error_message TEXT,
  claim_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

-- 周期版本：发布行先落盘并提交，之后进程即便退出也不能再产生同一版本的差异项。
CREATE TABLE IF NOT EXISTS reconciliation_versions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cycle_id TEXT NOT NULL REFERENCES cycles(id),
  version INTEGER NOT NULL,
  input_watermark TEXT NOT NULL,
  digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('published')),
  published_at TEXT NOT NULL,
  UNIQUE(cycle_id, version),
  UNIQUE(cycle_id, input_watermark)
);
CREATE TABLE IF NOT EXISTS reconciliation_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version_id INTEGER NOT NULL REFERENCES reconciliation_versions(id),
  claim_pk INTEGER NOT NULL REFERENCES execution_claims(id),
  claim_id TEXT NOT NULL,
  claim_revision INTEGER NOT NULL,
  subject_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  op TEXT NOT NULL,
  purpose TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  basis_version TEXT NOT NULL,
  result TEXT NOT NULL CHECK(result IN (
    'explained','missing_basis','out_of_scope','post_termination','awaiting_late_materials'
  )),
  reason TEXT NOT NULL,
  matched_snapshot_id INTEGER,
  matched_entry_key TEXT,
  item_json TEXT NOT NULL,
  UNIQUE(version_id, claim_pk)
);
CREATE INDEX IF NOT EXISTS idx_items_version_result
  ON reconciliation_items(version_id, result);
CREATE INDEX IF NOT EXISTS idx_items_subject
  ON reconciliation_items(subject_id, version_id);
CREATE INDEX IF NOT EXISTS idx_items_inst
  ON reconciliation_items(inst_id, version_id);

-- 追加式处置；新复核产生新行。老行 original_* 永不被改写。
CREATE TABLE IF NOT EXISTS dispositions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL REFERENCES reconciliation_items(id),
  version_id INTEGER NOT NULL REFERENCES reconciliation_versions(id),
  cycle_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  inst_id TEXT NOT NULL,
  adopted_snapshot_id INTEGER NOT NULL REFERENCES consent_snapshots(id),
  adopted_basis_version TEXT NOT NULL,
  decision TEXT NOT NULL CHECK(decision IN ('accepted','escalated','waived')),
  reason TEXT NOT NULL,
  source_claim_pk INTEGER NOT NULL,
  source_snapshot_id INTEGER NOT NULL,
  source_body_hash TEXT NOT NULL,
  original_decision TEXT NOT NULL,
  original_reason TEXT NOT NULL,
  original_snapshot_id INTEGER NOT NULL,
  original_basis_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('current','needs_review','superseded')),
  reviewer_id TEXT NOT NULL,
  reviewed_at TEXT,
  superseded_by_id INTEGER,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dispo_item ON dispositions(item_id, id);
CREATE INDEX IF NOT EXISTS idx_dispo_review ON dispositions(status, created_at);

CREATE TABLE IF NOT EXISTS audit_events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_id TEXT,
  inst_id TEXT,
  kind TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}'
);
"""


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".%03dZ" % int(time.time() * 1000 % 1000)


def hash_pw(salt, password):
    return hashlib.sha256((salt + ":" + password).encode("utf-8")).hexdigest()


def canonical_hash(value):
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_conn(path=None):
    conn = sqlite3.connect(path or DB_PATH, timeout=15, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def begin_tx(conn):
    conn.execute("BEGIN IMMEDIATE")


def init_db():
    global _initialized
    with _lock:
        if _initialized:
            return
        conn = get_conn()
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()
        _initialized = True

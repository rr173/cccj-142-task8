"""事后对账领域服务。

时间点裁定只依赖“发生时刻之前已经被本模块固化”的许可快照：
后补许可即便正文覆盖该操作，也因为其快照 observed_at 晚于 occurred_at 而不能解释历史行为。
"""
import json
import secrets
import sqlite3
from datetime import datetime, timezone

from db import begin_tx, canonical_hash, hash_pw, now

OPS = ("blood_draw", "imaging", "medication", "sample_retention")
SOURCE_SYSTEMS = {
    "blood": "blood_draw",
    "imaging": "imaging",
    "medication": "medication",
    "sample": "sample_retention",
}
# 与许可引擎四个中性操作码对应。sample_reuse 在执行声明侧具体化为留样。
OP_ALIASES = {
    "blood_draw": "blood_draw",
    "imaging": "imaging",
    "medication": "medication",
    "sample_retention": "sample_retention",
    "sample_reuse": "sample_retention",
}
RESULTS = (
    "explained", "missing_basis", "out_of_scope", "post_termination",
    "awaiting_late_materials",
)
DECISIONS = ("accepted", "escalated", "waived")
DEFAULT_PURPOSE_BY_OP = {
    "blood_draw": ["routine_trial"],
    "imaging": ["routine_trial"],
    "medication": ["treatment"],
    "sample_retention": ["biobank"],
}


class ServiceError(Exception):
    def __init__(self, code, message, http=400):
        super().__init__(message)
        self.code = code
        self.http = http


def jload(value, default=None):
    if value is None:
        return default
    return json.loads(value)


def parse_ts(value):
    if not value:
        raise ServiceError("bad_timestamp", "时间戳不能为空")
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ServiceError("bad_timestamp", f"时间戳不是 ISO-8601：{value}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def ts_text(value):
    return parse_ts(value).isoformat().replace("+00:00", "Z")


def require(value, code, message):
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ServiceError(code, message)
    return value


def clean_op(value):
    op = OP_ALIASES.get(str(value or ""))
    if not op:
        raise ServiceError("bad_op", f"未知中性操作码：{value}")
    return op


def receipt_no():
    return "R-" + secrets.token_hex(10)


def batch_no():
    return "B-" + secrets.token_hex(10)


def audit(conn, kind, actor=None, *, inst_id=None, detail=None):
    conn.execute(
        "INSERT INTO audit_events(ts,actor_id,inst_id,kind,detail_json) VALUES(?,?,?,?,?)",
        (now(), actor.get("id") if actor else None, inst_id, kind,
         json.dumps(detail or {}, ensure_ascii=False)),
    )


# ---------------- 认证与主体 ----------------

def authenticate(conn, login, password):
    r = conn.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
    if not r or hash_pw(r["pw_salt"], password) != r["pw_hash"]:
        raise ServiceError("bad_credentials", "账号或密码错误", 401)
    token = secrets.token_urlsafe(24)
    begin_tx(conn)
    try:
        conn.execute("INSERT INTO auth_tokens(token,user_id,created_at) VALUES(?,?,?)",
                     (token, r["id"], now()))
        audit(conn, "login", actor=dict(r), inst_id=r["inst_id"])
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return token, user_dict(r)


def principal(conn, token):
    if not token:
        raise ServiceError("unauthenticated", "缺少登录令牌", 401)
    r = conn.execute(
        "SELECT u.* FROM auth_tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?",
        (token,)).fetchone()
    if not r:
        raise ServiceError("unauthenticated", "登录令牌无效或已过期", 401)
    return user_dict(r)


def user_dict(r):
    return {"id": r["id"], "inst_id": r["inst_id"], "role": r["role"],
            "login": r["login"], "name": r["name"]}


def subject(conn, subject_id):
    r = conn.execute("SELECT * FROM subjects WHERE id=?", (subject_id,)).fetchone()
    if not r:
        raise ServiceError("subject_not_found", "对账对象不存在", 404)
    return dict(r)


def require_role(user, *roles):
    if not user or user["role"] not in roles:
        raise ServiceError("forbidden", "当前角色无权使用该接口", 403)


# ---------------- 许可快照 ----------------

def _clean_snapshot_entry(raw, *, snapshot_id=None):
    if not isinstance(raw, dict):
        raise ServiceError("bad_snapshot_entry", "快照条目必须是对象")
    sid = require(raw.get("subject_id"), "bad_subject", "快照条目缺少 subject_id")
    op = clean_op(raw.get("op"))
    purpose = str(require(raw.get("purpose"), "bad_purpose", "快照条目缺少 purpose")).strip()
    basis_version = str(require(raw.get("basis_version"), "bad_basis_version",
                                "快照条目缺少 basis_version")).strip()
    status = raw.get("status")
    if status not in ("active", "terminated"):
        raise ServiceError("bad_snapshot_status", "快照状态只能是 active/terminated")
    granted_at = ts_text(raw.get("granted_at"))
    terminated_at = None
    if status == "terminated":
        terminated_at = ts_text(require(raw.get("terminated_at"), "bad_terminated_at",
                                        "terminated 快照必须有 terminated_at"))
        if parse_ts(terminated_at) < parse_ts(granted_at):
            raise ServiceError("bad_terminated_at", "终止时刻早于授权时刻")
    entry = {
        "subject_id": sid,
        "op": op,
        "purpose": purpose,
        "basis_version": basis_version,
        "status": status,
        "granted_at": granted_at,
        "terminated_at": terminated_at,
    }
    entry["entry_key"] = raw.get("entry_key") or canonical_hash({
        "subject_id": sid, "op": op, "purpose": purpose, "basis_version": basis_version,
    })
    return entry


def import_snapshot(conn, body, user):
    require_role(user, "compliance")
    source_name = str(require(body.get("source_name"), "bad_source", "缺少 source_name")).strip()
    source_watermark = str(require(body.get("source_watermark"), "bad_watermark",
                                   "缺少 source_watermark")).strip()
    observed_at = ts_text(require(body.get("observed_at"), "bad_observed_at",
                                  "缺少快照 observed_at"))
    raw_entries = body.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ServiceError("bad_entries", "快照至少包含一条许可条目")
    entries = [_clean_snapshot_entry(x) for x in raw_entries]
    seen = set()
    for e in entries:
        key = (e["entry_key"], e["subject_id"], e["op"], e["purpose"], e["basis_version"])
        if key in seen:
            raise ServiceError("duplicate_snapshot_entry", "同一快照内条目键重复")
        seen.add(key)
        subject(conn, e["subject_id"])

    digest = canonical_hash({"source_name": source_name,
                             "source_watermark": source_watermark,
                             "observed_at": observed_at, "entries": entries})
    begin_tx(conn)
    try:
        old = conn.execute(
            "SELECT * FROM consent_snapshots WHERE source_name=? AND source_watermark=?",
            (source_name, source_watermark)).fetchone()
        if old:
            if old["digest"] != digest:
                raise ServiceError("snapshot_watermark_conflict",
                                   "同一来源水位线对应不同内容，不可改写历史快照", 409)
            conn.execute("ROLLBACK")
            return snapshot_dict(old, replay=True)
        cur = conn.execute(
            "INSERT INTO consent_snapshots(source_name,source_watermark,observed_at,"
            "imported_at,digest) VALUES(?,?,?,?,?)",
            (source_name, source_watermark, observed_at, now(), digest))
        snapshot_id = cur.lastrowid
        for e in entries:
            s = subject(conn, e["subject_id"])
            conn.execute(
                "INSERT INTO snapshot_entries(snapshot_id,entry_key,subject_id,inst_id,op,"
                "purpose,basis_version,status,granted_at,terminated_at,entry_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (snapshot_id, e["entry_key"], e["subject_id"], s["inst_id"], e["op"],
                 e["purpose"], e["basis_version"], e["status"], e["granted_at"],
                 e["terminated_at"], json.dumps(e, ensure_ascii=False)))
        audit(conn, "snapshot_imported", user, detail={"snapshot_id": snapshot_id,
                                                        "source": source_name,
                                                        "watermark": source_watermark,
                                                        "entries": len(entries)})
        conn.execute("COMMIT")
        return snapshot_dict(conn.execute(
            "SELECT * FROM consent_snapshots WHERE id=?", (snapshot_id,)).fetchone())
    except Exception:
        conn.execute("ROLLBACK")
        raise


def snapshot_dict(r, entries=None, replay=False):
    d = {"id": r["id"], "source_name": r["source_name"],
         "source_watermark": r["source_watermark"], "observed_at": r["observed_at"],
         "imported_at": r["imported_at"], "digest": r["digest"]}
    if entries is not None:
        d["entries"] = entries
    if replay:
        d["replayed"] = True
    return d


def get_snapshot(conn, snapshot_id):
    r = conn.execute("SELECT * FROM consent_snapshots WHERE id=?", (snapshot_id,)).fetchone()
    if not r:
        raise ServiceError("snapshot_not_found", "快照不存在", 404)
    entries = [dict(x) for x in conn.execute(
        "SELECT * FROM snapshot_entries WHERE snapshot_id=? ORDER BY id", (snapshot_id,))]
    return snapshot_dict(r, entries)


def list_snapshots(conn, user):
    require_role(user, "compliance", "site", "participant")
    return [snapshot_dict(r) for r in conn.execute(
        "SELECT * FROM consent_snapshots ORDER BY id")]


def import_from_consent_db(conn, consent_path, *, source_watermark=None, observed_at=None):
    """只读许可引擎库并把当时的许可状态物化成对账模块自己的不可变快照。"""
    uri = "file:" + consent_path + "?mode=ro"
    src = sqlite3.connect(uri, uri=True, isolation_level=None)
    src.row_factory = sqlite3.Row
    try:
        src.execute("SELECT 1 FROM permits LIMIT 1")
    finally:
        pass
    observed_at = ts_text(observed_at or now())
    watermark = source_watermark or ("consent@" + observed_at)
    permits = src.execute("""
        SELECT p.*, s.inst_id AS subject_inst FROM permits p
        JOIN subjects s ON s.id=p.subject_id
        ORDER BY p.id
    """).fetchall()
    entries = []
    known = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM subjects")}
    for p in permits:
        if p["subject_id"] not in known:
            inst = conn.execute("SELECT id FROM institutions WHERE id=?",
                                (p["subject_inst"],)).fetchone()
            if not inst:
                conn.execute("INSERT INTO institutions(id,name) VALUES(?,?)",
                             (p["subject_inst"], p["subject_inst"]))
            conn.execute(
                "INSERT INTO subjects(id,inst_id,name,user_id) VALUES(?,?,?,NULL)",
                (p["subject_id"], p["subject_inst"], p["subject_id"]))
        for op in jload(p["scope_json"], []):
            op = OP_ALIASES.get(op)
            if not op:
                continue
            for purpose in DEFAULT_PURPOSE_BY_OP[op]:
                status = "active" if p["status"] == "active" else "terminated"
                entries.append({
                    "subject_id": p["subject_id"], "op": op, "purpose": purpose,
                    "basis_version": f"{p['family']}:v{p['version']}",
                    "status": status, "granted_at": p["issued_at"],
                    "terminated_at": p["revoked_at"],
                    "entry_key": f"{p['id']}:{op}:{purpose}",
                })
    if not entries:
        raise ServiceError("empty_consent_snapshot", "许可引擎中没有可导入的许可")
    return import_snapshot(conn, {
        "source_name": "consent-sqlite", "source_watermark": watermark,
        "observed_at": observed_at, "entries": entries,
    }, {"id": "system", "role": "compliance", "inst_id": None})


# ---------------- 执行声明 ----------------

def claim_payload(data):
    source_system = str(require(data.get("source_system"), "bad_source_system",
                                "缺少 source_system")).strip()
    if source_system not in SOURCE_SYSTEMS:
        raise ServiceError("bad_source_system",
                           f"source_system 必须是 {tuple(SOURCE_SYSTEMS)}")
    subject_id = str(require(data.get("subject_id"), "bad_subject", "缺少 subject_id")).strip()
    purpose = str(require(data.get("purpose"), "bad_purpose", "缺少 purpose")).strip()
    occurred_at = ts_text(require(data.get("occurred_at"), "bad_occurred_at",
                                  "缺少 occurred_at"))
    basis_version = str(require(data.get("basis_version"), "bad_basis_version",
                                "缺少 basis_version")).strip()
    body = str(require(data.get("body"), "bad_body", "缺少执行声明正文")).strip()
    data_status = data.get("data_status", "complete")
    if data_status not in ("complete", "awaiting_materials"):
        raise ServiceError("bad_data_status", "data_status 非法")
    return {
        "source_system": source_system,
        "op": SOURCE_SYSTEMS[source_system],
        "subject_id": subject_id,
        "purpose": purpose,
        "occurred_at": occurred_at,
        "basis_version": basis_version,
        "data_status": data_status,
        "body": body,
    }


def _claim_hash(payload):
    return canonical_hash(payload)


def claim_dict(r, replay=False):
    d = {
        "claim_id": r["claim_id"], "revision": r["revision"],
        "supersedes_revision": r["supersedes_revision"],
        "batch_id": r["batch_id"], "source_system": r["source_system"],
        "subject_id": r["subject_id"], "inst_id": r["inst_id"], "op": r["op"],
        "purpose": r["purpose"], "occurred_at": r["occurred_at"],
        "arrived_at": r["arrived_at"], "basis_version": r["basis_version"],
        "data_status": r["data_status"], "body": r["body"],
        "receipt": r["receipt"], "status": r["status"],
    }
    if replay:
        d["replayed"] = True
    return d


def _insert_claim(conn, *, claim_id, revision, supersedes, batch_id, payload, subj, arrived_at):
    body_hash = _claim_hash(payload)
    receipt = receipt_no()
    cur = conn.execute(
        "INSERT INTO execution_claims(claim_id,revision,supersedes_revision,batch_id,"
        "source_system,subject_id,inst_id,op,purpose,occurred_at,arrived_at,basis_version,"
        "data_status,body,body_hash,receipt,status,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'accepted',?)",
        (claim_id, revision, supersedes, batch_id, payload["source_system"],
         payload["subject_id"], subj["inst_id"], payload["op"], payload["purpose"],
         payload["occurred_at"], arrived_at, payload["basis_version"],
         payload["data_status"], payload["body"], body_hash, receipt, now()))
    return claim_dict(conn.execute("SELECT * FROM execution_claims WHERE id=?",
                                   (cur.lastrowid,)).fetchone())


def ingest_claim(conn, data, user, *, batch_id=None, inst_scope=None, arrived_at=None):
    """单条或批量事务内调用。调用方负责打开/提交事务。"""
    if user["role"] == "site":
        if inst_scope != user["inst_id"]:
            raise ServiceError("cross_institution_batch", "批次机构与登录站点不一致", 409)
    payload = claim_payload(data)
    subj = subject(conn, payload["subject_id"])
    if inst_scope is not None and subj["inst_id"] != inst_scope:
        raise ServiceError("cross_institution_batch",
                          "一个导入批次不能包含跨机构对象", 409)
    claim_id = str(require(data.get("claim_id"), "bad_claim_id", "缺少 claim_id")).strip()
    supersedes = data.get("supersedes_revision")
    latest = conn.execute(
        "SELECT * FROM execution_claims WHERE claim_id=? ORDER BY revision DESC LIMIT 1",
        (claim_id,)).fetchone()
    payload_hash = _claim_hash(payload)
    arrived_at = ts_text(arrived_at or data.get("arrived_at") or now())

    if latest is None:
        if supersedes not in (None, 0):
            raise ServiceError("correction_previous_missing", "更正引用的上一版本不存在", 409)
        out = _insert_claim(conn, claim_id=claim_id, revision=1, supersedes=None,
                            batch_id=batch_id, payload=payload, subj=subj,
                            arrived_at=arrived_at)
        audit(conn, "claim_accepted", user, inst_id=subj["inst_id"],
              detail={"claim_id": claim_id, "revision": 1, "batch_id": batch_id})
        return out

    if supersedes in (None, 0):
        if latest["body_hash"] == payload_hash:
            return claim_dict(latest, replay=True)
        raise ServiceError("claim_payload_mismatch",
                           "相同声明标识已存在但时间、对象、用途或正文不同；更正必须引用上一版本",
                           409)
    try:
        supersedes = int(supersedes)
    except (TypeError, ValueError):
        raise ServiceError("bad_supersedes_revision", "supersedes_revision 必须是整数", 400)
    if supersedes != latest["revision"]:
        raise ServiceError("correction_out_of_order",
                           "更正必须引用当前最新版本，差异链不能分叉或覆盖", 409)
    if latest["body_hash"] == payload_hash:
        return claim_dict(latest, replay=True)
    conn.execute("UPDATE execution_claims SET status='superseded' WHERE id=?", (latest["id"],))
    out = _insert_claim(conn, claim_id=claim_id, revision=latest["revision"] + 1,
                        supersedes=supersedes, batch_id=batch_id, payload=payload,
                        subj=subj, arrived_at=arrived_at)
    audit(conn, "claim_corrected", user, inst_id=subj["inst_id"],
          detail={"claim_id": claim_id, "revision": out["revision"],
                  "previous_revision": supersedes, "batch_id": batch_id})
    return out


def submit_claim(conn, data, user):
    require_role(user, "compliance", "site")
    # 先做服务端校验，再打开写事务。
    payload = claim_payload(data)  # noqa: F841
    begin_tx(conn)
    try:
        scope = user["inst_id"] if user["role"] == "site" else None
        out = ingest_claim(conn, data, user, batch_id=batch_no(), inst_scope=scope)
        conn.execute("COMMIT")
        return out
    except Exception:
        conn.execute("ROLLBACK")
        raise


def submit_batch(conn, body, user):
    require_role(user, "compliance", "site")
    declarations = body.get("declarations")
    if not isinstance(declarations, list) or not declarations:
        raise ServiceError("bad_batch", "declarations 必须是非空数组")
    inst_scope = body.get("inst_scope")
    if user["role"] == "site":
        inst_scope = user["inst_id"]
    elif not inst_scope:
        raise ServiceError("bad_batch_scope", "合规批量导入必须声明单一 inst_scope")
    # 全量预检：任意一条格式损坏或跨机构，整批不进入写事务。
    prepared = []
    for i, item in enumerate(declarations):
        if not isinstance(item, dict):
            raise ServiceError("bad_declaration", f"第 {i} 条声明不是对象")
        payload = claim_payload(item)
        subj = subject(conn, payload["subject_id"])
        if subj["inst_id"] != inst_scope:
            raise ServiceError("cross_institution_batch",
                              f"第 {i} 条声明对象不属于批次机构 {inst_scope}", 409)
        prepared.append(item)

    begin_tx(conn)
    try:
        b_id = batch_no()
        # 批次登记与全部声明在同一事务；任何异常都会 ROLLBACK，不留半批。
        conn.execute(
            "INSERT INTO import_batches(id,status,inst_scope,claim_count,created_at)"
            " VALUES(?,?, 'accepted',?,?)",
            (b_id, inst_scope, len(prepared), now()))
        receipts = [
            ingest_claim(conn, item, user, batch_id=b_id, inst_scope=inst_scope,
                         arrived_at=item.get("arrived_at"))
            for item in prepared
        ]
        audit(conn, "batch_accepted", user, inst_id=inst_scope,
              detail={"batch_id": b_id, "count": len(receipts)})
        conn.execute("COMMIT")
        return {"batch_id": b_id, "status": "accepted", "count": len(receipts),
                "receipts": receipts}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def list_claims(conn, user, *, inst_id=None):
    if user["role"] == "site":
        inst_id = user["inst_id"]
    elif user["role"] == "participant":
        raise ServiceError("forbidden", "参与人不查看原始声明队列", 403)
    sql = "SELECT * FROM execution_claims WHERE 1=1"
    args = []
    if inst_id:
        sql += " AND inst_id=?"; args.append(inst_id)
    sql += " ORDER BY claim_id, revision"
    return [claim_dict(r) for r in conn.execute(sql, args)]


# ---------------- 周期与重算 ----------------

def create_cycle(conn, body, user):
    require_role(user, "compliance")
    cid = str(require(body.get("id"), "bad_cycle_id", "缺少周期 id")).strip()
    starts = ts_text(body.get("starts_at"))
    cutoff = ts_text(body.get("cutoff_at"))
    if parse_ts(cutoff) <= parse_ts(starts):
        raise ServiceError("bad_cycle_window", "cutoff_at 必须晚于 starts_at")
    begin_tx(conn)
    try:
        if conn.execute("SELECT 1 FROM cycles WHERE id=?", (cid,)).fetchone():
            raise ServiceError("cycle_exists", "周期已存在", 409)
        conn.execute("INSERT INTO cycles(id,title,starts_at,cutoff_at,created_at)"
                     " VALUES(?,?,?,?,?)",
                     (cid, body.get("title", cid), starts, cutoff, now()))
        audit(conn, "cycle_created", user, detail={"cycle_id": cid})
        conn.execute("COMMIT")
        return get_cycle(conn, cid)
    except Exception:
        conn.execute("ROLLBACK")
        raise


def get_cycle(conn, cycle_id):
    r = conn.execute("SELECT * FROM cycles WHERE id=?", (cycle_id,)).fetchone()
    if not r:
        raise ServiceError("cycle_not_found", "对账周期不存在", 404)
    return dict(r)


def list_cycles(conn, user):
    require_role(user, "compliance", "site")
    return [dict(r) for r in conn.execute("SELECT * FROM cycles ORDER BY starts_at")]


def _latest_claims(conn):
    return conn.execute("""
        SELECT c.* FROM execution_claims c
        JOIN (SELECT claim_id, MAX(revision) mr FROM execution_claims GROUP BY claim_id) m
          ON m.claim_id=c.claim_id AND m.mr=c.revision
        WHERE c.status='accepted'
        ORDER BY c.occurred_at, c.claim_id
    """).fetchall()


def _latest_basis_state(conn, claim, eligible_snapshot_id):
    """返回发生时刻之前所有快照中，该依据键的最新物化状态。"""
    return conn.execute("""
        SELECT e.* FROM snapshot_entries e
        JOIN (
          SELECT entry_key, subject_id, op, purpose, basis_version,
                 MAX((SELECT observed_at FROM consent_snapshots s WHERE s.id=x.snapshot_id)) AS oa
          FROM snapshot_entries x
          WHERE snapshot_id<=?
          GROUP BY entry_key, subject_id, op, purpose, basis_version
        ) latest
          ON latest.entry_key=e.entry_key
         AND latest.subject_id=e.subject_id
         AND latest.op=e.op
         AND latest.purpose=e.purpose
         AND latest.basis_version=e.basis_version
        JOIN consent_snapshots s ON s.id=e.snapshot_id AND s.observed_at=latest.oa
        WHERE e.subject_id=? AND e.op=? AND e.purpose=? AND e.basis_version=?
        LIMIT 1
    """, (eligible_snapshot_id, claim["subject_id"], claim["op"], claim["purpose"],
          claim["basis_version"])).fetchone()


def classify(conn, claim, cycle, latest_snapshot):
    if claim["data_status"] == "awaiting_materials":
        return ("awaiting_late_materials", "awaiting_materials", None, None)
    if latest_snapshot is None:
        return ("missing_basis", "no_snapshot_available", None, None)

    event_at = parse_ts(claim["occurred_at"])
    # 关键：只有 observed_at <= occurred_at 的快照才有资格裁定当时行为。
    eligible = conn.execute(
        "SELECT MAX(id) AS id FROM consent_snapshots WHERE observed_at<=?",
        (claim["occurred_at"],)).fetchone()
    if not eligible or eligible["id"] is None:
        return ("missing_basis", "no_basis_snapshot_at_event_time", None, None)
    exact = _latest_basis_state(conn, claim, eligible["id"])
    if exact:
        granted = parse_ts(exact["granted_at"])
        if granted > event_at:
            return ("missing_basis", "basis_granted_after_event",
                    exact["snapshot_id"], exact["entry_key"])
        if exact["status"] == "terminated" and parse_ts(exact["terminated_at"]) <= event_at:
            return ("post_termination", "basis_terminated_before_event",
                    exact["snapshot_id"], exact["entry_key"])
        return ("explained", "matched_at_event_time",
                exact["snapshot_id"], exact["entry_key"])

    # 同一依据版本存在但未覆盖该操作/用途 => 超出范围；完全找不到该版本 => 缺少依据。
    op_rows = conn.execute("""
        SELECT 1 FROM snapshot_entries
        WHERE snapshot_id<=? AND subject_id=? AND basis_version=? AND op=? LIMIT 1
    """, (eligible["id"], claim["subject_id"], claim["basis_version"], claim["op"])).fetchall()
    if op_rows:
        return ("out_of_scope", "purpose_not_authorized", None, None)
    version_rows = conn.execute("""
        SELECT 1 FROM snapshot_entries
        WHERE snapshot_id<=? AND subject_id=? AND basis_version=? LIMIT 1
    """, (eligible["id"], claim["subject_id"], claim["basis_version"])).fetchall()
    if version_rows:
        return ("out_of_scope", "op_not_authorized", None, None)
    return ("missing_basis", "basis_version_unknown_at_event_time", None, None)


def _current_watermark(conn):
    cs = conn.execute("SELECT COALESCE(MAX(id),0) sid, COALESCE(MAX(observed_at),'') soa "
                      "FROM consent_snapshots").fetchone()
    cc = conn.execute("SELECT COALESCE(MAX(id),0) cid, COALESCE(MAX(revision),0) cr "
                      "FROM execution_claims").fetchone()
    data = {"snapshot_id": cs["sid"], "snapshot_observed_at": cs["soa"],
            "claim_id": cc["cid"], "claim_revision": cc["cr"]}
    return canonical_hash(data), data


def recompute(conn, cycle_id, user, *, crash_after_publish=False):
    require_role(user, "compliance")
    cycle = get_cycle(conn, cycle_id)
    begin_tx(conn)
    try:
        watermark, watermark_data = _current_watermark(conn)
        duplicate = conn.execute(
            "SELECT * FROM reconciliation_versions WHERE cycle_id=? AND input_watermark=?",
            (cycle_id, watermark)).fetchone()
        if duplicate:
            conn.execute("ROLLBACK")
            return version_payload(conn, duplicate, replay=True)

        latest_snapshot = conn.execute(
            "SELECT * FROM consent_snapshots ORDER BY id DESC LIMIT 1").fetchone()
        start = parse_ts(cycle["starts_at"])
        end = parse_ts(cycle["cutoff_at"])
        selected = [c for c in _latest_claims(conn)
                    if start <= parse_ts(c["occurred_at"]) < end]
        version_no = conn.execute(
            "SELECT COALESCE(MAX(version),0)+1 n FROM reconciliation_versions WHERE cycle_id=?",
            (cycle_id,)).fetchone()["n"]
        published_at = now()
        digest = canonical_hash({
            "cycle_id": cycle_id, "version": version_no, "watermark": watermark_data,
            "claims": [{"pk": c["id"], "id": c["claim_id"], "revision": c["revision"],
                        "body_hash": c["body_hash"]} for c in selected],
        })
        cur = conn.execute(
            "INSERT INTO reconciliation_versions(cycle_id,version,input_watermark,digest,"
            "status,published_at) VALUES(?,?,?,?,'published',?)",
            (cycle_id, version_no, watermark, digest, published_at))
        version_id = cur.lastrowid
        items = []
        for c in selected:
            result, reason, snap_id, entry_key = classify(conn, c, cycle, latest_snapshot)
            item_json = {
                "claim_id": c["claim_id"], "claim_revision": c["revision"],
                "source_system": c["source_system"], "body": c["body"],
                "arrived_at": c["arrived_at"], "data_status": c["data_status"],
                "input_snapshot_id": latest_snapshot["id"] if latest_snapshot else None,
                "watermark": watermark_data,
            }
            ic = conn.execute(
                "INSERT INTO reconciliation_items(version_id,claim_pk,claim_id,claim_revision,"
                "subject_id,inst_id,op,purpose,occurred_at,basis_version,result,reason,"
                "matched_snapshot_id,matched_entry_key,item_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (version_id, c["id"], c["claim_id"], c["revision"], c["subject_id"],
                 c["inst_id"], c["op"], c["purpose"], c["occurred_at"], c["basis_version"],
                 result, reason, snap_id, entry_key,
                 json.dumps(item_json, ensure_ascii=False)))
            item = conn.execute("SELECT * FROM reconciliation_items WHERE id=?",
                                (ic.lastrowid,)).fetchone()
            items.append(item)

        # 新发布版本只把旧处置置为待复核；original_* 列原样保留。
        for item in items:
            old = conn.execute("""
                SELECT d.* FROM dispositions d
                JOIN reconciliation_items old_i ON old_i.id=d.item_id
                JOIN reconciliation_versions v ON v.id=old_i.version_id
                WHERE d.cycle_id=? AND old_i.claim_id=? AND d.status='current'
                  AND v.id<>?
                ORDER BY d.id DESC LIMIT 1
            """, (cycle_id, item["claim_id"], version_id)).fetchone()
            if not old:
                continue
            stale = (old["source_claim_pk"] != item["claim_pk"]
                     or old["source_body_hash"] != _claim_body_hash(conn, item["claim_pk"])
                     or old["source_snapshot_id"] != (item["matched_snapshot_id"]
                                                      or json.loads(item["item_json"])
                                                      .get("input_snapshot_id")))
            if stale:
                conn.execute(
                    "UPDATE dispositions SET status='needs_review',reviewed_at=? WHERE id=?",
                    (published_at, old["id"]))
                audit(conn, "disposition_needs_review", user, inst_id=old["inst_id"],
                      detail={"disposition_id": old["id"], "new_version_id": version_id,
                              "new_item_id": item["id"], "claim_id": item["claim_id"]})

        counts = {}
        for item in items:
            counts[item["result"]] = counts.get(item["result"], 0) + 1
        audit(conn, "version_published", user,
              detail={"cycle_id": cycle_id, "version_id": version_id,
                      "version": version_no, "counts": counts})
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    # 发布事务已落盘；响应前退出时，重启只能识别 published 版本，不能重算差异项。
    if crash_after_publish:
        import os
        os._exit(7)
    return get_version(conn, cycle_id, version_no, user=None)


def _claim_body_hash(conn, claim_pk):
    r = conn.execute("SELECT body_hash FROM execution_claims WHERE id=?",
                     (claim_pk,)).fetchone()
    return r["body_hash"] if r else None


def item_dict(r, include_disposition=None):
    d = {
        "id": r["id"], "version_id": r["version_id"], "claim_pk": r["claim_pk"],
        "claim_id": r["claim_id"], "claim_revision": r["claim_revision"],
        "subject_id": r["subject_id"], "inst_id": r["inst_id"], "op": r["op"],
        "purpose": r["purpose"], "occurred_at": r["occurred_at"],
        "basis_version": r["basis_version"], "result": r["result"], "reason": r["reason"],
        "matched_snapshot_id": r["matched_snapshot_id"],
        "matched_entry_key": r["matched_entry_key"],
        "detail": jload(r["item_json"], {}),
    }
    if include_disposition is not None:
        d["latest_disposition"] = include_disposition
    return d


def disposition_dict(r):
    return {
        "id": r["id"], "item_id": r["item_id"], "version_id": r["version_id"],
        "cycle_id": r["cycle_id"], "subject_id": r["subject_id"], "inst_id": r["inst_id"],
        "adopted_snapshot_id": r["adopted_snapshot_id"],
        "adopted_basis_version": r["adopted_basis_version"], "decision": r["decision"],
        "reason": r["reason"], "status": r["status"], "reviewer_id": r["reviewer_id"],
        "created_at": r["created_at"], "reviewed_at": r["reviewed_at"],
        "superseded_by_id": r["superseded_by_id"],
        "original": {
            "decision": r["original_decision"], "reason": r["original_reason"],
            "snapshot_id": r["original_snapshot_id"],
            "basis_version": r["original_basis_version"],
        },
    }


def latest_disposition_forItem(conn, item_id):
    r = conn.execute("SELECT * FROM dispositions WHERE item_id=? ORDER BY id DESC LIMIT 1",
                     (item_id,)).fetchone()
    return disposition_dict(r) if r else None


def version_dict(r, items=None, user=None):
    d = {"id": r["id"], "cycle_id": r["cycle_id"], "version": r["version"],
         "input_watermark": r["input_watermark"], "digest": r["digest"],
         "status": r["status"], "published_at": r["published_at"]}
    if items is not None:
        d["items"] = items
        counts = {k: 0 for k in RESULTS}
        for item in items:
            counts[item["result"]] += 1
        d["counts"] = counts
    return d


def version_payload(conn, r, replay=False):
    d = version_dict(r)
    if replay:
        d["replayed"] = True
    return d


def _version_row(conn, cycle_id, version):
    if version in (None, "latest"):
        r = conn.execute(
            "SELECT * FROM reconciliation_versions WHERE cycle_id=? ORDER BY version DESC LIMIT 1",
            (cycle_id,)).fetchone()
    else:
        r = conn.execute(
            "SELECT * FROM reconciliation_versions WHERE cycle_id=? AND version=?",
            (cycle_id, int(version))).fetchone()
    if not r:
        raise ServiceError("version_not_found", "对账版本不存在", 404)
    return r


def get_version(conn, cycle_id, version="latest", user=None):
    r = _version_row(conn, cycle_id, version)
    rows = conn.execute("SELECT * FROM reconciliation_items WHERE version_id=? ORDER BY id",
                        (r["id"],)).fetchall()
    items = []
    for row in rows:
        if user and user["role"] == "site" and row["inst_id"] != user["inst_id"]:
            continue
        if user and user["role"] == "participant":
            linked = participant_subject_id(conn, user)
            if row["subject_id"] != linked:
                continue
        items.append(item_dict(row, latest_disposition_forItem(conn, row["id"])))
    d = version_dict(r, items)
    if user and user["role"] == "site":
        d["site_scoped"] = True
    return d


def list_versions(conn, cycle_id, user):
    get_cycle(conn, cycle_id)
    require_role(user, "compliance", "site")
    rows = conn.execute(
        "SELECT * FROM reconciliation_versions WHERE cycle_id=? ORDER BY version",
        (cycle_id,)).fetchall()
    return [version_dict(r) for r in rows]


# ---------------- 处置 ----------------

def participant_subject_id(conn, user):
    r = conn.execute("SELECT id FROM subjects WHERE user_id=?", (user["id"],)).fetchone()
    if not r:
        raise ServiceError("subject_link_missing", "账号未关联参与人对象", 404)
    return r["id"]


def dispose_item(conn, item_id, body, user):
    require_role(user, "compliance")
    decision = body.get("decision")
    if decision not in DECISIONS:
        raise ServiceError("bad_decision", f"decision 必须是 {DECISIONS}")
    reason = str(require(body.get("reason"), "bad_reason", "处置理由必填")).strip()
    snapshot_id = require(body.get("adopted_snapshot_id"), "bad_snapshot",
                          "必须记录采用的快照版本")
    begin_tx(conn)
    try:
        item = conn.execute("SELECT * FROM reconciliation_items WHERE id=?",
                            (item_id,)).fetchone()
        if not item:
            raise ServiceError("item_not_found", "差异项不存在", 404)
        if item["result"] == "explained":
            raise ServiceError("item_not_discrepant", "已解释项无需处置", 409)
        snap = conn.execute("SELECT id FROM consent_snapshots WHERE id=?",
                            (snapshot_id,)).fetchone()
        if not snap:
            raise ServiceError("snapshot_not_found", "采用的快照不存在", 404)
        version = conn.execute("SELECT * FROM reconciliation_versions WHERE id=?",
                               (item["version_id"],)).fetchone()
        detail = json.loads(item["item_json"])
        source_snapshot_id = item["matched_snapshot_id"] or detail.get("input_snapshot_id")
        if not source_snapshot_id:
            raise ServiceError("no_source_snapshot", "该版本没有可追溯的输入快照", 409)
        claim = conn.execute("SELECT * FROM execution_claims WHERE id=?",
                             (item["claim_pk"],)).fetchone()

        prior_same_claim = conn.execute("""
            SELECT d.* FROM dispositions d
            JOIN reconciliation_items old_i ON old_i.id=d.item_id
            WHERE d.cycle_id=? AND old_i.claim_id=?
              AND d.status IN ('current','needs_review')
            ORDER BY d.id DESC LIMIT 1
        """, (version["cycle_id"], item["claim_id"])).fetchone()
        prior_same_item = conn.execute(
            "SELECT * FROM dispositions WHERE item_id=? ORDER BY id DESC LIMIT 1",
            (item_id,)).fetchone()
        prior = prior_same_claim or prior_same_item
        ts = now()
        cur = conn.execute(
            "INSERT INTO dispositions(item_id,version_id,cycle_id,subject_id,inst_id,"
            "adopted_snapshot_id,adopted_basis_version,decision,reason,source_claim_pk,"
            "source_snapshot_id,source_body_hash,original_decision,original_reason,"
            "original_snapshot_id,original_basis_version,status,reviewer_id,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'current',?,?)",
            (item_id, item["version_id"], version["cycle_id"], item["subject_id"],
             item["inst_id"], snapshot_id, item["basis_version"], decision, reason,
             item["claim_pk"], source_snapshot_id, claim["body_hash"],
             decision if not prior else prior["original_decision"],
             reason if not prior else prior["original_reason"],
             snapshot_id if not prior else prior["original_snapshot_id"],
             item["basis_version"] if not prior else prior["original_basis_version"],
             user["id"], ts))
        new_id = cur.lastrowid
        if prior:
            conn.execute(
                "UPDATE dispositions SET status='superseded',reviewed_at=?,"
                "superseded_by_id=? WHERE id=?", (ts, new_id, prior["id"]))
        audit(conn, "disposition_recorded", user, inst_id=item["inst_id"],
              detail={"disposition_id": new_id, "item_id": item_id, "decision": decision,
                      "adopted_snapshot_id": snapshot_id})
        conn.execute("COMMIT")
        return disposition_dict(conn.execute(
            "SELECT * FROM dispositions WHERE id=?", (new_id,)).fetchone())
    except Exception:
        conn.execute("ROLLBACK")
        raise


def list_dispositions(conn, user, *, status=None, inst_id=None):
    require_role(user, "compliance", "site")
    sql = "SELECT * FROM dispositions WHERE 1=1"
    args = []
    if user["role"] == "site":
        sql += " AND inst_id=?"; args.append(user["inst_id"])
    elif inst_id:
        sql += " AND inst_id=?"; args.append(inst_id)
    if status:
        if status not in ("current", "needs_review", "superseded"):
            raise ServiceError("bad_status", "处置状态非法")
        sql += " AND status=?"; args.append(status)
    sql += " ORDER BY id DESC LIMIT 500"
    return [disposition_dict(r) for r in conn.execute(sql, args)]


# ---------------- 角色视图 ----------------

def latest_site_items(conn, cycle_id, user):
    require_role(user, "site")
    get_cycle(conn, cycle_id)
    r = _version_row(conn, cycle_id, "latest")
    rows = conn.execute(
        "SELECT * FROM reconciliation_items WHERE version_id=? AND inst_id=? ORDER BY id",
        (r["id"], user["inst_id"])).fetchall()
    return {"version": version_dict(r), "site_id": user["inst_id"],
            "items": [item_dict(x, latest_disposition_forItem(conn, x["id"])) for x in rows]}


def participant_view(conn, user):
    require_role(user, "participant")
    sid = participant_subject_id(conn, user)
    versions = conn.execute("SELECT id FROM reconciliation_versions ORDER BY id").fetchall()
    out = []
    for v in versions:
        rows = conn.execute(
            "SELECT * FROM reconciliation_items WHERE version_id=? AND subject_id=? ORDER BY id",
            (v["id"], sid)).fetchall()
        for r in rows:
            d = item_dict(r, latest_disposition_forItem(conn, r["id"]))
            vr = conn.execute("SELECT cycle_id,version,published_at FROM reconciliation_versions"
                              " WHERE id=?", (v["id"],)).fetchone()
            d["cycle_id"] = vr["cycle_id"]
            d["published_version"] = vr["version"]
            d["published_at"] = vr["published_at"]
            out.append(d)
    return {"subject_id": sid, "items": out}

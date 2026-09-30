"""医疗行为与同意依据事后对账领域服务。

关键边界：
- 许可快照与终止事件只追加；后补材料只参与后续新版本，不改变历史时点判断。
- 声明按“标识 + 正文指纹”幂等接收；更正生成新版本和差异链，绝不覆盖原正文。
- 对账版本在单个写事务内发布，未提交的临时结果对其他进程不可见。
"""
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from db import (
    begin_tx,
    canonical_dumps,
    claim_body_hash,
    hash_pw,
    now_ms,
    sha256_text,
)

NEUTRAL_OPS = {"BLOOD_DRAW", "IMAGING", "MEDICATION", "SAMPLE_RETENTION"}
SOURCE_SYSTEMS = {"blood_station", "imaging", "medication", "sample_bank"}
RESULT_LABELS = {
    "explained": "已解释",
    "missing_basis": "缺少依据",
    "out_of_scope": "超出范围",
    "post_termination": "终止后执行",
    "awaiting_late_material": "等待迟到资料",
}
LEASE_SECONDS = int(os.environ.get("RECONCILE_LEASE_SECONDS", "120"))


class ServiceError(Exception):
    def __init__(self, code, message, http=400):
        super().__init__(message)
        self.code = code
        self.http = http


def _loads(value, default):
    if value is None:
        return default
    return json.loads(value)


def parse_ts(value, field="time"):
    if not isinstance(value, str) or not value:
        raise ServiceError("bad_time", f"{field} 必须是 ISO-8601 时刻")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ServiceError("bad_time", f"{field} 不是合法 ISO-8601 时刻") from exc


def _ts(value):
    return value.isoformat().replace("+00:00", "Z") if value.tzinfo else value.isoformat() + "Z"


def _event(conn, kind, detail):
    # 小而专的审计流水；它不参与不可变触发器保护的业务证据表。
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_events("
        "seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, kind TEXT NOT NULL, "
        "actor TEXT, inst_id TEXT, cycle_id TEXT, detail_json TEXT NOT NULL DEFAULT '{}')"
    )
    conn.execute(
        "INSERT INTO audit_events(ts,kind,actor,inst_id,cycle_id,detail_json) "
        "VALUES(?,?,?,?,?,?)",
        (now_ms(), kind, detail.get("actor"), detail.get("inst_id"),
         detail.get("cycle_id"), json.dumps(detail, ensure_ascii=False)),
    )


# ---------------- 认证与对象 ----------------

def authenticate(conn, login, password):
    begin_tx(conn)
    try:
        row = conn.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
        if not row or hash_pw(row["pw_salt"], password) != row["pw_hash"]:
            conn.execute("ROLLBACK")
            raise ServiceError("bad_credentials", "账号或密码错误", 401)
        token = secrets.token_urlsafe(28)
        conn.execute("INSERT INTO auth_tokens(token,user_id,created_at) VALUES(?,?,?)",
                     (token, row["id"], now_ms()))
        _event(conn, "login", {"actor": row["id"], "inst_id": row["inst_id"]})
        conn.execute("COMMIT")
        return token, safe_user(row)
    except Exception:
        conn.execute("ROLLBACK")
        raise


def principal(conn, token):
    if not token:
        raise ServiceError("unauthenticated", "缺少登录令牌", 401)
    row = conn.execute(
        "SELECT u.* FROM auth_tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?",
        (token,),
    ).fetchone()
    if not row:
        raise ServiceError("unauthenticated", "登录令牌无效或已退出", 401)
    return dict(row)


def safe_user(row):
    return {"id": row["id"], "login": row["login"], "name": row["name"],
            "role": row["role"], "inst_id": row["inst_id"]}


def subject_for_user(conn, user):
    row = conn.execute("SELECT * FROM subjects WHERE user_id=?", (user["id"],)).fetchone()
    if not row:
        raise ServiceError("subject_not_linked", "账号未关联参与人对象", 403)
    return dict(row)


def require_role(user, roles):
    if user["role"] not in roles:
        raise ServiceError("forbidden", "当前角色无权执行此操作", 403)


def _get_subject(conn, subject_id):
    row = conn.execute("SELECT * FROM subjects WHERE id=?", (subject_id,)).fetchone()
    if not row:
        raise ServiceError("subject_not_found", f"对象 {subject_id} 不存在", 404)
    return row


# ---------------- 许可快照导入 ----------------

def _validate_scope(scope):
    if not isinstance(scope, list) or any(x not in NEUTRAL_OPS for x in scope):
        raise ServiceError("bad_scope", "scope 必须是中性操作码数组")
    return sorted(scope)


def _validate_purposes(purposes):
    if purposes is None:
        return []
    if not isinstance(purposes, list) or any(not isinstance(x, str) or not x for x in purposes):
        raise ServiceError("bad_purposes", "allowed_purposes 必须是非空字符串数组")
    return purposes


def import_permit_snapshot(conn, body, user):
    require_role(user, {"compliance"})
    required = ("permit_id", "subject_id", "family", "basis_version", "scope",
                "effective_at", "snapshot_version", "body_hash")
    missing = [k for k in required if body.get(k) in (None, "")]
    if missing:
        raise ServiceError("missing_fields", f"缺少字段：{', '.join(missing)}")
    subject = _get_subject(conn, body["subject_id"])
    basis_version = int(body["basis_version"])
    snapshot_version = int(body["snapshot_version"])
    if basis_version < 1 or snapshot_version < 1:
        raise ServiceError("bad_version", "版本号必须为正整数")
    scope = _validate_scope(body["scope"])
    purposes = _validate_purposes(body.get("allowed_purposes", []))
    effective = parse_ts(body["effective_at"], "effective_at")
    body_hash = str(body["body_hash"])
    if len(body_hash) != 64:
        raise ServiceError("bad_body_hash", "body_hash 必须为 64 位十六进制摘要")

    begin_tx(conn)
    try:
        existing = conn.execute(
            "SELECT * FROM permit_snapshots WHERE permit_id=? AND basis_version=? "
            "AND snapshot_version=?",
            (body["permit_id"], basis_version, snapshot_version),
        ).fetchone()
        if existing:
            if existing["body_hash"] != body_hash or existing["scope_json"] != json.dumps(scope) \
                    or existing["allowed_purposes_json"] != json.dumps(purposes, ensure_ascii=False):
                conn.execute("ROLLBACK")
                raise ServiceError("snapshot_conflict",
                                   "同一快照版本出现不同正文，许可引擎历史不一致", 409)
            conn.execute("ROLLBACK")
            return {"id": existing["id"], "idempotent": True}

        cur = conn.execute(
            "INSERT INTO permit_snapshots(permit_id,subject_id,inst_id,family,basis_version,"
            "scope_json,allowed_purposes_json,effective_at,snapshot_version,body_hash,imported_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (body["permit_id"], subject["id"], subject["inst_id"], body["family"],
             basis_version, json.dumps(scope), json.dumps(purposes, ensure_ascii=False),
             _ts(effective), snapshot_version, body_hash, now_ms()))
        _event(conn, "permit_snapshot_imported", {
            "actor": user["id"], "inst_id": subject["inst_id"],
            "detail": {"snapshot_id": cur.lastrowid, "permit_id": body["permit_id"],
                       "basis_version": basis_version, "snapshot_version": snapshot_version},
        })
        conn.execute("COMMIT")
        return {"id": cur.lastrowid, "idempotent": False}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def import_termination(conn, body, user):
    require_role(user, {"compliance"})
    required = ("permit_id", "terminated_at", "reason", "snapshot_version")
    missing = [k for k in required if body.get(k) in (None, "")]
    if missing:
        raise ServiceError("missing_fields", f"缺少字段：{', '.join(missing)}")
    terminated = parse_ts(body["terminated_at"], "terminated_at")
    snapshot_version = int(body["snapshot_version"])
    begin_tx(conn)
    try:
        snap = conn.execute(
            "SELECT * FROM permit_snapshots WHERE permit_id=? ORDER BY snapshot_version DESC, id DESC",
            (body["permit_id"],),
        ).fetchone()
        if not snap:
            conn.execute("ROLLBACK")
            raise ServiceError("permit_snapshot_missing",
                               "终止事件必须引用已导入的许可历史快照", 409)
        duplicate = conn.execute(
            "SELECT id FROM permit_terminations WHERE permit_id=? AND terminated_at=? "
            "AND reason=? AND snapshot_version=?",
            (body["permit_id"], _ts(terminated), body["reason"], snapshot_version),
        ).fetchone()
        if duplicate:
            conn.execute("ROLLBACK")
            return {"id": duplicate["id"], "idempotent": True}
        cur = conn.execute(
            "INSERT INTO permit_terminations(permit_id,family,basis_version,subject_id,inst_id,"
            "terminated_at,reason,snapshot_version,imported_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (snap["permit_id"], snap["family"], snap["basis_version"], snap["subject_id"],
             snap["inst_id"], _ts(terminated), body["reason"], snapshot_version, now_ms()))
        _event(conn, "permit_termination_imported", {
            "actor": user["id"], "inst_id": snap["inst_id"],
            "detail": {"permit_id": body["permit_id"], "terminated_at": _ts(terminated)},
        })
        conn.execute("COMMIT")
        return {"id": cur.lastrowid, "idempotent": False}
    except Exception:
        conn.execute("ROLLBACK")
        raise


# ---------------- 执行声明接收、幂等、更正链 ----------------

REQUIRED_CLAIM_FIELDS = (
    "claim_id", "source_system", "source_claim_code", "subject_id", "neutral_op",
    "purpose", "occurred_at", "basis_family", "basis_version",
)


def normalize_claim(body):
    if not isinstance(body, dict):
        raise ServiceError("bad_claim", "声明必须是对象")
    missing = [k for k in REQUIRED_CLAIM_FIELDS if body.get(k) in (None, "")]
    if missing:
        raise ServiceError("bad_claim", f"声明缺少字段：{', '.join(missing)}")
    if body["source_system"] not in SOURCE_SYSTEMS:
        raise ServiceError("bad_source_system", f"未知来源系统：{body['source_system']}")
    if body["neutral_op"] not in NEUTRAL_OPS:
        raise ServiceError("bad_neutral_op", f"未知中性操作码：{body['neutral_op']}")
    occurred = parse_ts(body["occurred_at"], "occurred_at")
    basis_version = int(body["basis_version"])
    if basis_version < 1:
        raise ServiceError("bad_basis_version", "依据版本必须为正整数")
    payload = body.get("payload")
    if payload is not None and not isinstance(payload, dict):
        raise ServiceError("bad_payload", "payload 必须是对象")
    clean = {
        "claim_id": str(body["claim_id"]),
        "source_system": body["source_system"],
        "source_claim_code": str(body["source_claim_code"]),
        "subject_id": str(body["subject_id"]),
        "neutral_op": body["neutral_op"],
        "purpose": str(body["purpose"]),
        "occurred_at": _ts(occurred),
        "basis_family": str(body["basis_family"]),
        "basis_version": basis_version,
        "payload": payload or {},
    }
    replaces = body.get("replaces_version")
    if replaces is not None:
        replaces = int(replaces)
        if replaces < 1:
            raise ServiceError("bad_replaces_version", "replaces_version 必须为正整数")
    return clean, replaces, claim_body_hash(clean)


def _receipt():
    return "R-" + secrets.token_hex(12)


def _claim_view(row):
    d = dict(row)
    d["payload"] = _loads(d.pop("payload_json"), {})
    return d


def _record_rejected(conn, claim_id, version_no, body_hash, code, receipt, batch_id, source):
    conn.execute(
        "INSERT INTO claim_attempts(claim_id,version_no,body_hash,accepted,receipt,"
        "reject_code,batch_id,source_system,received_at) VALUES(?,?,?,0,?,?,?,?,?)",
        (claim_id, version_no, body_hash, receipt, code, batch_id, source, now_ms()),
    )


def ingest_claim(conn, body, user, *, batch_id=None, batch_conn_check=None):
    """接收单笔声明。批量模式由调用方预先完成全量校验并持有同一事务。"""
    if user["role"] not in {"compliance", "site"}:
        raise ServiceError("forbidden", "只有来源系统/合规人员可上报执行声明", 403)
    clean, replaces, digest = normalize_claim(body)
    subject = _get_subject(conn, clean["subject_id"])
    if user["role"] == "site" and subject["inst_id"] != user["inst_id"]:
        raise ServiceError("cross_institution", "不能替其他机构对象上报声明", 409)
    clean["inst_id"] = subject["inst_id"]

    external_tx = batch_conn_check is not None
    if not external_tx:
        begin_tx(conn)
    try:
        prior_accept = conn.execute(
            "SELECT receipt,version_no,accepted,reject_code FROM claim_attempts "
            "WHERE claim_id=? AND body_hash=? AND accepted=1 ORDER BY id LIMIT 1",
            (clean["claim_id"], digest),
        ).fetchone()
        if not prior_accept and replaces is None:
            prior_accept = conn.execute(
                "SELECT receipt,version_no,accepted,reject_code FROM claim_attempts "
                "WHERE claim_id=? AND body_hash=? AND accepted=0 AND version_no IS NULL "
                "ORDER BY id LIMIT 1", (clean["claim_id"], digest)).fetchone()
        elif not prior_accept and replaces is not None:
            prior_accept = conn.execute(
                "SELECT receipt,version_no,accepted,reject_code FROM claim_attempts "
                "WHERE claim_id=? AND body_hash=? AND accepted=0 AND version_no=? "
                "ORDER BY id LIMIT 1", (clean["claim_id"], digest, replaces)).fetchone()
        if prior_accept:
            accepted = bool(prior_accept["accepted"])
            if not external_tx:
                conn.execute("ROLLBACK")
            result = {"receipt": prior_accept["receipt"], "claim_id": clean["claim_id"],
                      "version_no": prior_accept["version_no"], "accepted": accepted}
            if accepted:
                result["replayed"] = True
            else:
                result["reject_code"] = prior_accept["reject_code"]
                result["status_code"] = 409
            return result

        current = conn.execute("SELECT * FROM claim_current WHERE claim_id=?",
                               (clean["claim_id"],)).fetchone()
        receipt = _receipt()

        if current and replaces is None:
            # 同标识异文：不允许把它悄悄当成新正文；必须显式更正。
            _record_rejected(conn, clean["claim_id"], None, digest,
                             "claim_identifier_conflict", receipt, batch_id,
                             clean["source_system"])
            if not external_tx:
                conn.execute("COMMIT")
            return {"receipt": receipt, "claim_id": clean["claim_id"], "accepted": False,
                    "reject_code": "claim_identifier_conflict", "status_code": 409}

        if current and replaces is not None:
            if replaces != current["current_version"]:
                _record_rejected(conn, clean["claim_id"], replaces, digest,
                                 "correction_chain_conflict", receipt, batch_id,
                                 clean["source_system"])
                if not external_tx:
                    conn.execute("COMMIT")
                return {"receipt": receipt, "claim_id": clean["claim_id"], "accepted": False,
                        "reject_code": "correction_chain_conflict",
                        "expected_version": current["current_version"], "status_code": 409}
            if current["current_body_hash"] == digest:
                prior = conn.execute(
                    "SELECT receipt,version_no FROM claim_attempts WHERE claim_id=? "
                    "AND body_hash=? AND accepted=1",
                    (clean["claim_id"], digest)).fetchone()
                if not external_tx:
                    conn.execute("ROLLBACK")
                return {"receipt": prior["receipt"], "claim_id": clean["claim_id"],
                        "version_no": prior["version_no"], "replayed": True, "accepted": True}
            version_no = current["current_version"] + 1
        elif replaces is not None:
            _record_rejected(conn, clean["claim_id"], replaces, digest,
                             "correction_predecessor_missing", receipt, batch_id,
                             clean["source_system"])
            if not external_tx:
                conn.execute("COMMIT")
            return {"receipt": receipt, "claim_id": clean["claim_id"], "accepted": False,
                    "reject_code": "correction_predecessor_missing", "status_code": 409}
        else:
            version_no = 1

        ts = now_ms()
        conn.execute(
            "INSERT INTO claim_versions(claim_id,version_no,source_system,source_claim_code,"
            "subject_id,inst_id,neutral_op,purpose,occurred_at,basis_family,basis_version,"
            "payload_json,body_hash,replaces_version,received_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (clean["claim_id"], version_no, clean["source_system"], clean["source_claim_code"],
             clean["subject_id"], clean["inst_id"], clean["neutral_op"], clean["purpose"],
             clean["occurred_at"], clean["basis_family"], clean["basis_version"],
             json.dumps(clean["payload"], ensure_ascii=False), digest, replaces, ts))
        conn.execute(
            "INSERT INTO claim_attempts(claim_id,version_no,body_hash,accepted,receipt,"
            "reject_code,batch_id,source_system,received_at) VALUES(?,?,?,1,?,?,?,?,?)",
            (clean["claim_id"], version_no, digest, receipt, None, batch_id,
             clean["source_system"], ts))
        if current:
            conn.execute(
                "UPDATE claim_current SET current_version=?,current_body_hash=?,receipt=?,"
                "updated_at=? WHERE claim_id=?",
                (version_no, digest, receipt, ts, clean["claim_id"]))
        else:
            conn.execute(
                "INSERT INTO claim_current(claim_id,current_version,current_body_hash,receipt,"
                "first_received_at,updated_at) VALUES(?,?,?,?,?,?)",
                (clean["claim_id"], version_no, digest, receipt, ts, ts))
        if not external_tx:
            _event(conn, "claim_ingested", {"actor": user["id"], "inst_id": clean["inst_id"],
                                            "detail": {"claim_id": clean["claim_id"],
                                                       "version_no": version_no}})
            conn.execute("COMMIT")
        return {"receipt": receipt, "claim_id": clean["claim_id"], "version_no": version_no,
                "accepted": True, "replayed": False}
    except Exception:
        if not external_tx:
            conn.execute("ROLLBACK")
        raise


def ingest_batch(conn, body, user):
    if user["role"] not in {"compliance", "site"}:
        raise ServiceError("forbidden", "无权批量上报", 403)
    raw_items = body.get("claims")
    if not isinstance(raw_items, list) or not raw_items:
        raise ServiceError("bad_batch", "claims 必须是非空数组")
    normalized = []
    seen_ids = set()
    institutions = set()
    # 先完整验证：任一格式损坏/跨机构对象，整个批次不进入事务、不留半条记录。
    for item in raw_items:
        clean, replaces, digest = normalize_claim(item)
        if clean["claim_id"] in seen_ids:
            raise ServiceError("batch_duplicate_claim",
                               f"批次内声明标识重复：{clean['claim_id']}")
        seen_ids.add(clean["claim_id"])
        subject = _get_subject(conn, clean["subject_id"])
        if user["role"] == "site" and subject["inst_id"] != user["inst_id"]:
            raise ServiceError("cross_institution", "批次包含跨机构对象，整批回滚", 409)
        institutions.add(subject["inst_id"])
        clean["inst_id"] = subject["inst_id"]
        normalized.append((clean, replaces, digest))
    if len(institutions) > 1:
        raise ServiceError("cross_institution", "批次包含多个机构对象，整批回滚", 409)

    batch_id = "B-" + secrets.token_hex(10)
    begin_tx(conn)
    try:
        receipts = []
        # 成组提交：任何数据库级冲突都会抛异常并 ROLLBACK，整批不可见。
        for item, _replaces, _digest in normalized:
            # 重新构造原始字段供统一入口使用。
            claim_input = {**item, "replaces_version": _replaces}
            result = ingest_claim(conn, claim_input, user, batch_id=batch_id,
                                  batch_conn_check=True)
            if not result.get("accepted"):
                raise ServiceError(result["reject_code"], "批次内存在冲突声明，整批回滚", 409)
            receipts.append(result)
        conn.execute(
            "INSERT INTO import_batches(id,status,item_count,operator_id,created_at) "
            "VALUES(?, 'accepted', ?, ?, ?)",
            (batch_id, len(normalized), user["id"], now_ms()))
        _event(conn, "claim_batch_accepted", {
            "actor": user["id"], "inst_id": next(iter(institutions)),
            "detail": {"batch_id": batch_id, "count": len(normalized)},
        })
        conn.execute("COMMIT")
        return {"batch_id": batch_id, "accepted": True, "count": len(normalized),
                "receipts": receipts}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def get_claim(conn, claim_id, user):
    rows = conn.execute(
        "SELECT * FROM claim_versions WHERE claim_id=? ORDER BY version_no", (claim_id,)
    ).fetchall()
    if not rows:
        raise ServiceError("claim_not_found", "执行声明不存在", 404)
    if user["role"] == "site" and any(r["inst_id"] != user["inst_id"] for r in rows):
        raise ServiceError("claim_not_found", "执行声明不存在", 404)
    if user["role"] == "subject":
        subject = subject_for_user(conn, user)
        if any(r["subject_id"] != subject["id"] for r in rows):
            raise ServiceError("forbidden", "只能查看本人声明", 403)
    current = conn.execute("SELECT * FROM claim_current WHERE claim_id=?", (claim_id,)).fetchone()
    attempts = [dict(r) for r in conn.execute(
        "SELECT version_no,accepted,receipt,reject_code,source_system,received_at "
        "FROM claim_attempts WHERE claim_id=? ORDER BY id", (claim_id,))]
    versions = [_claim_view(r) for r in rows]
    for idx, version in enumerate(versions):
        version["diff_from_previous"] = None if idx == 0 else _claim_diff(
            versions[idx - 1], version)
    return {"claim_id": claim_id, "current_version": current["current_version"],
            "receipt": current["receipt"], "versions": versions, "attempts": attempts}


def _claim_diff(old, new):
    fields = ("source_system", "source_claim_code", "subject_id", "neutral_op", "purpose",
              "occurred_at", "basis_family", "basis_version", "payload")
    return {f: {"from": old.get(f), "to": new.get(f)}
            for f in fields if old.get(f) != new.get(f)}


# ---------------- 周期与时间点对账 ----------------

def create_cycle(conn, body, user):
    require_role(user, {"compliance"})
    cycle_id = str(body.get("id") or "C-" + secrets.token_hex(6))
    start = parse_ts(body["starts_at"], "starts_at")
    end = parse_ts(body["ends_at"], "ends_at")
    if end <= start:
        raise ServiceError("bad_cycle_range", "周期结束时刻必须晚于开始时刻")
    begin_tx(conn)
    try:
        try:
            conn.execute("INSERT INTO cycles(id,starts_at,ends_at,created_at) VALUES(?,?,?,?)",
                         (cycle_id, _ts(start), _ts(end), now_ms()))
        except Exception:
            conn.execute("ROLLBACK")
            raise ServiceError("cycle_exists", "对账周期已存在", 409)
        conn.execute("COMMIT")
        return get_cycle(conn, cycle_id, user)
    except Exception:
        conn.execute("ROLLBACK")
        raise


def get_cycle(conn, cycle_id, user=None):
    row = conn.execute("SELECT * FROM cycles WHERE id=?", (cycle_id,)).fetchone()
    if not row:
        raise ServiceError("cycle_not_found", "对账周期不存在", 404)
    d = dict(row)
    latest = conn.execute(
        "SELECT * FROM reconciliation_versions WHERE cycle_id=? ORDER BY version_no DESC LIMIT 1",
        (cycle_id,)).fetchone()
    d["latest_version_no"] = latest["version_no"] if latest else None
    return d


def list_cycles(conn, user):
    if user["role"] == "subject":
        subject = subject_for_user(conn, user)
        rows = conn.execute(
            "SELECT DISTINCT c.* FROM cycles c JOIN reconciliation_items i ON i.cycle_id=c.id "
            "WHERE i.subject_id=? ORDER BY c.starts_at DESC", (subject["id"],)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM cycles ORDER BY starts_at DESC").fetchall()
    out = []
    for row in rows:
        d = dict(row)
        latest = conn.execute(
            "SELECT version_no FROM reconciliation_versions WHERE cycle_id=? "
            "ORDER BY version_no DESC LIMIT 1", (row["id"],)).fetchone()
        d["latest_version_no"] = latest["version_no"] if latest else None
        out.append(d)
    return out


def _current_claims(conn, cycle):
    return conn.execute(
        """SELECT v.* FROM claim_versions v
           JOIN claim_current c
             ON c.claim_id=v.claim_id AND c.current_version=v.version_no
           WHERE v.occurred_at >= ? AND v.occurred_at < ?
           ORDER BY v.occurred_at, v.claim_id""",
        (cycle["starts_at"], cycle["ends_at"]),
    ).fetchall()


def _basis_watermark(conn):
    snap = conn.execute("SELECT COALESCE(MAX(snapshot_version),0) n FROM permit_snapshots").fetchone()["n"]
    term = conn.execute("SELECT COALESCE(MAX(snapshot_version),0) n FROM permit_terminations").fetchone()["n"]
    return max(snap, term)


def classify_claim(conn, claim, watermark):
    occurred = parse_ts(claim["occurred_at"])
    cited = conn.execute(
        """SELECT * FROM permit_snapshots
           WHERE subject_id=? AND family=? AND basis_version=? AND effective_at <= ?
           ORDER BY snapshot_version DESC, id DESC LIMIT 1""",
        (claim["subject_id"], claim["basis_family"], claim["basis_version"],
         claim["occurred_at"]),
    ).fetchone()
    future = None
    if cited is None:
        future = conn.execute(
            """SELECT * FROM permit_snapshots
               WHERE subject_id=? AND family=? AND basis_version=?
               ORDER BY effective_at ASC, snapshot_version DESC, id DESC LIMIT 1""",
            (claim["subject_id"], claim["basis_family"], claim["basis_version"]),
        ).fetchone()
        if future is not None and parse_ts(future["effective_at"]) <= occurred:
            # 理论上不会发生：上面的生效中查询应已命中。防御并发导入边界。
            cited, future = future, None

    def item(result, detail, snap=None):
        return {
            "result": result, "detail": detail, "matched_snapshot_id": snap["id"] if snap else None,
            "matched_basis_version": snap["basis_version"] if snap else None,
            "matched_permit_id": snap["permit_id"] if snap else None,
        }

    if cited is None and future is not None:
        return item("missing_basis", {
            "reason": "basis_not_effective_at_occurrence",
            "effective_at": future["effective_at"],
            "note": "后补资料已经到达，但其生效时刻晚于行为，不能追认合规",
        }, future)
    if cited is None:
        return item("awaiting_late_material", {
            "reason": "cited_snapshot_not_yet_available",
            "later_effective_snapshot_exists": False,
            "note": "等待许可引擎补送当时资料；若资料生效时刻晚于行为，后续版本也不得追认",
        })

    if parse_ts(cited["effective_at"]) > occurred:
        return item("missing_basis", {
            "reason": "basis_not_effective_at_occurrence",
            "effective_at": cited["effective_at"],
        }, cited)

    termination = conn.execute(
        "SELECT * FROM permit_terminations WHERE permit_id=? AND terminated_at <= ? "
        "ORDER BY terminated_at DESC, id DESC LIMIT 1",
        (cited["permit_id"], claim["occurred_at"]),
    ).fetchone()
    if termination:
        return item("post_termination", {
            "reason": "permit_terminated_before_occurrence",
            "terminated_at": termination["terminated_at"],
            "termination_reason": termination["reason"],
        }, cited)

    scope = _loads(cited["scope_json"], [])
    allowed_purposes = _loads(cited["allowed_purposes_json"], [])
    if claim["neutral_op"] not in scope:
        return item("out_of_scope", {
            "reason": "neutral_op_not_in_scope", "allowed_ops": scope,
        }, cited)
    if allowed_purposes and claim["purpose"] not in allowed_purposes:
        return item("out_of_scope", {
            "reason": "purpose_not_allowed", "allowed_purposes": allowed_purposes,
        }, cited)

    return item("explained", {"reason": "exact_time_subject_op_purpose_basis_match"}, cited)


def _mark_stale_dispositions(conn, cycle_id, new_version_id, new_items):
    new_by_claim = {item["claim_id"]: item for item in new_items}
    old_rows = conn.execute(
        """SELECT d.*, i.claim_version_no AS old_claim_version, i.claim_body_hash,
                  i.result AS old_result, i.matched_permit_id AS old_permit,
                  i.matched_basis_version AS old_basis, i.matched_snapshot_id AS old_snapshot,
                  i.detail_json AS old_detail
           FROM dispositions d JOIN reconciliation_items i ON i.id=d.item_id
           WHERE d.cycle_id=? AND d.review_status='current'
             AND i.version_id != ?""",
        (cycle_id, new_version_id),
    ).fetchall()
    ts = now_ms()
    for old in old_rows:
        new = new_by_claim.get(old["claim_id"])
        reason = None
        if new is None:
            reason = "claim_no_longer_in_cycle_inputs"
        elif new["claim_body_hash"] != old["claim_body_hash"]:
            reason = "source_claim_changed"
        elif new["result"] != old["old_result"] \
                or new["matched_permit_id"] != old["old_permit"] \
                or new["matched_basis_version"] != old["old_basis"] \
                or new["matched_snapshot_id"] != old["old_snapshot"] \
                or canonical_dumps(new["detail"]) != old["old_detail"]:
            reason = "consent_snapshot_or_classification_changed"
        if reason:
            conn.execute(
                "UPDATE dispositions SET review_status='stale_pending_review',"
                "stale_reason=?,marked_stale_at=? WHERE id=? AND review_status='current'",
                (reason, ts, old["id"]))


def build_candidate(conn, cycle):
    """在写事务外只读计算候选结果；未落盘候选天然不可见。"""
    claims = _current_claims(conn, cycle)
    watermark = _basis_watermark(conn)
    classified = []
    for idx, claim in enumerate(claims, start=1):
        verdict = classify_claim(conn, claim, watermark)
        classified.append({
            "item_no": idx,
            "claim_id": claim["claim_id"],
            "claim_version_no": claim["version_no"],
            "subject_id": claim["subject_id"],
            "inst_id": claim["inst_id"],
            "neutral_op": claim["neutral_op"],
            "purpose": claim["purpose"],
            "occurred_at": claim["occurred_at"],
            "basis_family": claim["basis_family"],
            "basis_version": claim["basis_version"],
            "claim_body_hash": claim["body_hash"],
            "basis_snapshot_watermark": watermark,
            **verdict,
        })
    received_high = conn.execute(
        "SELECT COALESCE(MAX(received_at),'') n FROM claim_versions "
        "WHERE occurred_at >= ? AND occurred_at < ?",
        (cycle["starts_at"], cycle["ends_at"])).fetchone()["n"]
    watermarks = {
        "basis_snapshot_version": watermark,
        "claims_received_high_watermark": received_high,
        "claim_count": len(classified),
    }
    canonical_rows = [{k: row[k] for k in (
        "claim_id", "claim_version_no", "subject_id", "neutral_op", "purpose",
        "occurred_at", "basis_family", "basis_version", "claim_body_hash", "result",
        "matched_snapshot_id", "matched_basis_version", "matched_permit_id",
    )} for row in classified]
    input_hash = sha256_text(canonical_dumps({
        "cycle": {"id": cycle["id"], "starts_at": cycle["starts_at"],
                  "ends_at": cycle["ends_at"]},
        "watermarks": watermarks,
        "rows": canonical_rows,
    }))
    return {"items": classified, "watermarks": watermarks,
            "canonical_rows": canonical_rows, "input_hash": input_hash}


def _publish_candidate(conn, cycle, owner, job_id, candidate, crash_after_publish=False):
    classified = candidate["items"]
    watermarks = candidate["watermarks"]
    input_hash = candidate["input_hash"]
    latest = conn.execute(
        "SELECT * FROM reconciliation_versions WHERE cycle_id=? ORDER BY version_no DESC LIMIT 1",
        (cycle["id"],)).fetchone()
    if latest and latest["input_hash"] == input_hash:
        conn.execute(
            "UPDATE reconciliation_jobs SET status='failed',finished_at=?,"
            "published_version_id=?,error='inputs_unchanged' WHERE id=?",
            (now_ms(), latest["id"], job_id))
        conn.execute("COMMIT")
        return latest["id"], True

    version_no = (latest["version_no"] + 1) if latest else 1
    counts = {key: 0 for key in RESULT_LABELS}
    for row in classified:
        counts[row["result"]] += 1
    published_at = now_ms()
    cur = conn.execute(
        "INSERT INTO reconciliation_versions(cycle_id,version_no,input_watermark_json,"
        "input_hash,claim_count,counts_json,published_at) VALUES(?,?,?,?,?,?,?)",
        (cycle["id"], version_no, json.dumps(watermarks, ensure_ascii=False), input_hash,
         len(classified), json.dumps(counts, ensure_ascii=False), published_at))
    version_id = cur.lastrowid
    for row in classified:
        conn.execute(
            "INSERT INTO reconciliation_items(version_id,cycle_id,item_no,claim_id,"
            "claim_version_no,subject_id,inst_id,neutral_op,purpose,occurred_at,basis_family,"
            "basis_version,result,matched_snapshot_id,matched_basis_version,matched_permit_id,"
            "detail_json,claim_body_hash,basis_snapshot_watermark) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (version_id, cycle["id"], row["item_no"], row["claim_id"], row["claim_version_no"],
             row["subject_id"], row["inst_id"], row["neutral_op"], row["purpose"],
             row["occurred_at"], row["basis_family"], row["basis_version"], row["result"],
             row["matched_snapshot_id"], row["matched_basis_version"], row["matched_permit_id"],
             json.dumps(row["detail"], ensure_ascii=False), row["claim_body_hash"],
             row["basis_snapshot_watermark"]))
    _mark_stale_dispositions(conn, cycle["id"], version_id, classified)
    conn.execute(
        "UPDATE reconciliation_jobs SET status='published',published_version_id=?,"
        "finished_at=? WHERE id=?", (version_id, now_ms(), job_id))
    _event(conn, "reconciliation_published", {"actor": owner, "cycle_id": cycle["id"],
                                              "detail": {"version_id": version_id,
                                                         "version_no": version_no,
                                                         "counts": counts}})
    conn.execute("COMMIT")
    if crash_after_publish:
        # 测试钩子：版本已 fsync 提交，响应尚未发出。重启后必须直接识别该版本。
        os._exit(97)
    return version_id, False


def recompute(conn, cycle_id, user, crash_after_publish=False):
    require_role(user, {"compliance"})
    cycle = get_cycle(conn, cycle_id, user)
    candidate = build_candidate(conn, cycle)
    latest = conn.execute(
        "SELECT * FROM reconciliation_versions WHERE cycle_id=? ORDER BY version_no DESC LIMIT 1",
        (cycle_id,)).fetchone()
    if latest and latest["input_hash"] == candidate["input_hash"]:
        # 输入未变化（含崩溃重启）：识别已发布版本，不再插入任何差异项。
        return version_view(conn, latest["id"], user)

    job_id = "J-" + secrets.token_hex(10)
    owner = user["id"]
    begin_tx(conn)
    try:
        now = datetime.now(timezone.utc)
        active = conn.execute(
            "SELECT * FROM reconciliation_jobs WHERE cycle_id=? AND status='running'",
            (cycle_id,)).fetchone()
        if active:
            if parse_ts(active["lease_expires_at"]) > now:
                conn.execute("ROLLBACK")
                raise ServiceError("reconciliation_running",
                                   "另一个重算进程正在处理同一周期", 409)
            updated = conn.execute(
                "UPDATE reconciliation_jobs SET owner=?,lease_expires_at=? "
                "WHERE id=? AND status='running'",
                (owner, _ts(now + timedelta(seconds=LEASE_SECONDS)), active["id"]))
            if updated.rowcount != 1:
                conn.execute("ROLLBACK")
                raise ServiceError("reconciliation_lease_lost", "重算租约竞争失败", 409)
            job_id = active["id"]
        else:
            try:
                conn.execute(
                    "INSERT INTO reconciliation_jobs(id,cycle_id,owner,lease_expires_at,status,"
                    "started_at) VALUES(?,?,?,?,'running',?)",
                    (job_id, cycle_id, owner,
                     _ts(now + timedelta(seconds=LEASE_SECONDS)), _ts(now)))
            except Exception:
                conn.execute("ROLLBACK")
                raise ServiceError("reconciliation_running",
                                   "另一个重算进程正在处理同一周期", 409)

        latest_after_lock = conn.execute(
            "SELECT * FROM reconciliation_versions WHERE cycle_id=? ORDER BY version_no DESC LIMIT 1",
            (cycle_id,)).fetchone()
        if latest_after_lock and latest_after_lock["input_hash"] == candidate["input_hash"]:
            # 竞争者已用相同输入发布：本进程只返回权威版本，不再发布第二份。
            conn.execute(
                "UPDATE reconciliation_jobs SET status='failed',finished_at=?,"
                "published_version_id=?,error='published_by_competing_process' WHERE id=?",
                (now_ms(), latest_after_lock["id"], job_id))
            conn.execute("COMMIT")
            return version_view(conn, latest_after_lock["id"], user)

        version_id, _unchanged = _publish_candidate(
            conn, cycle, owner, job_id, candidate,
            crash_after_publish=crash_after_publish)
        return version_view(conn, version_id, user)
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise

def _item_dict(row):
    d = dict(row)
    d["detail"] = _loads(d.pop("detail_json"), {})
    d["result_label"] = RESULT_LABELS[d["result"]]
    d["disposition"] = None
    return d


def version_view(conn, version_id, user=None):
    version = conn.execute("SELECT * FROM reconciliation_versions WHERE id=?",
                           (version_id,)).fetchone()
    if not version:
        raise ServiceError("version_not_found", "对账版本不存在", 404)
    sql = "SELECT * FROM reconciliation_items WHERE version_id=? ORDER BY item_no"
    args = [version_id]
    if user and user["role"] == "site":
        sql = "SELECT * FROM reconciliation_items WHERE version_id=? AND inst_id=? ORDER BY item_no"
        args.append(user["inst_id"])
    elif user and user["role"] == "subject":
        subject = subject_for_user(conn, user)
        sql = "SELECT * FROM reconciliation_items WHERE version_id=? AND subject_id=? ORDER BY item_no"
        args.append(subject["id"])
    items = [_item_dict(r) for r in conn.execute(sql, args).fetchall()]
    disp_rows = conn.execute(
        "SELECT * FROM dispositions WHERE version_id=? ORDER BY id", (version_id,)).fetchall()
    if user and user["role"] == "site":
        disp_rows = [r for r in disp_rows if any(i["claim_id"] == r["claim_id"] for i in items)]
    disps = {r["item_id"]: dict(r) for r in disp_rows}
    for item in items:
        item["disposition"] = disps.get(item["id"])
    d = dict(version)
    d["input_watermark"] = _loads(d.pop("input_watermark_json"), {})
    d["counts"] = _loads(d.pop("counts_json"), {})
    d["items"] = items
    return d


def latest_version(conn, cycle_id, user):
    get_cycle(conn, cycle_id, user)
    row = conn.execute(
        "SELECT id FROM reconciliation_versions WHERE cycle_id=? ORDER BY version_no DESC LIMIT 1",
        (cycle_id,)).fetchone()
    if not row:
        raise ServiceError("version_not_published", "该周期尚未发布对账版本", 404)
    return version_view(conn, row["id"], user)


# ---------------- 处置与复核 ----------------

def dispose_item(conn, item_id, body, user):
    require_role(user, {"compliance"})
    resolution = body.get("resolution")
    reason = str(body.get("reason") or "").strip()
    snapshot_version = body.get("adopted_snapshot_version")
    if resolution not in {
        "accepted_justified", "documented_exception", "corrective_action",
        "escalated", "dismissed",
    }:
        raise ServiceError("bad_resolution", "处置结论无效")
    if not reason:
        raise ServiceError("reason_required", "处置理由必填")
    if snapshot_version is None:
        raise ServiceError("snapshot_version_required", "处置必须记录采用的快照版本")
    snapshot_version = int(snapshot_version)
    item = conn.execute("SELECT * FROM reconciliation_items WHERE id=?", (item_id,)).fetchone()
    if not item:
        raise ServiceError("item_not_found", "差异项不存在", 404)
    if item["result"] == "explained":
        raise ServiceError("item_not_disposable", "已解释项不需要处置", 409)
    latest = conn.execute(
        "SELECT id FROM reconciliation_versions WHERE cycle_id=? ORDER BY version_no DESC LIMIT 1",
        (item["cycle_id"],)).fetchone()
    if not latest or latest["id"] != item["version_id"]:
        raise ServiceError("version_superseded", "只能处置最新对账版本中的差异项", 409)
    existing = conn.execute(
        "SELECT id FROM dispositions WHERE item_id=?", (item_id,)).fetchone()
    if existing:
        raise ServiceError("disposition_exists", "该差异项已有处置；新版本会生成新差异项", 409)
    if snapshot_version < item["basis_snapshot_watermark"]:
        raise ServiceError("snapshot_version_too_old",
                           "采用快照版本不能早于该对账版本的输入水位", 409)
    begin_tx(conn)
    try:
        cur = conn.execute(
            "INSERT INTO dispositions(item_id,version_id,cycle_id,claim_id,resolution,reason,"
            "adopted_snapshot_version,decided_by,decided_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (item["id"], item["version_id"], item["cycle_id"], item["claim_id"], resolution,
             reason, snapshot_version, user["id"], now_ms()))
        conn.execute("COMMIT")
        return {"id": cur.lastrowid, "review_status": "current"}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def review_stale_disposition(conn, disposition_id, body, user):
    require_role(user, {"compliance"})
    note = str(body.get("review_note") or "").strip()
    if not note:
        raise ServiceError("review_note_required", "复核意见必填")
    row = conn.execute("SELECT * FROM dispositions WHERE id=?", (disposition_id,)).fetchone()
    if not row:
        raise ServiceError("disposition_not_found", "处置记录不存在", 404)
    if row["review_status"] != "stale_pending_review":
        raise ServiceError("disposition_not_stale", "该处置当前不是待复核状态", 409)
    begin_tx(conn)
    try:
        # 只补复核元数据；原 resolution/reason/snapshot_version 永不覆盖。
        conn.execute(
            "UPDATE dispositions SET review_note=?,reviewed_at=? WHERE id=?",
            (note, now_ms(), disposition_id))
        conn.execute("COMMIT")
        return {"id": disposition_id, "review_status": "stale_pending_review",
                "review_note": note}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def list_stale_dispositions(conn, user):
    require_role(user, {"compliance"})
    return [dict(r) for r in conn.execute(
        "SELECT * FROM dispositions WHERE review_status='stale_pending_review' "
        "ORDER BY marked_stale_at DESC")]


def subject_basis_view(conn, user):
    subject = subject_for_user(conn, user)
    permits = [dict(r) for r in conn.execute(
        "SELECT id,permit_id,family,basis_version,scope_json,allowed_purposes_json,"
        "effective_at,snapshot_version,body_hash,imported_at FROM permit_snapshots "
        "WHERE subject_id=? ORDER BY effective_at,basis_version", (subject["id"],))]
    for p in permits:
        p["scope"] = _loads(p.pop("scope_json"), [])
        p["allowed_purposes"] = _loads(p.pop("allowed_purposes_json"), [])
        p["terminations"] = [dict(r) for r in conn.execute(
            "SELECT terminated_at,reason,snapshot_version,imported_at "
            "FROM permit_terminations WHERE permit_id=? ORDER BY terminated_at",
            (p["permit_id"],))]
    items = []
    rows = conn.execute(
        """SELECT i.*, v.version_no AS reconciliation_version, v.published_at
           FROM reconciliation_items i
           JOIN reconciliation_versions v ON v.id=i.version_id
           WHERE i.subject_id=? ORDER BY i.occurred_at, v.version_no""",
        (subject["id"],)).fetchall()
    for row in rows:
        item = _item_dict(row)
        item["reconciliation_version"] = row["reconciliation_version"]
        item["published_at"] = row["published_at"]
        items.append(item)
    return {"subject": {"id": subject["id"], "name": subject["name"]},
            "permits": permits, "executions": items}

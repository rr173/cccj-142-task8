"""领域引擎：材料封存发布、签署会话、许可评估、再次同意、撤销/执行竞争。

所有写操作都在单个 BEGIN IMMEDIATE 事务内完成“读状态→判定→落盘→写事件流水”，
因此撤销与执行、双终端重复落款等竞争只按持久化先后收敛为一个结果。
"""
import json
import secrets
import hashlib
from datetime import datetime, timezone

from db import get_conn, begin_tx, now, seal_body, track_key
import trust

KNOWN_OPS = ["blood_draw", "imaging", "medication", "sample_reuse"]
KNOWN_ROLES = ["subject", "witness", "site_owner"]
ROLE_LABELS = {"subject": "参与人", "witness": "见证者", "site_owner": "现场负责人"}


class EngineError(Exception):
    def __init__(self, code, message, http=400):
        super().__init__(message)
        self.code = code
        self.http = http


def _j(row, key, default=None):
    if row is None:
        return default
    v = row[key]
    return json.loads(v) if v is not None else default


def _evt(conn, kind, *, inst_id=None, subject_id=None, session_id=None,
         permit_id=None, material_id=None, detail=None):
    conn.execute(
        "INSERT INTO events(ts,inst_id,kind,subject_id,session_id,permit_id,material_id,detail_json)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (now(), inst_id, kind, subject_id, session_id, permit_id, material_id,
         json.dumps(detail or {}, ensure_ascii=False)),
    )


def _idem_get(conn, key, scope):
    r = conn.execute("SELECT response_code,response_body FROM idempotents WHERE key=? AND scope=?",
                     (key, scope)).fetchone()
    return (r["response_code"], json.loads(r["response_body"]), True) if r else None


def _idem_put(conn, key, scope, code, body, *, credential_id=None, device_id=None,
              request_hash=None):
    conn.execute(
        "INSERT OR IGNORE INTO idempotents(key,scope,credential_id,device_id,request_hash,"
        "response_code,response_body,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (key, scope, credential_id, device_id, request_hash, code,
         json.dumps(body, ensure_ascii=False), now()),
    )


# ---------------- 机构 / 对象 / 认证 ----------------

def list_institutions(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM institutions ORDER BY id")]


def get_subject(conn, subject_id):
    r = conn.execute("SELECT * FROM subjects WHERE id=?", (subject_id,)).fetchone()
    if not r:
        raise EngineError("subject_not_found", "参与人对象不存在", 404)
    d = dict(r)
    d["conditions"] = json.loads(d.pop("conditions_json"))
    return d


def list_subjects(conn, inst_id):
    out = []
    for r in conn.execute("SELECT * FROM subjects WHERE inst_id=? ORDER BY id", (inst_id,)):
        d = dict(r)
        d["conditions"] = json.loads(d.pop("conditions_json"))
        out.append(d)
    return out


def authenticate(conn, login, pw):
    from db import hash_pw
    r = conn.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
    if not r or hash_pw(r["pw_salt"], pw) != r["pw_hash"]:
        raise EngineError("bad_credentials", "账号或密码错误", 401)
    token = secrets.token_urlsafe(24)
    conn.execute("INSERT INTO auth_tokens(token,user_id,created_at) VALUES(?,?,?)",
                 (token, r["id"], now()))
    _evt(conn, "login", inst_id=r["inst_id"], detail={"user_id": r["id"], "role": r["role"]})
    return token, dict(r)




def principal_from_token(conn, token):
    r = conn.execute(
        "SELECT u.* FROM auth_tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?",
        (token,)).fetchone()
    if not r:
        raise EngineError("unauthenticated", "未登录或会话已失效", 401)
    d = dict(r)
    return d


# ---------------- 设备可信登记 / 挑战 / 证明 ----------------

CHALLENGE_TTL_SECONDS = 60
CREDENTIAL_DAYS = 365
ENROLLMENT_TTL_SECONDS = 15 * 60
DEVICE_ACTIONS = {
    "session.start": "subject",
    "witness.tokens": "session",
    "sign": "session",
    "revoke": "session",
    "execute": "subject",
}


def _parse_ts(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _sha256_text(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _business_body(body):
    """幂等键是传输层元数据，不参与被设备签署的业务载荷指纹。"""
    if not isinstance(body, dict):
        return {}
    return {k: v for k, v in body.items() if k != "idempotency_key"}


def _new_device_id():
    return "D-" + secrets.token_hex(6)


def _new_credential_id():
    return "DC-" + secrets.token_hex(8)


def _new_challenge_id():
    return "CH-" + secrets.token_hex(8)


def _clean_hardware_id(value):
    value = str(value or "").strip()
    if not 8 <= len(value) <= 128:
        raise EngineError("bad_hardware_id", "设备硬件标识长度需在 8–128 字符之间", 400)
    return value


def _clean_device_label(value):
    value = str(value or "").strip()
    if not 1 <= len(value) <= 60:
        raise EngineError("bad_device_label", "设备名称长度需在 1–60 字符之间", 400)
    return value


def _public_jwk(value):
    try:
        trust.jwk_coordinates(value)
    except trust.TrustError:
        raise EngineError("bad_public_key", "需要 ECDSA P-256 公钥 JWK，且不得携带私钥字段", 400)
    return {
        "kty": "EC", "crv": "P-256",
        "x": value["x"], "y": value["y"],
    }


def _issue_code(conn, *, purpose, owner_type, user=None, slot=None, credential=None):
    if purpose == "register" and owner_type == "witness" and slot is None:
        raise EngineError("bad_enrollment", "见证登记授权必须绑定签署位", 400)
    if purpose == "rotate" and credential is None:
        raise EngineError("bad_enrollment", "轮换授权必须绑定旧凭据", 400)
    plain = secrets.token_urlsafe(24)
    ts = now()
    expires = datetime.now(timezone.utc).timestamp() + ENROLLMENT_TTL_SECONDS
    conn.execute(
        "INSERT INTO device_enrollments(code_hash,purpose,owner_type,user_id,inst_id,"
        "slot_id,credential_id,status,expires_at,created_at) VALUES(?,?,?,?,?,?,?, 'issued',?,?)",
        (_sha256_text(plain), purpose, owner_type,
         user["id"] if user else None, user["inst_id"] if user else None,
         slot["id"] if slot else None, credential["id"] if credential else None,
         datetime.fromtimestamp(expires, timezone.utc).isoformat(), ts))
    detail = {"purpose": purpose, "owner_type": owner_type}
    if user:
        detail["user_id"] = user["id"]
    if slot:
        detail["slot_id"] = slot["id"]
    _evt(conn, "device_enrollment_issued",
         inst_id=user["inst_id"] if user else None,
         session_id=slot["session_id"] if slot else None, detail=detail)
    return plain


def create_user_enrollment(conn, principal, user_id):
    if not principal or principal["role"] != "admin":
        raise EngineError("forbidden", "只有规则维护员可以预发终端登记授权", 403)
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        raise EngineError("user_not_found", "账号不存在", 404)
    begin_tx(conn)
    try:
        code = _issue_code(conn, purpose="register", owner_type="user", user=user)
        conn.execute("COMMIT")
        return {"enrollment_code": code, "user_id": user["id"], "expires_in": ENROLLMENT_TTL_SECONDS}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _active_credential_for_device(conn, device_id):
    return conn.execute(
        """SELECT c.* FROM device_credentials c JOIN devices d ON d.id=c.device_id
           WHERE c.device_id=? AND c.status='active' AND d.status='active'""",
        (device_id,)).fetchone()


def _witness_slot_for_token(conn, session_id, role, token):
    if role != "witness" or not token:
        return None
    slot = conn.execute(
        "SELECT * FROM sign_slots WHERE session_id=? AND role='witness'",
        (session_id,)).fetchone()
    if not slot:
        return None
    if _sha256_text(token) != slot["token_hash"]:
        return None
    return slot


def register_device(conn, body):
    code_text = str(body.get("enrollment_code") or "").strip()
    hardware_id = _clean_hardware_id(body.get("hardware_id"))
    label = _clean_device_label(body.get("device_label"))
    public_jwk = _public_jwk(body.get("public_jwk"))
    csr_sig = str(body.get("csr_sig") or "")
    csr = {
        "alg": "CONSENT-REGISTER-CSR/v1",
        "enrollment_code": code_text,
        "hardware_id": hardware_id,
        "device_label": label,
        "public_jwk": public_jwk,
    }
    if not trust.verify_object(public_jwk, csr, csr_sig):
        raise EngineError("csr_signature_invalid", "终端公钥自证签名无效", 401)

    begin_tx(conn)
    try:
        enr = conn.execute("SELECT * FROM device_enrollments WHERE code_hash=?",
                           (_sha256_text(code_text),)).fetchone()
        if not enr:
            conn.execute("ROLLBACK")
            raise EngineError("enrollment_code_invalid", "终端登记授权无效", 404)
        if enr["status"] != "issued":
            conn.execute("ROLLBACK")
            raise EngineError("enrollment_code_consumed", "终端登记授权已使用或撤销", 409)
        if _parse_ts(enr["expires_at"]) <= datetime.now(timezone.utc):
            conn.execute("ROLLBACK")
            raise EngineError("enrollment_code_expired", "终端登记授权已过期", 410)

        ts = now()
        not_after_ts = datetime.now(timezone.utc).timestamp() + CREDENTIAL_DAYS * 86400
        not_after = datetime.fromtimestamp(not_after_ts, timezone.utc).isoformat()
        public_jwk_json = json.dumps(public_jwk, sort_keys=True, separators=(",", ":"))
        public_hash = trust.canonical_hash(public_jwk)

        if enr["purpose"] == "register":
            if enr["owner_type"] == "user":
                existing = conn.execute(
                    "SELECT * FROM devices WHERE owner_type='user' AND user_id=? AND hardware_id=?",
                    (enr["user_id"], hardware_id)).fetchone()
                if existing:
                    conn.execute("ROLLBACK")
                    raise EngineError("device_already_registered",
                                      "该硬件已登记，请使用轮换授权更换密钥代次", 409)
                user = conn.execute("SELECT * FROM users WHERE id=?", (enr["user_id"],)).fetchone()
                device_id = _new_device_id()
                credential_id = _new_credential_id()
                conn.execute(
                    "INSERT INTO devices(id,owner_type,user_id,inst_id,hardware_id,label,status,"
                    "current_credential_id,created_at) VALUES(?, 'user',?,?,?,?,'active',?,?)",
                    (device_id, user["id"], user["inst_id"], hardware_id, label,
                     credential_id, ts))
                conn.execute(
                    "INSERT INTO device_credentials(id,device_id,generation,user_id,inst_id,"
                    "public_jwk_json,public_key_hash,status,not_after,created_at)"
                    " VALUES(?,?,1,?,?,?,?,'active',?,?)",
                    (credential_id, device_id, user["id"], user["inst_id"],
                     public_jwk_json, public_hash, not_after, ts))
            else:
                slot = conn.execute("SELECT * FROM sign_slots WHERE id=?",
                                    (enr["slot_id"],)).fetchone()
                existing = conn.execute(
                    "SELECT * FROM devices WHERE owner_type='witness' AND slot_id=? AND hardware_id=?",
                    (slot["id"], hardware_id)).fetchone()
                if existing:
                    conn.execute("ROLLBACK")
                    raise EngineError("device_already_registered",
                                      "该见证硬件已登记，请使用轮换授权更换密钥代次", 409)
                session = conn.execute("SELECT * FROM sessions WHERE id=?",
                                       (slot["session_id"],)).fetchone()
                subj = conn.execute("SELECT inst_id FROM subjects WHERE id=?",
                                    (session["subject_id"],)).fetchone()
                device_id = _new_device_id()
                credential_id = _new_credential_id()
                conn.execute(
                    "INSERT INTO devices(id,owner_type,slot_id,inst_id,hardware_id,label,status,"
                    "current_credential_id,created_at) VALUES(?, 'witness',?,?,?,?, 'active',?,?)",
                    (device_id, slot["id"], subj["inst_id"], hardware_id, label,
                     credential_id, ts))
                conn.execute(
                    "INSERT INTO device_credentials(id,device_id,generation,slot_id,inst_id,"
                    "public_jwk_json,public_key_hash,status,not_after,created_at)"
                    " VALUES(?,?,1,?,?,?,?, 'active',?,?)",
                    (credential_id, device_id, slot["id"], subj["inst_id"],
                     public_jwk_json, public_hash, not_after, ts))
        else:
            old = conn.execute(
                """SELECT c.*, d.owner_type,d.user_id,d.slot_id,d.inst_id AS device_inst_id,
                          d.hardware_id,d.label,d.status AS device_status
                   FROM device_enrollments e
                   JOIN device_credentials c ON c.id=e.credential_id
                   JOIN devices d ON d.id=c.device_id WHERE e.code_hash=? AND e.credential_id=?""",
                (enr["code_hash"], enr["credential_id"])).fetchone()
            if not old or old["device_status"] != "active":
                conn.execute("ROLLBACK")
                raise EngineError("device_revoked", "设备已停用，不能换新代次密钥", 403)
            if old["hardware_id"] != hardware_id:
                conn.execute("ROLLBACK")
                raise EngineError("hardware_mismatch", "轮换授权与原设备硬件标识不一致", 409)
            device_id = old["device_id"]
            credential_id = _new_credential_id()
            gen = old["generation"] + 1
            conn.execute(
                "UPDATE device_credentials SET status='rotated',rotated_at=? WHERE id=?",
                (ts, old["id"]))
            conn.execute(
                "INSERT INTO device_credentials(id,device_id,generation,user_id,inst_id,slot_id,"
                "public_jwk_json,public_key_hash,status,not_after,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,'active',?,?)",
                (credential_id, device_id, gen, old["user_id"], old["device_inst_id"],
                 old["slot_id"], public_jwk_json, public_hash, not_after, ts))
            conn.execute("UPDATE devices SET current_credential_id=? WHERE id=?",
                         (credential_id, device_id))

        conn.execute(
            "UPDATE device_enrollments SET status='used',used_at=?,resulting_device_id=?,"
            "resulting_credential_id=? WHERE code_hash=?",
            (ts, device_id, credential_id, enr["code_hash"]))
        _evt(conn, "device_registered" if enr["purpose"] == "register" else "device_rotated",
             inst_id=enr["inst_id"], session_id=None if not enr["slot_id"] else
             conn.execute("SELECT session_id FROM sign_slots WHERE id=?",
                          (enr["slot_id"],)).fetchone()["session_id"],
             detail={"device_id": device_id, "credential_id": credential_id,
                     "purpose": enr["purpose"], "owner_type": enr["owner_type"],
                     "generation": 1 if enr["purpose"] == "register" else gen,
                     "hardware_id_hash": _sha256_text(hardware_id)})
        conn.execute("COMMIT")
        return {"device_id": device_id, "credential_id": credential_id,
                "expires_at": not_after, "registered_at": ts}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def create_rotation_enrollment(conn, principal, credential_id):
    begin_tx(conn)
    try:
        row = conn.execute(
            """SELECT c.*,d.status AS device_status,d.user_id,d.inst_id,d.slot_id
               FROM device_credentials c JOIN devices d ON d.id=c.device_id
               WHERE c.id=?""", (credential_id,)).fetchone()
        if not row:
            conn.execute("ROLLBACK")
            raise EngineError("credential_not_found", "设备凭据不存在", 404)
        allowed = principal["role"] == "admin" or (
            principal["role"] == "site" and principal["inst_id"] == row["inst_id"]
            and (row["user_id"] is None or row["slot_id"] is not None))
        if not allowed:
            conn.execute("ROLLBACK")
            raise EngineError("forbidden", "不能为其他机构设备签发轮换授权", 403)
        if row["status"] != "active" or row["device_status"] != "active":
            conn.execute("ROLLBACK")
            raise EngineError("device_credential_inactive", "仅当前有效凭据可轮换", 409)
        code = _issue_code(conn, purpose="rotate", owner_type=None, credential=row)
        conn.execute("COMMIT")
        return {"rotation_code": code, "credential_id": credential_id,
                "expires_in": ENROLLMENT_TTL_SECONDS}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def revoke_device(conn, principal, device_id, reason):
    if principal["role"] not in ("admin", "site"):
        raise EngineError("forbidden", "无权停用设备", 403)
    begin_tx(conn)
    try:
        d = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not d or (principal["role"] == "site" and principal["inst_id"] != d["inst_id"]):
            conn.execute("ROLLBACK")
            raise EngineError("device_not_found", "设备不存在", 404)
        if d["status"] == "revoked":
            conn.execute("ROLLBACK")
            return {"idempotent": True, "device_id": device_id, "status": "revoked"}
        ts = now()
        conn.execute("UPDATE devices SET status='revoked',revoked_at=?,revoke_reason=? WHERE id=?",
                     (ts, reason, device_id))
        conn.execute(
            "UPDATE device_credentials SET status='revoked',revoked_at=? "
            "WHERE device_id=? AND status='active'", (ts, device_id))
        _evt(conn, "device_revoked", inst_id=d["inst_id"],
             detail={"device_id": device_id, "reason": reason})
        conn.execute("COMMIT")
        return {"idempotent": False, "device_id": device_id, "status": "revoked",
                "revoked_at": ts}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _device_owner_error(owner_type):
    return EngineError("device_not_authorized", "设备证明与本入口/主体不匹配", 403)


def _authorize_challenge(conn, action, resource, role, principal, witness_token):
    def need_principal(roles):
        if not principal or principal["role"] not in roles:
            raise EngineError("device_not_authorized", "登录身份不能使用该设备", 403)
        return principal

    if action == "session.start":
        need_principal(("site",))
        subj = get_subject(conn, resource)
        if principal["inst_id"] != subj["inst_id"]:
            raise EngineError("subject_not_found", "参与人对象不存在", 404)
        return {"owner_type": "user", "user_id": principal["id"], "inst_id": principal["inst_id"]}

    if action == "witness.tokens":
        need_principal(("site",))
        s = conn.execute("SELECT * FROM sessions WHERE id=?", (resource,)).fetchone()
        if not s:
            raise EngineError("session_not_found", "会话不存在", 404)
        subj = get_subject(conn, s["subject_id"])
        if principal["inst_id"] != subj["inst_id"]:
            raise EngineError("session_not_found", "会话不存在", 404)
        return {"owner_type": "user", "user_id": principal["id"], "inst_id": principal["inst_id"]}

    if action == "revoke":
        need_principal(("subject",))
        s = conn.execute("SELECT * FROM sessions WHERE id=?", (resource,)).fetchone()
        if not s:
            raise EngineError("session_not_found", "会话不存在", 404)
        linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                              (principal["id"],)).fetchone()
        if not linked or linked["id"] != s["subject_id"]:
            raise EngineError("session_not_found", "会话不存在", 404)
        return {"owner_type": "user", "user_id": principal["id"],
                "inst_id": principal["inst_id"]}

    if action == "execute":
        need_principal(("site",))
        subj = get_subject(conn, resource)
        if principal["inst_id"] != subj["inst_id"]:
            raise EngineError("subject_not_found", "参与人对象不存在", 404)
        return {"owner_type": "user", "user_id": principal["id"], "inst_id": principal["inst_id"]}

    if action == "sign":
        if role not in KNOWN_ROLES:
            raise EngineError("bad_role", "未知签署角色")
        s = conn.execute("SELECT * FROM sessions WHERE id=?", (resource,)).fetchone()
        if not s:
            raise EngineError("session_not_found", "会话不存在", 404)
        if role == "witness":
            slot = _witness_slot_for_token(conn, resource, "witness", witness_token)
            if not slot:
                raise EngineError("invalid_token", "见证链接无效或已使用", 403)
            return {"owner_type": "witness", "slot_id": slot["id"], "inst_id":
                    conn.execute("SELECT inst_id FROM subjects WHERE id=?",
                                 (s["subject_id"],)).fetchone()["inst_id"]}
        need_principal(("site", "subject"))
        subj = get_subject(conn, s["subject_id"])
        if role == "subject":
            linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                                  (principal["id"],)).fetchone()
            if principal["role"] != "subject" or not linked or linked["id"] != s["subject_id"]:
                raise EngineError("session_not_found", "会话不存在", 404)
        elif role != "site_owner" or principal["inst_id"] != subj["inst_id"]:
            raise EngineError("forbidden", "必须由本机构现场负责人签署", 403)
        return {"owner_type": "user", "user_id": principal["id"],
                "inst_id": principal["inst_id"]}

    raise EngineError("action_unknown", "未知设备动作", 400)


def create_challenge(conn, body, principal=None):
    action = str(body.get("action") or "")
    resource = str(body.get("resource") or "")
    role = body.get("role")
    witness_token = body.get("witness_token")
    credential_id = str(body.get("credential_id") or "")
    body_hash = str(body.get("body_hash") or "")
    if action not in DEVICE_ACTIONS:
        raise EngineError("action_unknown", "未知设备动作", 400)
    if not resource or len(body_hash) != 64:
        raise EngineError("bad_challenge_request", "资源与 64 位正文摘要不能为空", 400)
    scope = _authorize_challenge(conn, action, resource, role, principal, witness_token)
    begin_tx(conn)
    try:
        cred = conn.execute("SELECT * FROM device_credentials WHERE id=?",
                            (credential_id,)).fetchone()
        device = conn.execute("SELECT * FROM devices WHERE id=?",
                              (cred["device_id"],)).fetchone() if cred else None
        if not cred or not device:
            raise EngineError("credential_not_found", "设备凭据未登记", 404)
        if device["status"] != "active" or cred["status"] != "active":
            if cred["status"] == "rotated":
                raise EngineError("credential_generation_stale", "旧代密钥不能发起新请求", 403)
            raise EngineError("device_disabled", "设备已停用", 403)
        if _parse_ts(cred["not_after"]) <= datetime.now(timezone.utc):
            raise EngineError("credential_expired", "设备授权已失效", 403)
        owner_ok = (
            device["owner_type"] == scope["owner_type"]
            and device["inst_id"] == scope["inst_id"]
            and (scope["owner_type"] == "witness"
                 and device["slot_id"] == scope["slot_id"]
                 or scope["owner_type"] == "user"
                 and device["user_id"] == scope["user_id"])
        )
        if not owner_ok:
            raise _device_owner_error(scope["owner_type"])

        challenge_id = _new_challenge_id()
        nonce = secrets.token_hex(32)
        ts = now()
        expires = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() + CHALLENGE_TTL_SECONDS, timezone.utc
        ).isoformat()
        witness_hash = _sha256_text(witness_token) if witness_token else None
        conn.execute(
            "INSERT INTO device_challenges(id,nonce,credential_id,device_id,action,resource,"
            "role,body_digest,witness_token_hash,status,expires_at,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?, 'issued',?,?)",
            (challenge_id, nonce, cred["id"], device["id"], action, resource, role,
             body_hash, witness_hash, expires, ts))
        _evt(conn, "device_challenge_issued", inst_id=device["inst_id"],
             session_id=resource if action in ("sign", "witness.tokens", "revoke") else None,
             material_id=None, detail={"action": action, "resource": resource, "role": role,
                                       "device_id": device["id"],
                                       "credential_id": cred["id"], "generation": cred["generation"]})
        conn.execute("COMMIT")
        return {"challenge_id": challenge_id, "nonce": nonce, "action": action,
                "resource": resource, "role": role, "body_hash": body_hash,
                "expires_at": expires, "ttl_seconds": CHALLENGE_TTL_SECONDS}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def begin_attested_state(conn, *, action, resource, body, idem_key, attestation):
    """校验设备证明并打开业务写事务。

    返回值携带 active 事务和证明上下文；业务函数成功后必须调用 commit_state。
    挑战消费、幂等回执、业务落盘和 device_attestations 同事务提交。
    """
    if not isinstance(attestation, dict):
        raise EngineError("device_attestation_required", "状态变更必须携带设备可信证明", 401)
    if not idem_key:
        raise EngineError("idempotency_key_required", "状态变更必须携带幂等键", 400)
    scope_action = action
    role = attestation.get("role")
    if action == "sign":
        scope_action = f"sign:{resource}:{role}"
    elif action == "session.start":
        scope_action = f"session.start:{resource}"
    elif action == "witness.tokens":
        scope_action = f"witness.tokens:{resource}"
    elif action == "revoke":
        scope_action = f"revoke:{resource}"
    elif action == "execute":
        scope_action = f"execute:{resource}:{body.get('op')}:{body.get('purpose') or ''}"
    scope = scope_action
    body_hash = trust.canonical_hash(_business_body(body))
    business_hash = trust.canonical_hash({
        "action": action, "resource": resource, "role": role,
        "body_hash": body_hash,
    })

    begin_tx(conn)
    try:
        ctx = _verify_attestation_in_tx(conn, attestation, body, action, resource)
        request_hash = ctx["request_hash"]
        existing = conn.execute(
            "SELECT response_code,response_body,request_hash,credential_id FROM idempotents "
            "WHERE key=? AND scope=?", (idem_key, scope)).fetchone()
        if existing:
            if existing["request_hash"] != business_hash:
                raise EngineError("idempotency_payload_mismatch",
                                  "同一幂等键的请求载荷不同，拒绝改换内容", 409)
            if existing["credential_id"] != ctx["credential_id"]:
                raise EngineError("idempotency_device_mismatch",
                                  "同一幂等键已由其他设备使用，拒绝跨终端重放", 409)
            reply = json.loads(existing["response_body"])
            reply["replayed"] = True
            # 本次重试的一次性挑战随回执原子消费；不再执行任何业务状态机。
            conn.execute("UPDATE device_challenges SET status='consumed',consumed_at=? WHERE id=?",
                         (now(), ctx["challenge"]["id"]))
            conn.execute("COMMIT")
            return {"replayed": True, "code": existing["response_code"], "reply": reply}
        ctx.update({"scope": scope, "idem_key": idem_key, "request_hash": request_hash,
                    "business_hash": business_hash})
        return {"replayed": False, "ctx": ctx}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _verify_attestation_in_tx(conn, attestation, body, action, resource):
    required = ("challenge_id", "nonce", "credential_id", "request_hash", "terminal_signature")
    if any(not attestation.get(k) for k in required):
        raise EngineError("device_attestation_invalid", "设备证明字段不完整", 400)
    ch = conn.execute("SELECT * FROM device_challenges WHERE id=?",
                      (attestation["challenge_id"],)).fetchone()
    if not ch:
        raise EngineError("challenge_not_found", "挑战不存在", 404)
    if ch["status"] == "consumed":
        # 首次结果必须通过幂等入口取回；同一挑战不能制造第二次状态变更。
        raise EngineError("challenge_consumed", "挑战已消费，请用同载荷幂等重试", 409)
    if _parse_ts(ch["expires_at"]) <= datetime.now(timezone.utc):
        raise EngineError("challenge_expired", "挑战已过期，请重新领取", 410)
    for key, value in (("nonce", attestation["nonce"]), ("credential_id", attestation["credential_id"]),
                       ("action", action), ("resource", resource)):
        if ch[key] != value:
            raise EngineError("attestation_binding_mismatch",
                              f"设备证明与请求绑定不一致（{key}）", 409)
    if ch["role"] != attestation.get("role"):
        raise EngineError("attestation_binding_mismatch", "角色已被调换", 409)
    body_hash = trust.canonical_hash(_business_body(body))
    if ch["body_digest"] != body_hash:
        raise EngineError("body_digest_mismatch", "请求正文与挑战绑定摘要不同", 409)

    cred = conn.execute("SELECT * FROM device_credentials WHERE id=?",
                        (ch["credential_id"],)).fetchone()
    device = conn.execute("SELECT * FROM devices WHERE id=?",
                          (ch["device_id"],)).fetchone()
    if not cred or not device:
        raise EngineError("credential_not_found", "设备凭据未登记", 404)
    if cred["status"] == "rotated":
        raise EngineError("credential_generation_stale", "旧代密钥不能改变办理状态", 403)
    if device["status"] != "active" or cred["status"] == "revoked":
        raise EngineError("device_disabled", "设备已停用，请求稳定失败", 403)
    if _parse_ts(cred["not_after"]) <= datetime.now(timezone.utc):
        raise EngineError("credential_expired", "设备授权已失效", 403)

    request_hash = trust.request_digest(
        action=ch["action"], resource=ch["resource"], role=ch["role"],
        body_hash=ch["body_digest"], challenge_id=ch["id"], nonce=ch["nonce"])
    if attestation["request_hash"] != request_hash:
        raise EngineError("request_hash_mismatch", "设备证明内容指纹不匹配", 409)
    signed = {"alg": "CONSENT-ATTESTATION/v1", "request_hash": request_hash}
    if not trust.verify_object(json.loads(cred["public_jwk_json"]), signed,
                               attestation["terminal_signature"]):
        raise EngineError("attestation_signature_invalid", "终端私钥签名核验失败", 401)
    return {"challenge": ch, "credential": cred, "device": device,
            "credential_id": cred["id"], "device_id": device["id"],
            "generation": cred["generation"], "action": ch["action"],
            "resource": ch["resource"], "role": ch["role"], "request_hash": request_hash,
            "attestation": attestation}


def insert_attestation(conn, ctx):
    """在业务行写入前分配设备证明编号，便于外键/审计列与业务行同事务绑定。"""
    if "attestation_id" in ctx:
        return ctx["attestation_id"]
    ts = now()
    cur = conn.execute(
        "INSERT INTO device_attestations(challenge_id,credential_id,device_id,generation,"
        "action,resource,role,request_hash,terminal_signature,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        (ctx["challenge"]["id"], ctx["credential_id"], ctx["device_id"], ctx["generation"],
         ctx["action"], ctx["resource"], ctx["role"], ctx["request_hash"],
         ctx["attestation"]["terminal_signature"], ts))
    ctx["attestation_id"] = cur.lastrowid
    return ctx["attestation_id"]


def commit_state(conn, *, ctx, code, reply):
    insert_attestation(conn, ctx)
    ts = now()
    conn.execute("UPDATE device_challenges SET status='consumed',consumed_at=? WHERE id=?",
                 (ts, ctx["challenge"]["id"]))
    _idem_put(conn, ctx["idem_key"], ctx["scope"], code, reply,
              credential_id=ctx["credential_id"], device_id=ctx["device_id"],
              request_hash=ctx["business_hash"])
    conn.execute("COMMIT")
    return ctx["attestation_id"]


def publish_material(conn, *, family, inst_id, language, body, conditions, roles,
                     scope, requires_reconsent=False, reconsent_ops=None, principal=None):
    if principal and principal["role"] != "admin":
        raise EngineError("forbidden", "只有规则维护员可以发布材料", 403)
    if not family or not body:
        raise EngineError("bad_material", "family 与正文不能为空")
    inst = conn.execute("SELECT id FROM institutions WHERE id=?", (inst_id,)).fetchone()
    if not inst:
        raise EngineError("inst_not_found", "机构不存在", 404)
    roles = list(roles or [])
    if not roles or "subject" not in roles or "site_owner" not in roles:
        raise EngineError("bad_roles", "必签角色至少包含参与人与现场负责人")
    if any(r not in KNOWN_ROLES for r in roles):
        raise EngineError("bad_roles", f"未知角色，允许 {KNOWN_ROLES}")
    scope = list(scope or [])
    if not scope:
        raise EngineError("bad_scope", "至少允许一项操作")
    if any(op not in KNOWN_OPS for op in scope):
        raise EngineError("bad_scope", f"未知操作，允许 {KNOWN_OPS}")
    conditions = dict(conditions or {})
    reconsent_ops = list(reconsent_ops or [])
    if requires_reconsent and not reconsent_ops:
        raise EngineError("bad_reconsent", "要求再次同意时必须给出受影响操作")
    if any(op not in scope for op in reconsent_ops):
        raise EngineError("bad_reconsent", "再次同意的操作必须在本版许可范围内")

    tk = track_key(family, inst_id, language, conditions)
    bh = seal_body(body, inst_id, language, conditions, roles, scope)

    begin_tx(conn)
    latest = conn.execute(
        "SELECT * FROM materials WHERE track_key=? ORDER BY version DESC LIMIT 1", (tk,)).fetchone()
    if latest and latest["body_hash"] == bh and latest["scope_json"] == json.dumps(
            scope, ensure_ascii=False) and bool(latest["requires_reconsent"]) == bool(requires_reconsent) \
            and latest["reconsent_ops_json"] == json.dumps(reconsent_ops, ensure_ascii=False):
        conn.execute("ROLLBACK")
        raise EngineError("unchanged_version", "正文与覆盖范围均无变化，无需另立版本", 409)

    version = (latest["version"] + 1) if latest else 1
    cur = conn.execute(
        "INSERT INTO materials(family,version,inst_id,language,body,conditions_json,roles_json,"
        "scope_json,requires_reconsent,reconsent_ops_json,status,track_key,body_hash,published_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?, 'active', ?,?,?)",
        (family, version, inst_id, language, body,
         json.dumps(conditions, ensure_ascii=False), json.dumps(sorted(roles), ensure_ascii=False),
         json.dumps(scope, ensure_ascii=False), 1 if requires_reconsent else 0,
         json.dumps(reconsent_ops, ensure_ascii=False), tk, bh, now()),
    )
    mid = cur.lastrowid
    _evt(conn, "material_published", inst_id=inst_id, material_id=mid, detail={
        "family": family, "version": version, "language": language,
        "conditions": conditions, "roles": sorted(roles), "scope": scope,
        "requires_reconsent": bool(requires_reconsent), "reconsent_ops": reconsent_ops,
        "body_hash": bh, "track_key": tk,
    })
    conn.execute("COMMIT")
    return get_material(conn, mid)


def retire_material(conn, material_id, principal=None):
    if principal and principal["role"] != "admin":
        raise EngineError("forbidden", "只有规则维护员可以停用材料", 403)
    begin_tx(conn)
    m = conn.execute("SELECT * FROM materials WHERE id=?", (material_id,)).fetchone()
    if not m:
        conn.execute("ROLLBACK")
        raise EngineError("material_not_found", "材料不存在", 404)
    if m["status"] == "retired":
        conn.execute("ROLLBACK")
        raise EngineError("already_retired", "材料已停用", 409)
    ts = now()
    conn.execute("UPDATE materials SET status='retired',retired_at=? WHERE id=?", (ts, material_id))
    # 办理途中停用：未结束会话立刻冻结，不能悄悄降级/挪到别的版本
    rows = conn.execute(
        "SELECT id,subject_id FROM sessions WHERE material_id=? AND status='open'",
        (material_id,)).fetchall()
    for r in rows:
        conn.execute("UPDATE sessions SET status='blocked',blocked_at=? WHERE id=?", (ts, r["id"]))
        _evt(conn, "session_blocked", inst_id=m["inst_id"], subject_id=r["subject_id"],
             session_id=r["id"], material_id=material_id,
             detail={"reason": "material_retired", "version": m["version"]})
    _evt(conn, "material_retired", inst_id=m["inst_id"], material_id=material_id,
         detail={"family": m["family"], "version": m["version"], "blocked_sessions": len(rows)})
    conn.execute("COMMIT")
    return get_material(conn, material_id)


def get_material(conn, mid):
    r = conn.execute("SELECT * FROM materials WHERE id=?", (mid,)).fetchone()
    if not r:
        raise EngineError("material_not_found", "材料不存在", 404)
    return _material_dict(r)


def _material_dict(r):
    return {
        "id": r["id"], "family": r["family"], "version": r["version"],
        "inst_id": r["inst_id"], "language": r["language"], "body": r["body"],
        "conditions": _j(r, "conditions_json", {}), "roles": _j(r, "roles_json", []),
        "scope": _j(r, "scope_json", []),
        "requires_reconsent": bool(r["requires_reconsent"]),
        "reconsent_ops": _j(r, "reconsent_ops_json", []),
        "status": r["status"], "track_key": r["track_key"], "body_hash": r["body_hash"],
        "published_at": r["published_at"], "retired_at": r["retired_at"],
    }


def list_materials(conn, *, inst_id=None, family=None, include_retired=False):
    sql = "SELECT * FROM materials WHERE 1=1"
    args = []
    if not include_retired:
        sql += " AND status='active'"
    if inst_id:
        sql += " AND inst_id=?"; args.append(inst_id)
    if family:
        sql += " AND family=?"; args.append(family)
    sql += " ORDER BY family, inst_id, language, version"
    return [_material_dict(r) for r in conn.execute(sql, args)]


def _conditions_match(mat_cond, subj_cond):
    return all(subj_cond.get(k) == v for k, v in mat_cond.items())


def eligibility_for_subject(conn, subject):
    """现场开单时只能选 机构+语种+人群条件 全部吻合 的现行版材料。"""
    out = []
    mats = [m for m in list_materials(conn, inst_id=subject["inst_id"])
            if m["language"] == subject["language"]]
    # 每个 track 只呈现最新版（不允许拿旧版/未批准译文拼接）
    latest = {}
    for m in mats:
        latest[m["track_key"]] = m
    for m in latest.values():
        reasons = []
        if m["language"] != subject.get("language"):
            reasons.append("language_mismatch")
        if not _conditions_match(m["conditions"], subject["conditions"]):
            reasons.append("condition_mismatch")
        out.append({**m, "eligible": not reasons, "reject_reasons": reasons})
    return sorted(out, key=lambda m: (m["family"], m["track_key"]))


# ---------------- 签署会话 ----------------

def _new_token():
    return secrets.token_urlsafe(18)


def start_session(conn, subject_id, material_id, principal=None, attested_ctx=None):
    subj = get_subject(conn, subject_id)
    if principal:
        if principal["role"] == "admin":
            raise EngineError("forbidden", "规则维护员不能替人办理落款", 403)
        if principal["role"] == "site" and principal["inst_id"] != subj["inst_id"]:
            raise EngineError("cross_institution", "资源不属于本机构", 404)
    m = get_material(conn, material_id)
    if m["inst_id"] != subj["inst_id"]:
        raise EngineError("cross_institution", "资源不属于本机构", 404)
    if m["status"] != "active":
        raise EngineError("material_retired", "材料已停用，不能开新会话", 409)
    if m["language"] != subj.get("language"):
        raise EngineError("language_mismatch", "首选语种与材料语种不一致", 409)
    if not _conditions_match(m["conditions"], subj["conditions"]):
        raise EngineError("condition_mismatch", "人群条件不吻合", 409)

    if attested_ctx is None:
        begin_tx(conn)
    dup = conn.execute(
        "SELECT * FROM sessions WHERE subject_id=? AND track_key=? AND status='open'",
        (subject_id, m["track_key"])).fetchone()
    if dup:
        if attested_ctx is None:
            conn.execute("ROLLBACK")
        return get_session(conn, dup["id"], principal)
    attestation_id = insert_attestation(conn, attested_ctx) if attested_ctx else None
    sid = "S-" + secrets.token_hex(6)
    conn.execute(
        "INSERT INTO sessions(id,subject_id,material_id,track_key,status,device_id,"
        "credential_id,attestation_id,created_at) VALUES(?,?,?,?,'open',?,?,?,?)",
        (sid, subject_id, m["id"], m["track_key"],
         attested_ctx["device_id"] if attested_ctx else None,
         attested_ctx["credential_id"] if attested_ctx else None,
         attestation_id, now()))
    tokens = {}
    enrollments = {}
    for role in m["roles"]:
        tok = _new_token()
        conn.execute(
            "INSERT INTO sign_slots(session_id,role,token_hash) VALUES(?,?,?)",
            (sid, role, hashlib.sha256(tok.encode()).hexdigest()))
        tokens[role] = tok
        if role == "witness":
            slot = conn.execute(
                "SELECT * FROM sign_slots WHERE session_id=? AND role=?",
                (sid, role)).fetchone()
            enrollments[role] = _issue_code(
                conn, purpose="register", owner_type="witness", slot=slot)
    _evt(conn, "session_started", inst_id=subj["inst_id"], subject_id=subject_id,
         session_id=sid, material_id=m["id"],
         detail={"family": m["family"], "version": m["version"], "track_key": m["track_key"],
                 "body_hash": m["body_hash"]})
    s = get_session(conn, sid, principal)
    s["slot_tokens"] = tokens  # 仅本次开单返回；现场可另行索取未用令牌
    s["enrollment_codes"] = enrollments
    if attested_ctx is not None:
        commit_state(conn, ctx=attested_ctx, code=201, reply=s)
    else:
        conn.execute("COMMIT")
    return s


def list_device_audit(conn, principal, *, inst_id=None, device_id=None, limit=200):
    """设备凭据与业务状态变更的审计视图；维护员可全局查看，现场限本机构。"""
    if principal["role"] not in ("admin", "site"):
        raise EngineError("forbidden", "无权查看设备审计", 403)
    where = "1=1"
    args = []
    if principal["role"] == "site":
        where += " AND d.inst_id=?"; args.append(principal["inst_id"])
    elif inst_id:
        where += " AND d.inst_id=?"; args.append(inst_id)
    if device_id:
        where += " AND d.id=?"; args.append(device_id)
    args.append(min(int(limit or 200), 1000))
    devices = [dict(r) for r in conn.execute(f"""
        SELECT d.id,d.owner_type,d.user_id,d.inst_id,d.slot_id,d.hardware_id,d.label,
               d.status,d.current_credential_id,d.created_at,d.revoked_at,d.revoke_reason
        FROM devices d WHERE {where} ORDER BY d.created_at DESC LIMIT ?""", args)]
    ids = [d["id"] for d in devices]
    creds = []
    atts = []
    if ids:
        ph = ",".join("?" for _ in ids)
        creds = [dict(r) for r in conn.execute(f"""
            SELECT id,device_id,generation,user_id,inst_id,slot_id,public_jwk_json,
                   public_key_hash,status,not_after,created_at,rotated_at,revoked_at
            FROM device_credentials WHERE device_id IN ({ph})
            ORDER BY device_id, generation""", ids)]
        atts = [dict(r) for r in conn.execute(f"""
            SELECT id,challenge_id,credential_id,device_id,generation,action,resource,role,
                   request_hash,created_at
            FROM device_attestations WHERE device_id IN ({ph})
            ORDER BY id DESC LIMIT ?""", ids + [min(int(limit or 200), 1000)])]
        for c in creds:
            c["public_jwk"] = json.loads(c.pop("public_jwk_json"))
    return {"devices": devices, "credentials": creds, "attestations": atts}


def _session_views(conn, rows):
    out = []
    for r in rows:
        m = conn.execute("SELECT * FROM materials WHERE id=?", (r["material_id"],)).fetchone()
        sigs = conn.execute("SELECT role,signer_name,created_at,body_hash FROM signatures WHERE session_id=?",
                            (r["id"],)).fetchall()
        slots = []
        for sl in conn.execute("SELECT * FROM sign_slots WHERE session_id=? ORDER BY id", (r["id"],)):
            sg = next((s for s in sigs if s["role"] == sl["role"]), None)
            slots.append({"role": sl["role"], "role_label": ROLE_LABELS[sl["role"]],
                          "filled": sg is not None,
                          "signer_name": sg["signer_name"] if sg else None,
                          "signed_at": sg["created_at"] if sg else None})
        out.append({
            "id": r["id"], "status": r["status"], "subject_id": r["subject_id"],
            "material_id": r["material_id"], "track_key": r["track_key"],
            "created_at": r["created_at"], "completed_at": r["completed_at"],
            "withdrawn_at": r["withdrawn_at"], "blocked_at": r["blocked_at"],
            "material": _material_dict(m),
            "slots": slots,
            "remaining_roles": [s["role"] for s in slots if not s["filled"]],
        })
    return out


def get_session(conn, session_id, principal=None):
    r = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not r:
        raise EngineError("session_not_found", "会话不存在", 404)
    view = _session_views(conn, [r])[0]
    subj = get_subject(conn, view["subject_id"])
    if principal:
        if principal["role"] == "site" and principal["inst_id"] != subj["inst_id"]:
            # 跨机构：对其他机构统一报“不存在”，报错不暴露他人身份
            raise EngineError("session_not_found", "会话不存在", 404)
        if principal["role"] == "subject":
            linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                                  (principal["id"],)).fetchone()
            if not linked or linked["id"] != view["subject_id"]:
                raise EngineError("session_not_found", "会话不存在", 404)
    return view


def list_sessions(conn, *, subject_id=None, inst_id=None):
    sql = "SELECT * FROM sessions WHERE 1=1"
    args = []
    if subject_id:
        sql += " AND subject_id=?"; args.append(subject_id)
    if inst_id:
        sql += " AND subject_id IN (SELECT id FROM subjects WHERE inst_id=?)"
        args.append(inst_id)
    sql += " ORDER BY created_at DESC"
    return _session_views(conn, conn.execute(sql, args).fetchall())


def slot_tokens(conn, session_id, principal, attested_ctx=None):
    """现场负责人获取未签角色的一次性签名链接及见证终端一次性登记授权。"""
    s = get_session(conn, session_id, principal)
    if principal["role"] != "site":
        raise EngineError("forbidden", "仅现场人员可以索取签名令牌", 403)
    if attested_ctx is None:
        begin_tx(conn)
    out = {}
    enrollment = {}
    for sl in conn.execute("SELECT * FROM sign_slots WHERE session_id=? ORDER BY id",
                           (session_id,)).fetchall():
        if sl["role"] == "subject":
            continue
        sig = conn.execute("SELECT 1 FROM signatures WHERE slot_id=?", (sl["id"],)).fetchone()
        if sig:
            continue
        tok = _new_token()
        conn.execute("UPDATE sign_slots SET token_hash=? WHERE id=?",
                     (hashlib.sha256(tok.encode()).hexdigest(), sl["id"]))
        out[sl["role"]] = tok
        if sl["role"] == "witness":
            enrollment[sl["role"]] = _issue_code(
                conn, purpose="register", owner_type="witness", slot=sl)
        _evt(conn, "witness_link_rotated", inst_id=principal["inst_id"],
             session_id=session_id, detail={"role": sl["role"], "slot_id": sl["id"]})
    reply = {"session_id": session_id, "tokens": out, "enrollment_codes": enrollment}
    if attested_ctx is not None:
        commit_state(conn, ctx=attested_ctx, code=200, reply=reply)
    else:
        conn.execute("COMMIT")
    return reply


def sign(conn, session_id, role, *, signer_name=None, token=None, principal=None,
         idem_key=None, attested_ctx=None):
    tx_active = attested_ctx is not None
    def rollback():
        if tx_active:
            conn.execute("ROLLBACK")
        else:
            conn.execute("ROLLBACK")

    if attested_ctx is None and idem_key:
        scope = f"sign:{session_id}:{role}"
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body

    if attested_ctx is None:
        begin_tx(conn)
    r = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not r:
        conn.execute("ROLLBACK")
        raise EngineError("session_not_found", "会话不存在", 404)
    subj = get_subject(conn, r["subject_id"])
    m = conn.execute("SELECT * FROM materials WHERE id=?", (r["material_id"],)).fetchone()

    # 权限与身份核对
    if role not in KNOWN_ROLES:
        conn.execute("ROLLBACK")
        raise EngineError("bad_role", "未知签署角色")
    slot = conn.execute("SELECT * FROM sign_slots WHERE session_id=? AND role=?",
                        (session_id, role)).fetchone()
    if not slot:
        conn.execute("ROLLBACK")
        raise EngineError("role_not_required", "这份封存材料不要求该角色签署", 409)

    signer_principal = None
    if role == "witness":
        if not token or not signer_name:
            conn.execute("ROLLBACK")
            raise EngineError("witness_token_required", "见证者需凭一次性签名链接并署名", 403)
        if slot["token_used"] or hashlib.sha256(token.encode()).hexdigest() != slot["token_hash"]:
            conn.execute("ROLLBACK")
            raise EngineError("invalid_token", "签名链接无效或已使用", 403)
        signer_principal = "witness:token"
    else:
        if not principal:
            conn.execute("ROLLBACK")
            raise EngineError("login_required", "该角色必须登录后签署", 401)
        if principal["role"] == "admin":
            conn.execute("ROLLBACK")
            raise EngineError("forbidden", "规则维护员不得替人落款", 403)
        if role == "subject":
            if principal["role"] != "subject":
                conn.execute("ROLLBACK")
                raise EngineError("forbidden", "只有参与人本人能签参与人栏", 403)
            linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                                  (principal["id"],)).fetchone()
            if not linked or linked["id"] != r["subject_id"]:
                conn.execute("ROLLBACK")
                raise EngineError("session_not_found", "会话不存在", 404)
            signer_principal = principal["id"]
            signer_name = principal["name"]
        elif role == "site_owner":
            if principal["role"] != "site" or principal["inst_id"] != subj["inst_id"]:
                conn.execute("ROLLBACK")
                raise EngineError("forbidden", "必须由本机构现场负责人签署", 403)
            signer_principal = principal["id"]
            signer_name = principal["name"]

    # 会话状态（与撤销、停用竞争时以本事务内读到的持久化状态为准）
    if r["status"] == "blocked" or m["status"] == "retired":
        if r["status"] == "open":
            ts = now()
            attestation_id = insert_attestation(conn, attested_ctx) if attested_ctx else None
            conn.execute(
                "UPDATE sessions SET status='blocked',blocked_at=?,device_id=?,"
                "credential_id=?,attestation_id=? WHERE id=?",
                (ts, attested_ctx["device_id"] if attested_ctx else r["device_id"],
                 attested_ctx["credential_id"] if attested_ctx else r["credential_id"],
                 attestation_id, session_id))
            _evt(conn, "session_blocked", inst_id=subj["inst_id"], subject_id=subj["id"],
                 session_id=session_id, material_id=m["id"],
                 detail={"reason": "material_retired", "version": m["version"],
                         "device_id": attested_ctx["device_id"] if attested_ctx else None})
            body = {"result": "blocked", "session_id": session_id, "blocked_at": ts}
            if attested_ctx:
                body["session"] = get_session(conn, session_id, principal)
                commit_state(conn, ctx=attested_ctx, code=409, reply=body)
            else:
                conn.execute("COMMIT")
        else:
            conn.execute("ROLLBACK")
        raise EngineError("material_retired", "材料在签署途中被停用，本会话已冻结", 409)
    if r["status"] == "withdrawn":
        conn.execute("ROLLBACK")
        raise EngineError("session_withdrawn", "参与人已撤销，不能再落款", 409)
    if r["status"] == "completed":
        conn.execute("ROLLBACK")
        raise EngineError("already_completed", "所有必需角色已完成签署", 409)

    # 重复落款：槽位已被占用时，同一落款人=重复提交取首次结果；不同落款人=目标冲突，
    # 槽位归属以先提交者为准，系统给出唯一可说明状态
    sig_hash = hashlib.sha256(
        f"{session_id}|{role}|{signer_principal}|{m['body_hash']}".encode()).hexdigest()
    existing = conn.execute("SELECT * FROM signatures WHERE slot_id=?", (slot["id"],)).fetchone()
    if existing:
        conn.execute("ROLLBACK")
        if existing["signer_principal"] != signer_principal:
            raise EngineError(
                "slot_filled_by_other",
                f"{ROLE_LABELS[role]}签署位已由 {existing['signer_name']} 完成，不能重复落款",
                409)
        view = get_session(conn, session_id, principal)
        body = {"result": "already_signed", "session": view,
                "first_signed_at": existing["created_at"]}
        conn.execute("ROLLBACK")
        return 200, body

    ts = now()
    attestation_id = insert_attestation(conn, attested_ctx) if attested_ctx else None
    cur = conn.execute(
        "INSERT INTO signatures(session_id,slot_id,role,signer_principal,signer_name,"
        "body_hash,sig_hash,device_id,credential_id,attestation_id,request_hash,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (session_id, slot["id"], role, signer_principal, signer_name,
         m["body_hash"], sig_hash,
         attested_ctx["device_id"] if attested_ctx else None,
         attested_ctx["credential_id"] if attested_ctx else None,
         attestation_id,
         attested_ctx["request_hash"] if attested_ctx else None,
         ts))
    if role == "witness":
        conn.execute("UPDATE sign_slots SET token_used=1,signer_name=? WHERE id=?",
                     (signer_name, slot["id"]))
    else:
        conn.execute("UPDATE sign_slots SET signer_name=? WHERE id=?", (signer_name, slot["id"]))
    _evt(conn, "signed", inst_id=subj["inst_id"], subject_id=subj["id"],
         session_id=session_id, material_id=m["id"],
         detail={"role": role, "signer_name": signer_name, "body_hash": m["body_hash"],
                 "version": m["version"], "attestation_id": attestation_id,
                 "device_id": attested_ctx["device_id"] if attested_ctx else None})

    body = {"result": "signed", "role": role, "signed_at": ts}
    # 全部必签角色针对同一份封存内容完成 -> 生成唯一有效许可
    unfilled = conn.execute(
        "SELECT sl.role FROM sign_slots sl LEFT JOIN signatures sg ON sg.slot_id=sl.id"
        " WHERE sl.session_id=? AND sg.id IS NULL", (session_id,)).fetchall()
    if not unfilled:
        conn.execute(
            "UPDATE sessions SET status='completed',completed_at=?,device_id=?,"
            "credential_id=?,attestation_id=? WHERE id=?",
            (ts, attested_ctx["device_id"] if attested_ctx else r["device_id"],
             attested_ctx["credential_id"] if attested_ctx else r["credential_id"],
             attestation_id, session_id))
        seq = conn.execute("SELECT COALESCE(MAX(seq),0)+1 AS n FROM events").fetchone()["n"]
        permit_id = "P-" + secrets.token_hex(6)
        conn.execute(
            "INSERT INTO permits(id,session_id,subject_id,material_id,family,track_key,version,"
            "body_hash,scope_json,status,issued_at,issued_seq) VALUES(?,?,?,?,?,?,?,?,?, 'active',?,?)",
            (permit_id, session_id, subj["id"], m["id"], m["family"], m["track_key"],
             m["version"], m["body_hash"], m["scope_json"], ts, seq))
        _evt(conn, "permit_issued", inst_id=subj["inst_id"], subject_id=subj["id"],
             session_id=session_id, permit_id=permit_id, material_id=m["id"],
             detail={"family": m["family"], "version": m["version"], "scope": _j(m, "scope_json"),
                     "body_hash": m["body_hash"], "attestation_id": attestation_id})
        body["result"] = "completed"
        body["permit_id"] = permit_id
    body["session"] = get_session(conn, session_id, principal)
    if attested_ctx:
        commit_state(conn, ctx=attested_ctx, code=200, reply=body)
    else:
        conn.execute("COMMIT")
    return 200, body


def revoke(conn, session_id, principal, idem_key=None, attested_ctx=None):
    """参与人撤销（对进行中会话表达撤销意愿，或撤销已发许可）。"""
    if attested_ctx is None and idem_key:
        scope = f"revoke:{session_id}"
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body
    if attested_ctx is None:
        begin_tx(conn)
    r = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not r:
        conn.execute("ROLLBACK")
        raise EngineError("session_not_found", "会话不存在", 404)
    if principal["role"] != "subject":
        conn.execute("ROLLBACK")
        raise EngineError("forbidden", "只有参与人本人可以撤销", 403)
    linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                          (principal["id"],)).fetchone()
    if not linked or linked["id"] != r["subject_id"]:
        conn.execute("ROLLBACK")
        raise EngineError("session_not_found", "会话不存在", 404)

    ts = now()
    inst_id = conn.execute("SELECT inst_id FROM subjects WHERE id=?",
                           (r["subject_id"],)).fetchone()["inst_id"]
    attestation_id = insert_attestation(conn, attested_ctx) if attested_ctx else None
    if r["status"] == "open":
        conn.execute(
            "UPDATE sessions SET status='withdrawn',withdrawn_at=?,device_id=?,"
            "credential_id=?,attestation_id=? WHERE id=?",
            (ts, attested_ctx["device_id"] if attested_ctx else r["device_id"],
             attested_ctx["credential_id"] if attested_ctx else r["credential_id"],
             attestation_id, session_id))
        _evt(conn, "session_withdrawn", inst_id=inst_id, subject_id=r["subject_id"],
             session_id=session_id, detail={"at": ts, "attestation_id": attestation_id})
        body = {"result": "withdrawn", "session_id": session_id, "at": ts}
    elif r["status"] == "completed":
        p = conn.execute("SELECT * FROM permits WHERE session_id=? AND status='active'",
                         (session_id,)).fetchone()
        if not p:
            conn.execute("ROLLBACK")
            return 200, {"result": "already_revoked", "session_id": session_id}
        conn.execute("UPDATE permits SET status='revoked',revoked_at=? WHERE id=?",
                     (ts, p["id"]))
        conn.execute(
            "UPDATE sessions SET device_id=?,credential_id=?,attestation_id=? WHERE id=?",
            (attested_ctx["device_id"] if attested_ctx else r["device_id"],
             attested_ctx["credential_id"] if attested_ctx else r["credential_id"],
             attestation_id, session_id))
        _evt(conn, "permit_revoked", inst_id=inst_id, subject_id=r["subject_id"],
             session_id=session_id, permit_id=p["id"],
             detail={"at": ts, "version": p["version"], "attestation_id": attestation_id})
        body = {"result": "revoked", "permit_id": p["id"], "at": ts}
    elif r["status"] == "withdrawn":
        conn.execute("ROLLBACK")
        return 200, {"result": "already_withdrawn", "session_id": session_id}
    else:
        conn.execute("ROLLBACK")
        raise EngineError("session_blocked", "会话已因材料停用冻结，无需撤销", 409)
    body["session"] = get_session(conn, session_id, principal)
    if attested_ctx:
        commit_state(conn, ctx=attested_ctx, code=200, reply=body)
    else:
        conn.execute("COMMIT")
    return 200, body


# ---------------- 许可评估 / 执行确认 ----------------

def _permits_for(conn, subject_id):
    rows = conn.execute(
        "SELECT * FROM permits WHERE subject_id=? ORDER BY issued_seq DESC", (subject_id,)).fetchall()
    out = []
    for p in rows:
        d = dict(p)
        d["scope"] = _j(p, "scope_json")
        out.append(d)
    return out


def _open_requirements(conn, subject_id, family=None, track=None):
    """进行中会话尚缺的角色。"""
    rows = conn.execute(
        "SELECT * FROM sessions WHERE subject_id=? AND status='open'", (subject_id,)).fetchall()
    res = []
    for r in rows:
        m = conn.execute("SELECT * FROM materials WHERE id=?", (r["material_id"],)).fetchone()
        if family and m["family"] != family:
            continue
        if track and m["track_key"] != track:
            continue
        missing = [x["role"] for x in get_session(conn, r["id"])["slots"] if not x["filled"]]
        res.append({"session_id": r["id"], "family": m["family"], "version": m["version"],
                    "remaining_roles": missing})
    return res


def evaluate(conn, subject_id, op, purpose=None):
    """实际操作前查询：依据材料版本、获准范围、尚缺条件。"""
    subj = get_subject(conn, subject_id)
    if op not in KNOWN_OPS:
        raise EngineError("bad_op", f"未知操作 {op}")
    permits = _permits_for(conn, subject_id)
    covering = [p for p in permits if op in p["scope"]]
    # 以“最新的一份覆盖该操作的许可”为唯一裁定者：它若被撤销，不得回落到更旧许可复活权限
    newest = covering[0] if covering else None

    result = {"subject_id": subject_id, "op": op, "purpose": purpose,
              "allowed": False, "basis": None, "scope": None, "missing": None}

    if newest is None:
        result["reason"] = "no_permit"
        result["missing"] = {
            "open_sessions": _open_requirements(conn, subject_id),
            "hint": "尚无覆盖该操作的有效许可，需要完成全部必签角色",
        }
        return result
    if newest["status"] == "revoked":
        result["reason"] = "revoked"
        result["basis"] = {"permit_id": newest["id"], "family": newest["family"],
                           "version": newest["version"], "body_hash": newest["body_hash"],
                           "track_key": newest["track_key"], "issued_at": newest["issued_at"]}
        result["scope"] = newest["scope"]
        result["missing"] = {"hint": "最新许可已被参与人撤销；撤销后的新操作一律拒绝"}
        return result

    base = newest  # 最新有效许可
    result["basis"] = {
        "permit_id": base["id"], "family": base["family"], "version": base["version"],
        "body_hash": base["body_hash"], "track_key": base["track_key"],
        "issued_at": base["issued_at"],
    }
    result["scope"] = base["scope"]

    # 再次同意：同 track 的现行新版若把该操作列为需重新同意，未发生的相关操作立即冻结
    latest_mat = conn.execute(
        "SELECT * FROM materials WHERE track_key=? AND status='active' ORDER BY version DESC LIMIT 1",
        (base["track_key"],)).fetchone()
    if latest_mat and latest_mat["requires_reconsent"] \
            and op in _j(latest_mat, "reconsent_ops_json", []) \
            and latest_mat["version"] > base["version"]:
        result["reason"] = "frozen_reconsent"
        result["allowed"] = False
        result["missing"] = {
            "requires_reconsent_version": latest_mat["version"],
            "family": latest_mat["family"],
            "open_sessions": _open_requirements(conn, subject_id, latest_mat["family"],
                                                latest_mat["track_key"]),
            "hint": "规则修订要求对该操作再次同意，新版补签齐备后解锁",
        }
        return result

    result["allowed"] = True
    result["reason"] = "ok"
    return result


def execute(conn, subject_id, op, *, purpose=None, principal=None, idem_key=None,
            attested_ctx=None):
    """操作实际发生前的执行确认（与撤销竞争时由写锁分出唯一先后）。"""
    if attested_ctx is None and idem_key:
        scope = f"execute:{subject_id}:{op}:{purpose or ''}"
        hit = _idem_get(conn, idem_key, scope)
        if hit:
            code, body, _ = hit
            body["replayed"] = True
            return code, body
    if attested_ctx is None:
        begin_tx(conn)
    subj = get_subject(conn, subject_id)
    if principal and principal["role"] == "site" and principal["inst_id"] != subj["inst_id"]:
        conn.execute("ROLLBACK")
        raise EngineError("cross_institution", "资源不属于本机构", 404)

    # 同一“新增用途”不允许重复登记；无用途的常规操作按次确认
    if purpose:
        prior = conn.execute(
            "SELECT * FROM executions WHERE subject_id=? AND op=? AND purpose=? AND result='performed'",
            (subject_id, op, purpose)).fetchone()
        if prior:
            conn.execute("ROLLBACK")
            return 200, {"result": "already_performed", "execution_id": prior["id"],
                         "performed_at": prior["created_at"],
                         "basis_version": prior["version"]}

    ev = evaluate(conn, subject_id, op, purpose)
    ts = now()
    attestation_id = insert_attestation(conn, attested_ctx) if attested_ctx else None
    device_id = attested_ctx["device_id"] if attested_ctx else None
    credential_id = attested_ctx["credential_id"] if attested_ctx else None
    request_hash = attested_ctx["request_hash"] if attested_ctx else None
    if ev["allowed"]:
        cur = conn.execute(
            "INSERT INTO executions(subject_id,op,purpose,permit_id,material_family,version,"
            "result,device_id,credential_id,attestation_id,request_hash,created_at)"
            " VALUES(?,?,?,?,?,?,'performed',?,?,?,?,?)",
            (subject_id, op, purpose, ev["basis"]["permit_id"], ev["basis"]["family"],
             ev["basis"]["version"], device_id, credential_id, attestation_id,
             request_hash, ts))
        _evt(conn, "op_performed", inst_id=subj["inst_id"], subject_id=subject_id,
             permit_id=ev["basis"]["permit_id"],
             detail={"op": op, "purpose": purpose, "family": ev["basis"]["family"],
                     "version": ev["basis"]["version"], "execution_id": cur.lastrowid,
                     "attestation_id": attestation_id})
        body = {"result": "performed", "execution_id": cur.lastrowid, "performed_at": ts,
                "basis": ev["basis"], "scope": ev["scope"]}
    else:
        cur = conn.execute(
            "INSERT INTO executions(subject_id,op,purpose,permit_id,material_family,version,"
            "result,reason,device_id,credential_id,attestation_id,request_hash,created_at)"
            " VALUES(?,?,?,?,?,?,'denied',?,?,?,?,?,?)",
            (subject_id, op, purpose,
             ev["basis"]["permit_id"] if ev["basis"] else None,
             ev["basis"]["family"] if ev["basis"] else None,
             ev["basis"]["version"] if ev["basis"] else None,
             ev["reason"], device_id, credential_id, attestation_id, request_hash, ts))
        _evt(conn, "op_denied", inst_id=subj["inst_id"], subject_id=subject_id,
             permit_id=ev["basis"]["permit_id"] if ev["basis"] else None,
             detail={"op": op, "purpose": purpose, "reason": ev["reason"],
                     "missing": ev["missing"], "execution_id": cur.lastrowid,
                     "attestation_id": attestation_id})
        body = {"result": "denied", "execution_id": cur.lastrowid, "reason": ev["reason"],
                "basis": ev["basis"], "scope": ev["scope"], "missing": ev["missing"]}
    if attested_ctx:
        commit_state(conn, ctx=attested_ctx, code=200, reply=body)
    else:
        conn.execute("COMMIT")
    return 200, body


def list_executions(conn, subject_id):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM executions WHERE subject_id=? ORDER BY id", (subject_id,))]


def list_permits(conn, subject_id):
    return _permits_for(conn, subject_id)


# ---------------- 审计 ----------------

def audit_events(conn, principal, *, inst_id=None, limit=100):
    """审计可见性：现场仅本机构；规则维护员可见全局但参与人身份打码；参与人仅本人。"""
    sql = "SELECT * FROM events WHERE 1=1"
    args = []
    if principal["role"] == "site":
        sql += " AND inst_id=?"; args.append(principal["inst_id"])
    elif principal["role"] == "subject":
        linked = conn.execute("SELECT id FROM subjects WHERE user_id=?",
                              (principal["id"],)).fetchone()
        sql += " AND subject_id=?"; args.append(linked["id"] if linked else "!")
    elif inst_id:
        sql += " AND inst_id=?"; args.append(inst_id)
    sql += " ORDER BY seq DESC LIMIT ?"; args.append(limit)
    rows = conn.execute(sql, args).fetchall()
    mask = principal["role"] == "admin"
    out = []
    for r in rows:
        d = dict(r)
        d["detail"] = json.loads(d.pop("detail_json"))
        if mask and d.get("subject_id"):
            d["subject_id"] = "SUBJ-MASKED"
            if "signer_name" in d["detail"]:
                d["detail"]["signer_name"] = "***"
        out.append(d)
    return out

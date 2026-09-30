"""HTTP API + 静态页面。标准库 http.server，每请求独立连接，写操作在引擎内串行化。"""
import json
import os
import re
import base64
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import db as dbmod
import engine
from engine import EngineError

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
MAX_BODY = 2 * 1024 * 1024

_PAT = {
    "material_retire": re.compile(r"^/api/materials/(\d+)/retire$"),
    "session": re.compile(r"^/api/sessions/(S-[0-9a-f]+)$"),
    "session_tokens": re.compile(r"^/api/sessions/(S-[0-9a-f]+)/tokens$"),
    "session_sign": re.compile(r"^/api/sessions/(S-[0-9a-f]+)/sign$"),
    "session_revoke": re.compile(r"^/api/sessions/(S-[0-9a-f]+)/revoke$"),
    "subject": re.compile(r"^/api/subjects/([A-Za-z0-9_\-]+)$"),
    "subject_elig": re.compile(r"^/api/subjects/([A-Za-z0-9_\-]+)/eligibility$"),
    "subject_sessions": re.compile(r"^/api/subjects/([A-Za-z0-9_\-]+)/sessions$"),
    "subject_permits": re.compile(r"^/api/subjects/([A-Za-z0-9_\-]+)/permits$"),
    "subject_exec": re.compile(r"^/api/subjects/([A-Za-z0-9_\-]+)/executions$"),
    "subject_check": re.compile(r"^/api/subjects/([A-Za-z0-9_\-]+)/check$"),
    "subject_execute": re.compile(r"^/api/subjects/([A-Za-z0-9_\-]+)/execute$"),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "ConsentEngine/1.0"

    def log_message(self, fmt, *args):
        pass  # 测试环境静默

    # ---------- 基础收发 ----------
    def _send(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > MAX_BODY:
            raise EngineError("body_too_large", "请求体过大", 413)
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            d = json.loads(raw.decode("utf-8"))
            return d if isinstance(d, dict) else {}
        except Exception:
            raise EngineError("bad_json", "请求体不是合法 JSON")

    def _qs(self):
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    def _token(self):
        h = self.headers.get("Authorization", "")
        return h[7:].strip() if h.startswith("Bearer ") else None

    def _principal(self, required=True):
        t = self._token()
        if not t:
            if required:
                raise EngineError("unauthenticated", "缺少登录令牌", 401)
            return None
        conn = dbmod.get_conn()
        try:
            return engine.principal_from_token(conn, t)
        finally:
            conn.close()

    def _serve_static(self, path):
        if path == "/":
            path = "/index.html"
        name = os.path.normpath(path).lstrip("/")
        if name.startswith("static/"):
            name = name[len("static/"):]
        full = os.path.join(STATIC_DIR, name)
        if not full.startswith(STATIC_DIR + os.sep) or not os.path.isfile(full):
            self.send_error(404, "Not found")
            return
        ctype = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8",
                 "css": "text/css; charset=utf-8", "svg": "image/svg+xml"}.get(
            name.rsplit(".", 1)[-1], "application/octet-stream")
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _attestation(self):
        raw = self.headers.get("X-Device-Attestation")
        if not raw:
            return None
        try:
            value = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
            return value if isinstance(value, dict) else None
        except Exception:
            raise EngineError("device_attestation_invalid", "设备证明不是合法 JSON", 400)

    def _challenge_principal(self, body):
        """挑战接口：见证者只出示一次性链接，其他主体必须登录。"""
        if body.get("action") == "sign" and body.get("role") == "witness":
            return None
        return self._principal()

    def _with_device_gateway(self, conn, action, resource, body, business):
        idem = body.get("idempotency_key") or self.headers.get("Idempotency-Key")
        for attempt in range(2):
            try:
                state = engine.begin_attested_state(
                    conn, action=action, resource=resource, body=body,
                    idem_key=idem, attestation=self._attestation())
                if state.get("replayed"):
                    return state["code"], state["reply"]
                return business(state["ctx"], idem)
            except sqlite3.IntegrityError:
                # 并发失败者在首个事务释放写锁后重读同一幂等键，回放唯一首次结果。
                conn.rollback()
                if attempt:
                    raise

    # ---------- 路由 ----------
    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if not path.startswith("/api/"):
                return self._serve_static(path)
            conn = dbmod.get_conn()
            try:
                if path == "/api/me":
                    p = self._principal()
                    s = engine.get_subject(conn, self._linked_subject(conn, p)) if p["role"] == "subject" else None
                    return self._send(200, {"user": self._safe_user(p), "subject": s})
                if path == "/api/institutions":
                    return self._send(200, engine.list_institutions(conn))
                if path == "/api/materials":
                    p = self._principal()
                    q = self._qs()
                    if p["role"] == "site":
                        q.setdefault("inst_id", p["inst_id"])
                    return self._send(200, engine.list_materials(
                        conn, inst_id=q.get("inst_id"), family=q.get("family"),
                        include_retired=q.get("include_retired") == "1" and p["role"] == "admin"))
                if path == "/api/subjects":
                    p = self._principal()
                    if p["role"] != "site":
                        raise EngineError("forbidden", "仅现场人员可列对象", 403)
                    return self._send(200, engine.list_subjects(conn, p["inst_id"]))
                if path == "/api/sessions":
                    p = self._principal()
                    kwargs = {}
                    if p["role"] == "site":
                        kwargs["inst_id"] = p["inst_id"]
                    elif p["role"] == "subject":
                        kwargs["subject_id"] = self._linked_subject(conn, p)
                    else:
                        raise EngineError("forbidden", "规则维护员不接触办理明细", 403)
                    return self._send(200, engine.list_sessions(conn, **kwargs))
                if path == "/api/audit":
                    p = self._principal()
                    q = self._qs()
                    return self._send(200, engine.audit_events(
                        conn, p, inst_id=q.get("inst_id"),
                        limit=int(q.get("limit", 100))))

                m = _PAT["subject"].match(path)
                if m:
                    p = self._principal()
                    sid = m.group(1)
                    s = engine.get_subject(conn, sid)
                    self._guard_subject(conn, p, s)
                    return self._send(200, s)
                m = _PAT["subject_elig"].match(path)
                if m:
                    p = self._principal()
                    s = engine.get_subject(conn, m.group(1))
                    self._guard_subject(conn, p, s)
                    return self._send(200, engine.eligibility_for_subject(conn, s))
                m = _PAT["subject_sessions"].match(path)
                if m:
                    p = self._principal()
                    s = engine.get_subject(conn, m.group(1))
                    self._guard_subject(conn, p, s)
                    return self._send(200, engine.list_sessions(conn, subject_id=s["id"]))
                m = _PAT["subject_permits"].match(path)
                if m:
                    p = self._principal()
                    s = engine.get_subject(conn, m.group(1))
                    self._guard_subject(conn, p, s)
                    return self._send(200, engine.list_permits(conn, s["id"]))
                m = _PAT["subject_exec"].match(path)
                if m:
                    p = self._principal()
                    s = engine.get_subject(conn, m.group(1))
                    self._guard_subject(conn, p, s)
                    return self._send(200, engine.list_executions(conn, s["id"]))
                m = _PAT["subject_check"].match(path)
                if m:
                    p = self._principal()
                    s = engine.get_subject(conn, m.group(1))
                    self._guard_subject(conn, p, s)
                    q = self._qs()
                    if "op" not in q:
                        raise EngineError("missing_op", "需要 op 查询参数")
                    return self._send(200, engine.evaluate(conn, s["id"], q["op"],
                                                           q.get("purpose")))
                m = _PAT["session"].match(path)
                if m:
                    p = self._principal(required=False)
                    return self._send(200, engine.get_session(conn, m.group(1), p))
                raise EngineError("not_found", "接口不存在", 404)
            finally:
                conn.close()
        except EngineError as e:
            self._send(e.http, {"error": e.code, "message": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": "internal", "message": str(e)})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            conn = dbmod.get_conn()
            body = self._body()
            try:
                if path == "/api/auth/login":
                    tok, user = engine.authenticate(conn, body.get("login", ""),
                                                    body.get("password", ""))
                    return self._send(200, {"token": tok, "user": self._safe_user(user)})

                if path == "/api/devices/challenge":
                    p = self._challenge_principal(body)
                    return self._send(201, engine.create_challenge(
                        conn, body, principal=p))

                if path == "/api/devices/register":
                    return self._send(201, engine.register_device(conn, body))

                if path == "/api/devices/rotate-code":
                    p = self._principal()
                    return self._send(200, engine.create_rotation_enrollment(
                        conn, p, body.get("credential_id")))

                if path == "/api/devices/revoke":
                    p = self._principal()
                    return self._send(200, engine.revoke_device(
                        conn, p, body.get("device_id"), body.get("reason", "")))

                if path == "/api/device-audit":
                    p = self._principal()
                    q = self._qs()
                    return self._send(200, engine.list_device_audit(
                        conn, p, inst_id=q.get("inst_id"), device_id=q.get("device_id"),
                        limit=q.get("limit", 200)))

                if path == "/api/admin/device-enrollments":
                    p = self._principal()
                    return self._send(201, engine.create_user_enrollment(
                        conn, p, body.get("user_id")))

                if path == "/api/materials":
                    p = self._principal()
                    m = engine.publish_material(
                        conn, family=body.get("family"), inst_id=body.get("inst_id"),
                        language=body.get("language", "zh"), body=body.get("body", ""),
                        conditions=body.get("conditions", {}), roles=body.get("roles"),
                        scope=body.get("scope"),
                        requires_reconsent=body.get("requires_reconsent", False),
                        reconsent_ops=body.get("reconsent_ops", []), principal=p)
                    return self._send(201, m)

                m = _PAT["material_retire"].match(path)
                if m:
                    p = self._principal()
                    return self._send(200, engine.retire_material(conn, int(m.group(1)), p))

                m = _PAT["subject_sessions"].match(path)
                if m:
                    p = self._principal()
                    s = engine.get_subject(conn, m.group(1))
                    self._guard_subject(conn, p, s)
                    return self._send(*self._with_device_gateway(
                        conn, "session.start", m.group(1), body,
                        lambda ctx, _idem: (201, engine.start_session(
                            conn, m.group(1), int(body["material_id"]), p,
                            attested_ctx=ctx))))

                m = _PAT["session_tokens"].match(path)
                if m:
                    p = self._principal()
                    engine.get_session(conn, m.group(1), p)
                    return self._send(*self._with_device_gateway(
                        conn, "witness.tokens", m.group(1), body,
                        lambda ctx, _idem: (200, engine.slot_tokens(
                            conn, m.group(1), p, attested_ctx=ctx))))

                m = _PAT["session_sign"].match(path)
                if m:
                    # 见证者可持一次性令牌免登录；参与人/现场负责人必须登录。
                    # 三者都必须先在本站有效设备上完成挑战-响应。
                    p = self._principal(required=(body.get("role") != "witness"))
                    return self._send(*self._with_device_gateway(
                        conn, "sign", m.group(1), body,
                        lambda ctx, _idem: engine.sign(
                            conn, m.group(1), body.get("role"),
                            signer_name=body.get("signer_name"), token=body.get("token"),
                            principal=p, idem_key=_idem, attested_ctx=ctx)))

                m = _PAT["session_revoke"].match(path)
                if m:
                    p = self._principal()
                    return self._send(*self._with_device_gateway(
                        conn, "revoke", m.group(1), body,
                        lambda ctx, idem: engine.revoke(
                            conn, m.group(1), p, idem_key=idem, attested_ctx=ctx)))

                m = _PAT["subject_execute"].match(path)
                if m:
                    p = self._principal()
                    s = engine.get_subject(conn, m.group(1))
                    self._guard_subject(conn, p, s)
                    return self._send(*self._with_device_gateway(
                        conn, "execute", s["id"], body,
                        lambda ctx, idem: engine.execute(
                            conn, s["id"], body.get("op"), purpose=body.get("purpose"),
                            principal=p, idem_key=idem, attested_ctx=ctx)))

                raise EngineError("not_found", "接口不存在", 404)
            finally:
                conn.close()
        except EngineError as e:
            self._send(e.http, {"error": e.code, "message": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": "internal", "message": str(e)})

    # ---------- 权限工具 ----------
    def _safe_user(self, u):
        return {"id": u["id"], "login": u["login"], "name": u["name"],
                "role": u["role"], "inst_id": u["inst_id"]}

    def _linked_subject(self, conn, p):
        r = conn.execute("SELECT id FROM subjects WHERE user_id=?", (p["id"],)).fetchone()
        return r["id"] if r else None

    def _guard_subject(self, conn, p, s):
        if p["role"] == "site":
            if p["inst_id"] != s["inst_id"]:
                raise EngineError("subject_not_found", "对象不存在", 404)
        elif p["role"] == "subject":
            if self._linked_subject(conn, p) != s["id"]:
                raise EngineError("subject_not_found", "对象不存在", 404)
        else:
            raise EngineError("forbidden", "规则维护员不接触参与人对象", 403)


def main():
    dbmod.init_db()
    import seed
    seed.ensure_seed(dbmod.get_conn())
    port = int(os.environ.get("CONSENT_PORT", "8088"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    print(f"consent engine on http://127.0.0.1:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()

"""标准库 HTTP API + 三类角色静态页面。"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import db as dbmod
import service
from service import ServiceError

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
MAX_BODY = 4 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "BehaviorReconciliation/1.0"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY:
            raise ServiceError("body_too_large", "请求体过大", 413)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ServiceError("bad_json", "请求体不是合法 JSON；批量导入整批拒绝")
        if not isinstance(value, (dict, list)):
            raise ServiceError("bad_body", "请求体必须是 JSON 对象或数组")
        return value

    def qs(self):
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    def token(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else None

    def principal(self, required=True):
        try:
            conn = getattr(self, "_conn", None)
            return service.principal(conn, self.token())
        except ServiceError:
            if required:
                raise
            return None

    def static(self, path):
        if path == "/":
            path = "/index.html"
        name = os.path.normpath(path).lstrip("/")
        if name.startswith("static/"):
            name = name[len("static/"):]
        full = os.path.join(STATIC_DIR, name)
        if not full.startswith(STATIC_DIR + os.sep) or not os.path.isfile(full):
            self.send_error(404, "Not found")
            return
        suffix = name.rsplit(".", 1)[-1]
        ctype = {"html": "text/html; charset=utf-8",
                 "js": "text/javascript; charset=utf-8",
                 "css": "text/css; charset=utf-8"}.get(suffix, "application/octet-stream")
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.handle_request(False)

    def do_POST(self):
        self.handle_request(True)

    def handle_request(self, write):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            if write:
                self.send_error(405, "Method not allowed")
            else:
                self.static(path)
            return
        conn = dbmod.get_conn()
        self._conn = conn
        payload = {}
        try:
            if write:
                payload = self.body()
            self.dispatch(conn, path, payload, write)
        except ServiceError as e:
            self.send_json(e.http, {"error": e.code, "message": str(e)})
        except Exception as e:  # noqa: BLE001
            self.send_json(500, {"error": "internal", "message": str(e)})
        finally:
            conn.close()

    def dispatch(self, conn, path, body, write):
        q = self.qs()
        method = "POST" if write else "GET"

        if write and path == "/api/auth/login":
            token, user = service.authenticate(conn, body.get("login", ""),
                                               body.get("password", ""))
            return self.send_json(200, {"token": token, "user": user})
        user = self.principal()

        if not write and path == "/api/me":
            out = {"user": user}
            if user["role"] == "participant":
                out["subject_id"] = service.participant_subject_id(conn, user)
            return self.send_json(200, out)

        if write and path == "/api/snapshots":
            return self.send_json(201, service.import_snapshot(conn, body, user))
        if not write and path == "/api/snapshots":
            service.require_role(user, "compliance")
            return self.send_json(200, service.list_snapshots(conn, user))

        if write and path == "/api/claims":
            return self.send_json(200, service.submit_claim(conn, body, user))
        if not write and path == "/api/claims":
            return self.send_json(200, service.list_claims(
                conn, user, inst_id=q.get("inst_id")))
        if write and path == "/api/claims/batch":
            return self.send_json(200, service.submit_batch(conn, body, user))

        if write and path == "/api/cycles":
            return self.send_json(201, service.create_cycle(conn, body, user))
        if not write and path == "/api/cycles":
            return self.send_json(200, service.list_cycles(conn, user))

        if path.startswith("/api/cycles/") and path.endswith("/recompute") and write:
            cycle_id = path.split("/")[3]
            return self.send_json(200, service.recompute(
                conn, cycle_id, user,
                crash_after_publish=bool(body.get("crash_after_publish"))))
        if path.startswith("/api/cycles/") and "/versions" in path and not write:
            parts = path.strip("/").split("/")
            cycle_id = parts[2]
            if len(parts) == 4:
                return self.send_json(200, service.list_versions(conn, cycle_id, user))
            version = parts[4] if len(parts) > 4 else "latest"
            return self.send_json(200, service.get_version(conn, cycle_id, version, user))
        if path.startswith("/api/cycles/") and path.endswith("/site-items") and not write:
            cycle_id = path.split("/")[3]
            return self.send_json(200, service.latest_site_items(conn, cycle_id, user))

        if write and path.startswith("/api/items/") and path.endswith("/disposition"):
            item_id = int(path.split("/")[3])
            return self.send_json(201, service.dispose_item(conn, item_id, body, user))
        if not write and path == "/api/dispositions":
            return self.send_json(200, service.list_dispositions(
                conn, user, status=q.get("status"), inst_id=q.get("inst_id")))

        if not write and path == "/api/my/executions":
            return self.send_json(200, service.participant_view(conn, user))

        raise ServiceError("not_found", f"{method} 接口不存在", 404)


def main():
    dbmod.init_db()
    conn = dbmod.get_conn()
    try:
        import seed
        seed.ensure_seed(conn)
    finally:
        conn.close()
    port = int(os.environ.get("RECONCILE_PORT", "8090"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    print(f"behavior reconciliation on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()

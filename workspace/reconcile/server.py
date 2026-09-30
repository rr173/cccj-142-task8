"""HTTP API 与静态页面：每请求独立 SQLite 连接，写事务由服务层串行化。"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import db as dbmod
import service
from service import ServiceError

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
MAX_BODY = 8 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "ReconcileAudit/1.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        size = int(self.headers.get("Content-Length", 0) or 0)
        if size > MAX_BODY:
            raise ServiceError("body_too_large", "请求体过大", 413)
        raw = self.rfile.read(size) if size else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            # 批量导入遇到格式损坏：服务层/路由捕获后不会写入任何声明。
            raise ServiceError("bad_json", "请求体不是合法 JSON", 400) from exc
        if not isinstance(data, dict):
            raise ServiceError("bad_body", "请求体必须是 JSON 对象", 400)
        return data

    def _query(self):
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    def _token(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else None

    def _user(self):
        return service.principal(self.conn, self._token())

    def _static(self, path):
        if path == "/":
            path = "/index.html"
        name = os.path.normpath(path).lstrip("/")
        if name.startswith("static/"):
            name = name[7:]
        full = os.path.join(STATIC_DIR, name)
        if not full.startswith(STATIC_DIR + os.sep) or not os.path.isfile(full):
            self.send_error(404, "Not found")
            return
        ctype = {
            "html": "text/html; charset=utf-8",
            "js": "text/javascript; charset=utf-8",
            "css": "text/css; charset=utf-8",
        }.get(name.rsplit(".", 1)[-1], "application/octet-stream")
        with open(full, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self._static(path)
        self.conn = dbmod.get_conn()
        try:
            q = self._query()
            if path == "/api/me":
                return self._send(200, {"user": service.safe_user(self._user())})
            user = self._user()

            if path == "/api/cycles":
                return self._send(200, service.list_cycles(self.conn, user))
            if path == "/api/subject/basis":
                return self._send(200, service.subject_basis_view(self.conn, user))
            if path == "/api/dispositions/stale":
                return self._send(200, service.list_stale_dispositions(self.conn, user))
            if path.startswith("/api/cycles/") and path.endswith("/latest"):
                cycle_id = path[len("/api/cycles/"):-len("/latest")]
                return self._send(200, service.latest_version(self.conn, cycle_id, user))
            if path.startswith("/api/versions/"):
                version_id = int(path[len("/api/versions/"):])
                return self._send(200, service.version_view(self.conn, version_id, user))
            if path.startswith("/api/claims/"):
                return self._send(200, service.get_claim(self.conn, path[len("/api/claims/"):], user))
            raise ServiceError("not_found", "接口不存在", 404)
        except ServiceError as exc:
            self._send(exc.http, {"error": exc.code, "message": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._send(500, {"error": "internal", "message": str(exc)})
        finally:
            self.conn.close()

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._body()
        except ServiceError as exc:
            return self._send(exc.http, {"error": exc.code, "message": str(exc)})
        self.conn = dbmod.get_conn()
        try:
            if path == "/api/auth/login":
                token, user = service.authenticate(
                    self.conn, body.get("login", ""), body.get("password", ""))
                return self._send(200, {"token": token, "user": user})
            user = self._user()

            if path == "/api/permit-snapshots":
                return self._send(201, service.import_permit_snapshot(self.conn, body, user))
            if path == "/api/permit-terminations":
                return self._send(201, service.import_termination(self.conn, body, user))
            if path == "/api/claims":
                result = service.ingest_claim(self.conn, body, user)
                return self._send(result.get("status_code", 200 if result.get("accepted") else 409),
                                  result)
            if path == "/api/claim-batches":
                return self._send(201, service.ingest_batch(self.conn, body, user))
            if path == "/api/cycles":
                return self._send(201, service.create_cycle(self.conn, body, user))
            if path.startswith("/api/cycles/") and path.endswith("/recompute"):
                cycle_id = path[len("/api/cycles/"):-len("/recompute")]
                result = service.recompute(
                    self.conn, cycle_id, user,
                    crash_after_publish=body.get("__crash_after_publish", False))
                return self._send(200, result)
            if path.startswith("/api/items/") and path.endswith("/disposition"):
                item_id = int(path[len("/api/items/"):-len("/disposition")])
                return self._send(201, service.dispose_item(self.conn, item_id, body, user))
            if path.startswith("/api/dispositions/") and path.endswith("/review"):
                disposition_id = int(path[len("/api/dispositions/"):-len("/review")])
                return self._send(200, service.review_stale_disposition(
                    self.conn, disposition_id, body, user))
            raise ServiceError("not_found", "接口不存在", 404)
        except ServiceError as exc:
            self._send(exc.http, {"error": exc.code, "message": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._send(500, {"error": "internal", "message": str(exc)})
        finally:
            self.conn.close()


def main():
    dbmod.init_db()
    import seed
    seed.ensure_seed(dbmod.get_conn())
    port = int(os.environ.get("RECONCILE_PORT", "8090"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    print(f"reconciliation audit on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()

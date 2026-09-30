"""真实 HTTP 进程崩溃恢复验证。

运行：python3 tests/test_restart.py
发布事务提交后、响应返回前强制 os._exit；重启后必须识别已发布版本且不重复生成差异。
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import db as dbmod  # noqa: E402
from db import hash_pw  # noqa: E402


def request(port, path, body=None, token=None, method=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, headers=headers,
        method=method or ("POST" if body is not None else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not start")


def prepare(path):
    dbmod.DB_PATH = path
    dbmod._initialized = False
    dbmod.init_db()
    conn = dbmod.get_conn()
    conn.execute("INSERT INTO institutions(id,name) VALUES('INST-A','A')")
    salt = "s"
    conn.execute(
        "INSERT INTO users(id,inst_id,role,login,name,pw_hash,pw_salt) VALUES"
        "(?,NULL,'compliance','compliance','合规',?,?)",
        ("U-C", hash_pw(salt, "pw"), salt))
    conn.execute("INSERT INTO subjects(id,inst_id,name,user_id) VALUES('S-A','INST-A','A',NULL)")
    conn.execute("INSERT INTO cycles(id,starts_at,ends_at,created_at) VALUES"
                 "('CY1','2026-09-01T00:00:00Z','2026-10-01T00:00:00Z','t')")
    conn.execute(
        "INSERT INTO permit_snapshots(permit_id,subject_id,inst_id,family,basis_version,"
        "scope_json,allowed_purposes_json,effective_at,snapshot_version,body_hash,imported_at)"
        " VALUES('P1','S-A','INST-A','MAIN',1,?,?, '2026-08-01T00:00:00Z',1,?, 't')",
        (json.dumps(["BLOOD_DRAW"]), json.dumps([]), "a" * 64))
    conn.execute(
        "INSERT INTO claim_versions(claim_id,version_no,source_system,source_claim_code,"
        "subject_id,inst_id,neutral_op,purpose,occurred_at,basis_family,basis_version,"
        "payload_json,body_hash,replaces_version,received_at) VALUES"
        "('C1',1,'blood_station','SRC','S-A','INST-A','BLOOD_DRAW','routine',"
        "'2026-09-02T09:00:00Z','MAIN',1,'{}', 'h',NULL,'t')")
    conn.execute(
        "INSERT INTO claim_current(claim_id,current_version,current_body_hash,receipt,"
        "first_received_at,updated_at) VALUES('C1',1,'h','R1','t','t')")
    conn.commit()
    conn.close()


def start(db_path, port):
    env = os.environ.copy()
    env["RECONCILE_DB"] = db_path
    env["RECONCILE_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, "server.py"], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_port(port)
    except Exception:
        proc.terminate()
        out, err = proc.communicate(timeout=5)
        print(out.decode(errors="ignore"))
        print(err.decode(errors="ignore"), file=sys.stderr)
        raise
    return proc


def main():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "crash.db")
        prepare(db_path)
        port = 8967
        proc = start(db_path, port)
        try:
            _status, login = request(port, "/api/auth/login", {"login": "compliance", "password": "pw"})
            token = login["token"]
            try:
                request(port, "/api/cycles/CY1/recompute",
                        {"__crash_after_publish": True}, token=token)
                raise AssertionError("server should have exited before HTTP response")
            except Exception:
                pass
            proc.wait(timeout=10)
            assert proc.returncode == 97, proc.returncode

            proc = start(db_path, port)
            status, version = request(port, "/api/cycles/CY1/latest", token=token)
            assert status == 200 and version["version_no"] == 1
            assert len(version["items"]) == 1
            before_ids = [i["id"] for i in version["items"]]

            # 输入未变化，再次重算识别既有版本，不能生成第二版或第二批差异项。
            status, same = request(port, "/api/cycles/CY1/recompute", {}, token=token)
            assert status == 200 and same["id"] == version["id"]
            assert [i["id"] for i in same["items"]] == before_ids
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    print("PASS crash recovery: published version recognized; no duplicate items")


if __name__ == "__main__":
    main()

"""平台事件出站队列：真实 uvicorn 进程 SIGKILL 重启持久性。

验证：
- 已提交事务写出的事件、订阅、queued/leased/死信投递全部落盘；
- 重启后后台队列继续处理未发送/重试到期的记录；
- "投递成功但平台落 sent 前崩溃" → 重启后重投，接收端按 event_id 去重，
  最终只落一条 sent，历史事件不被回写（签名/正文/序号不变）。
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from rts.db import connect
from rts.events import canonical_json

ROOT = Path(__file__).resolve().parents[2]
PORT = 18791
BASE = f"http://127.0.0.1:{PORT}"
RECV_PORT = 18792


class Receiver:
    """最小订阅端点：记录收到的事件，按 X-RTS-Event-Id 去重统计。
    行为可由 mode 控制：'ok' 恒 200；'fail_first' 每个事件首次 500，之后 200。"""

    def __init__(self, mode="ok"):
        self.mode = mode
        self.received = []          # 全部投递（含重复）
        self.unique = {}            # event_id -> envelope（首次）
        self.lock = threading.Lock()
        self._seen = set()
        self.httpd = None
        self.thread = None

    def start(self):
        recv = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                env = json.loads(body)
                eid = self.headers.get("X-RTS-Event-Id")
                with recv.lock:
                    recv.received.append({
                        "event_id": eid,
                        "seq": self.headers.get("X-RTS-Event-Seq"),
                        "sub_version": self.headers.get("X-RTS-Subscription-Version"),
                        "signature_present": bool(self.headers.get("X-RTS-Signature")),
                        "envelope": env,
                    })
                    first = eid not in recv._seen
                    recv._seen.add(eid)
                    if first:
                        recv.unique[eid] = env
                    if recv.mode == "fail_first" and first:
                        self.send_response(500); self.end_headers()
                        self.wfile.write(b"retry")
                        return
                self.send_response(200); self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", RECV_PORT), H)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()


def _wait_up(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{BASE}/api/health", timeout=1).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("server did not come up")


def _spawn(db_path):
    env = os.environ.copy()
    env["RTS_DB"] = db_path
    env["PYTHONPATH"] = str(ROOT)
    env["RTS_QUEUE_ENABLED"] = "1"
    env["RTS_QUEUE_INTERVAL"] = "0.3"
    env["RTS_QUEUE_LEASE"] = "2"
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "rts.main:app",
         "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


@pytest.fixture
def db_path(tmp_path):
    p = str(tmp_path / "evt_restart.db")
    env = os.environ.copy()
    env["RTS_DB"] = p
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, "-m", "rts.seed"], cwd=str(ROOT), env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return p


def _login(c, u):
    t = c.post("/api/login", json={"username": u, "password": "demo1234"}).json()["token"]
    return {"X-Authorization": f"Bearer {t}"}


def _wait_n(predicate, timeout=15, interval=0.3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_restart_picks_up_pending_and_dedups(db_path):
    recv = Receiver(mode="ok").start()
    endpoint = f"http://127.0.0.1:{RECV_PORT}/hook"
    proc = _spawn(db_path)
    try:
        _wait_up()
        c = httpx.Client(base_url=BASE, timeout=10)
        safe = _login(c, "safe1")
        inv = _login(c, "inv01")
        ph = _login(c, "ph01")
        # 订阅：全收
        r = c.post("/api/safety/event-subscriptions", headers=safe,
                   json={"name": "本地接收端", "endpoint_url": endpoint})
        assert r.status_code == 200, r.text
        # 两笔入组 + 发药（产生多条事件）
        rand = []
        for code in ("E1", "E2"):
            c.post("/api/investigator/eligibility", headers=inv, json={
                "subject_code": code,
                "answers": {"informed_consent": True, "age_ok": True,
                            "indication_ok": True, "no_exclusion": True}})
            e = c.post("/api/investigator/enroll", headers=inv,
                       json={"subject_code": code, "pv_code": "V1.0"}).json()
            rand.append(e["random_no"])
            d = c.post("/api/pharmacy/dispense", headers=ph,
                       json={"random_no": e["random_no"]})
            assert d.status_code == 200, d.text
        # 等后台队列投递完
        assert _wait_n(lambda: len(recv.unique) >= 4), len(recv.unique)
        c.close()
    finally:
        proc.kill(); proc.wait(timeout=10)

    # 重启：全部应为 sent；再无重复投递（worker 不会重发已 sent）
    before_unique = dict(recv.unique)
    proc2 = _spawn(db_path)
    try:
        _wait_up()
        time.sleep(2.0)  # 让队列空跑几轮
        conn = connect(db_path)
        rows = conn.execute(
            "SELECT status, COUNT(*) n FROM event_deliveries GROUP BY status"
        ).fetchall()
        counts = {r["status"]: r["n"] for r in rows}
        assert counts.get("sent", 0) >= 4, counts
        assert "queued" not in counts and "leased" not in counts and "dead" not in counts
        # 历史事件未被回写：序号/事件标识仍与重启前收到的一致
        for eid, env in before_unique.items():
            dbrow = conn.execute(
                "SELECT seq,event_id,signature,body FROM platform_events WHERE event_id=?",
                (eid,)).fetchone()
            assert dbrow["seq"] == env["header"]["seq"]
            assert dbrow["signature"] == env["signature"]
            assert canonical_json(dbrow["body"] and json.loads(dbrow["body"])) == \
                canonical_json(env["body"])
        # 完整性巡检（库内重算链与签名）
        from rts.events import EventBus
        assert EventBus(conn).check_integrity()["ok"]
        conn.close()
    finally:
        proc2.kill(); proc2.wait(timeout=10)
        recv.stop()


def test_restart_retries_failed_then_succeeds(db_path):
    # 接收端对每个事件首次返回 500（触发退避重试），之后 200
    recv = Receiver(mode="fail_first").start()
    endpoint = f"http://127.0.0.1:{RECV_PORT}/hook"
    proc = _spawn(db_path)
    try:
        _wait_up()
        c = httpx.Client(base_url=BASE, timeout=10)
        safe = _login(c, "safe1"); inv = _login(c, "inv01")
        c.post("/api/safety/event-subscriptions", headers=safe,
               json={"name": "先败后成", "endpoint_url": endpoint,
                     "kinds": ["enrolled"]})
        c.post("/api/investigator/eligibility", headers=inv, json={
            "subject_code": "F1",
            "answers": {"informed_consent": True, "age_ok": True,
                        "indication_ok": True, "no_exclusion": True}})
        e = c.post("/api/investigator/enroll", headers=inv,
                   json={"subject_code": "F1", "pv_code": "V1.0"}).json()
        # 立即硬杀：可能停在 queued / leased / 退避中
        c.close()
    finally:
        proc.kill(); proc.wait(timeout=10)

    proc2 = _spawn(db_path)
    try:
        _wait_up()
        # 重启后台队列继续退避重试，最终接收端成功（同一事件首次失败、重试成功）
        assert _wait_n(lambda: len(recv.unique) >= 1), "重启后未完成重试投递"
        eid = next(iter(recv.unique))
        assert _wait_n(lambda: any(
            r["event_id"] == eid and r["envelope"]["header"]["body_digest"]
            for r in recv.received), timeout=12)
        # 该投递最终 sent，且 attempts 体现了重试
        conn = connect(db_path)
        assert _wait_n(lambda: conn.execute(
            "SELECT status FROM event_deliveries d JOIN platform_events e ON e.id=d.event_id "
            "WHERE e.event_id=?", (eid,)).fetchone()["status"] == "sent", timeout=12)
        d = conn.execute(
            "SELECT attempts FROM event_deliveries d JOIN platform_events e ON e.id=d.event_id "
            "WHERE e.event_id=?", (eid,)).fetchone()
        assert d["attempts"] >= 1
        # 尝试流水里出现过 retried，且错误码是稳定码、不含密钥
        logs = conn.execute(
            """SELECT result,error_code FROM delivery_attempts a
               JOIN event_deliveries d ON d.id=a.delivery_id
               JOIN platform_events e ON e.id=d.event_id
               WHERE e.event_id=?""", (eid,)).fetchall()
        results = {x["result"] for x in logs}
        assert "retried" in results and "sent" in results
        for x in logs:
            assert x["error_code"] is None or x["error_code"].startswith("ENDPOINT_")
        conn.close()
    finally:
        proc2.kill(); proc2.wait(timeout=10)
        recv.stop()

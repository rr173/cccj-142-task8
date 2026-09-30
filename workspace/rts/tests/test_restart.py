"""服务重启持久性：真实 uvicorn 进程，SIGKILL 后用同一 DB 文件重启，
随机序列位置、随机号、药盒三态/流水、登录会话都必须存活且序列可继续。"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from rts.service import arm_at

ROOT = Path(__file__).resolve().parents[2]
PORT = 18765
BASE = f"http://127.0.0.1:{PORT}"


def _wait_up(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{BASE}/api/health", timeout=1).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("server did not come up")


def _spawn(db_path):
    env = os.environ.copy()
    env["RTS_DB"] = db_path
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "rts.main:app",
         "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


@pytest.fixture
def db_path(tmp_path):
    p = str(tmp_path / "restart.db")
    env = os.environ.copy()
    env["RTS_DB"] = p
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, "-m", "rts.seed"], cwd=str(ROOT), env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return p


def test_kill_and_restart_preserves_everything(db_path):
    # ---------- 第一次启动：业务操作 ----------
    proc = _spawn(db_path)
    try:
        _wait_up()
        c = httpx.Client(base_url=BASE)
        token = c.post("/api/login", json={"username": "inv01", "password": "demo1234"}).json()["token"]
        inv = {"X-Authorization": f"Bearer {token}"}
        ptoken = c.post("/api/login", json={"username": "ph01", "password": "demo1234"}).json()["token"]
        ph = {"X-Authorization": f"Bearer {ptoken}"}

        nos = []
        for code in ["R1", "R2", "R3"]:
            c.post("/api/investigator/eligibility", headers=inv, json={
                "subject_code": code,
                "answers": {"informed_consent": True, "age_ok": True,
                            "indication_ok": True, "no_exclusion": True}})
            r = c.post("/api/investigator/enroll", headers=inv,
                       json={"subject_code": code, "pv_code": "V1.0"})
            nos.append(r.json()["random_no"])
        assert nos == ["V10-01-0001", "V10-01-0002", "V10-01-0003"]

        d1 = c.post("/api/pharmacy/dispense", headers=ph,
                    json={"random_no": nos[0]}).json()
        d2 = c.post("/api/pharmacy/dispense", headers=ph,
                    json={"random_no": nos[1]}).json()
        # 退第一盒但不再入库（模拟停在 returned 状态）
        c.post("/api/pharmacy/return", headers=ph,
               json={"kit_no": d1["kit_no"], "note": "重启前退药"})
        c.close()
    finally:
        # 硬杀（SIGKILL），不给优雅停机机会
        proc.kill()
        proc.wait(timeout=10)

    # ---------- 第二次启动：验证存活 ----------
    proc2 = _spawn(db_path)
    try:
        _wait_up()
        c = httpx.Client(base_url=BASE)
        # 旧 token 仍有效（会话已持久化）
        me = c.get("/api/me", headers=inv)
        assert me.status_code == 200 and me.json()["username"] == "inv01"

        subjects = c.get("/api/investigator/subjects", headers=inv).json()
        assert sorted(x["random_no"] for x in subjects) == nos

        # 序列继续：第 4 号位置推出的治疗组必须与确定性序列 index=3 一致
        c.post("/api/investigator/eligibility", headers=inv, json={
            "subject_code": "R4",
            "answers": {"informed_consent": True, "age_ok": True,
                        "indication_ok": True, "no_exclusion": True}})
        r4 = c.post("/api/investigator/enroll", headers=inv,
                    json={"subject_code": "R4", "pv_code": "V1.0"}).json()
        assert r4["random_no"] == "V10-01-0004"

        # 直接读库对照确定性序列
        from rts.db import connect as db_connect
        conn = db_connect(db_path)
        for i, no in enumerate(nos + [r4["random_no"]]):
            arm = conn.execute("SELECT arm FROM subjects WHERE random_no=?", (no,)).fetchone()["arm"]
            assert arm == arm_at("V1.0", "01", i, ["A", "B"], [1, 1], 4), no
        # 药盒状态存活：d1 returned 无持有人；d2 dispensed 有持有人
        k1 = conn.execute("SELECT status,holder_subject_id FROM kits WHERE kit_no=?",
                          (d1["kit_no"],)).fetchone()
        k2 = conn.execute("SELECT status,holder_subject_id FROM kits WHERE kit_no=?",
                          (d2["kit_no"],)).fetchone()
        assert tuple(k1) == ("returned", None)
        assert k2["status"] == "dispensed" and k2["holder_subject_id"] is not None
        conn.close()

        # 守恒巡检
        stoken = c.post("/api/login", json={"username": "safe1", "password": "demo1234"}).json()["token"]
        rep = c.get("/api/safety/invariants",
                    headers={"X-Authorization": f"Bearer {stoken}"}).json()
        assert rep["ok"], rep
        c.close()
    finally:
        proc2.kill()
        proc2.wait(timeout=10)

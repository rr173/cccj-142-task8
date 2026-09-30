"""测试公共夹具：每个测试独立 DB + TestClient，自动播种演示数据。"""
import os
import sys
import tempfile
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# 测试中关闭后台投递线程：投递由测试用假传输手动驱动（确定性、不发真实网络）
os.environ.setdefault("RTS_QUEUE_ENABLED", "0")

from fastapi.testclient import TestClient  # noqa: E402

from rts import main as appmod  # noqa: E402
from rts.seed import seed  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(appmod, "DB_PATH", db_path)
    seed(db_path)
    with TestClient(appmod.app) as c:
        yield c


def login(client, username, password="demo1234"):
    r = client.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    h = {"X-Authorization": "Bearer " + r.json()["token"]}
    return h


def pass_eligibility(client, h, code):
    r = client.post("/api/investigator/eligibility", headers=h, json={
        "subject_code": code,
        "answers": {"informed_consent": True, "age_ok": True,
                    "indication_ok": True, "no_exclusion": True},
    })
    assert r.status_code == 200 and r.json()["eligible"], r.text


def enroll(client, h, code, pv="V1.0"):
    pass_eligibility(client, h, code)
    r = client.post("/api/investigator/enroll", headers=h,
                    json={"subject_code": code, "pv_code": pv})
    assert r.status_code == 200, r.text
    return r.json()

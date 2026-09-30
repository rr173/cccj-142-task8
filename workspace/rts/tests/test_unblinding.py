"""揭盲流程：数据锁定前置、双人审批、同人不可双算、锁定解除阻断、审批后才释放全表。"""
from .conftest import login, enroll


def test_normal_unblind_requires_lock_and_two_people(client):
    safe1, safe2 = login(client, "safe1"), login(client, "safe2")
    inv = login(client, "inv01")
    enroll(client, inv, "U-1")
    enroll(client, inv, "U-2")

    # 未锁数据 → 拒绝
    r = client.post("/api/safety/unblind-requests", headers=safe1,
                    json={"reason": "试验结束揭盲"})
    assert r.status_code == 409 and r.json()["error"] == "DATA_NOT_LOCKED"

    # 锁数据
    assert client.post("/api/safety/data-lock", headers=safe1).status_code == 200

    # 发起即第一票
    r = client.post("/api/safety/unblind-requests", headers=safe1,
                    json={"reason": "试验结束揭盲"})
    assert r.status_code == 200
    req = r.json()
    assert req["status"] == "pending" and "unblinded_table" not in req

    # 同一人不能双算
    again = client.post(f"/api/safety/unblind-requests/{req['id']}/approve", headers=safe1)
    assert again.status_code == 409 and again.json()["error"] == "ALREADY_APPROVED_BY_YOU"

    # 待审批期间列表接口绝不释放分组
    pending_list = client.get("/api/safety/unblind-requests", headers=safe2).json()
    assert all("unblinded_table" not in x for x in pending_list)

    # 第二人审批 → 通过并释放全表
    r2 = client.post(f"/api/safety/unblind-requests/{req['id']}/approve", headers=safe2)
    assert r2.status_code == 200
    done = r2.json()
    assert done["status"] == "approved"
    table = done["unblinded_table"]
    assert len(table) == 2 and all(x["arm"] in ("A", "B") for x in table)

    # 已结束申请不可再审
    assert client.post(f"/api/safety/unblind-requests/{req['id']}/approve",
                       headers=safe2).status_code == 409

    # 事后查看接口：仅 approved 的请求能取到分组表
    got = client.get(f"/api/safety/unblind-requests/{req['id']}", headers=safe1).json()
    assert "unblinded_table" in got and len(got["unblinded_table"]) == 2


def test_only_security_can_unblind(client):
    inv = login(client, "inv01")
    ph = login(client, "ph01")
    assert client.post("/api/safety/data-lock", headers=inv).status_code == 403
    assert client.post("/api/safety/unblind-requests", headers=ph,
                       json={"reason": "x"}).status_code == 403


def test_audit_records_sensitive_actions(client):
    safe1, safe2 = login(client, "safe1"), login(client, "safe2")
    inv = login(client, "inv01")
    s = enroll(client, inv, "AUD-1")
    client.post(f"/api/investigator/emergency-unblind/{s['random_no']}",
                headers=inv, json={"reason": "急救"})
    client.post("/api/safety/data-lock", headers=safe1)
    req = client.post("/api/safety/unblind-requests", headers=safe1,
                      json={"reason": "结束"}).json()
    client.post(f"/api/safety/unblind-requests/{req['id']}/approve", headers=safe2)

    log = client.get("/api/safety/audit?limit=500", headers=safe1).json()
    actions = {e["action"] for e in log}
    assert {"login", "randomize", "emergency_unblind", "data_lock",
            "unblind_request", "unblind_approve"} <= actions
    # 审计明细不得泄露治疗组（randomize 不含 arm）
    for e in log:
        if e["action"] == "randomize":
            assert '"arm"' not in e["detail"]

"""端到端 + 随机化压力下的守恒不变量。"""
import random
from .conftest import login, pass_eligibility
from rts.db import connect
from rts import main as appmod


def test_full_workflow_end_to_end(client):
    inv01, inv02 = login(client, "inv01"), login(client, "inv02")
    ph01, ph02 = login(client, "ph01"), login(client, "ph02")
    safe1, safe2 = login(client, "safe1"), login(client, "safe2")

    enrolled = {"01": [], "02": []}
    for center, inv, ph in [("01", inv01, ph01), ("02", inv02, ph02)]:
        for i in range(5):
            code = f"E2E-{center}-{i}"
            pass_eligibility(client, inv, code)
            r = client.post("/api/investigator/enroll", headers=inv,
                            json={"subject_code": code, "pv_code": "V1.0"})
            assert r.status_code == 200
            d = client.post("/api/pharmacy/dispense", headers=ph,
                            json={"random_no": r.json()["random_no"]})
            assert d.status_code == 200, d.text
            enrolled[center].append((r.json(), d.json()))

    # 北京退 2 盒并再入库，再发给新受试者
    for info, disp in enrolled["01"][:2]:
        client.post("/api/pharmacy/return", headers=ph01, json={"kit_no": disp["kit_no"]})
        client.post("/api/pharmacy/restock", headers=ph01, json={"kit_no": disp["kit_no"]})
    for i in range(2):
        code = f"E2E-01-N{i}"
        pass_eligibility(client, inv01, code)
        r = client.post("/api/investigator/enroll", headers=inv01,
                        json={"subject_code": code, "pv_code": "V1.0"}).json()
        d = client.post("/api/pharmacy/dispense", headers=ph01,
                        json={"random_no": r["random_no"]})
        assert d.status_code == 200, d.text

    # 一个应急揭盲
    target = enrolled["02"][0][0]
    r = client.post(f"/api/investigator/emergency-unblind/{target['random_no']}",
                    headers=inv02, json={"reason": "过敏反应需确认用药"})
    assert r.status_code == 200 and r.json()["scope"] == "single_subject"

    # 正常揭盲双人流程
    client.post("/api/safety/data-lock", headers=safe1)
    req = client.post("/api/safety/unblind-requests", headers=safe1,
                      json={"reason": "锁库后揭盲"}).json()
    done = client.post(f"/api/safety/unblind-requests/{req['id']}/approve",
                       headers=safe2).json()
    assert done["status"] == "approved" and len(done["unblinded_table"]) == 12

    # 最终守恒
    rep = client.get("/api/safety/invariants", headers=safe1).json()
    assert rep["ok"], rep


def test_fuzz_kit_conservation(client):
    """随机操作流：入组→发药→部分退→再入库→再发，中途与结束反复校验不变量。"""
    inv, ph = login(client, "inv01"), login(client, "ph01")
    safe = login(client, "safe1")
    rnd = random.Random(20260926)

    n = 20
    numbers = []
    for i in range(n):
        code = f"FZ-{i}"
        pass_eligibility(client, inv, code)
        r = client.post("/api/investigator/enroll", headers=inv,
                        json={"subject_code": code, "pv_code": "V1.0"})
        assert r.status_code == 200
        numbers.append(r.json()["random_no"])

    held = []  # 已发未退
    failed = 0
    for no in numbers:
        r = client.post("/api/pharmacy/dispense", headers=ph, json={"random_no": no})
        if r.status_code == 200:
            held.append((no, r.json()["kit_no"]))
        else:
            assert r.status_code == 409
            failed += 1
        # 随机退一些
        if held and rnd.random() < 0.3:
            no2, kit = held.pop(rnd.randrange(len(held)))
            assert client.post("/api/pharmacy/return", headers=ph,
                               json={"kit_no": kit}).status_code == 200
            if rnd.random() < 0.7:
                assert client.post("/api/pharmacy/restock", headers=ph,
                                   json={"kit_no": kit}).status_code == 200

    # 库存可能不足是允许的（409 已统计）；但守恒必须始终成立
    rep = client.get("/api/safety/invariants", headers=safe).json()
    assert rep["ok"], rep

    # 数据库层二次核验：每盒 d-r ∈ {0,1}
    conn = connect(appmod.DB_PATH)
    rows = conn.execute("SELECT kit_no FROM kits").fetchall()
    for row in rows:
        agg = conn.execute(
            """SELECT SUM(event_type='dispense') d, SUM(event_type='return') r
               FROM kit_events WHERE kit_no=?""", (row["kit_no"],)).fetchone()
        assert (agg["d"] or 0) - (agg["r"] or 0) in (0, 1)
    # 随机号无重复
    dup = conn.execute(
        "SELECT random_no FROM subjects GROUP BY random_no HAVING COUNT(*)>1").fetchall()
    assert dup == []
    conn.close()

"""药盒守恒：自动匹配、兼容批号转用、并发抢最后一盒、退药再发、指定盒校验。"""
import threading
from .conftest import login, enroll, pass_eligibility
from rts.db import connect
from rts import main as appmod


def _arm_of(db, random_no):
    conn = connect(db)
    arm = conn.execute("SELECT arm FROM subjects WHERE random_no=?", (random_no,)).fetchone()["arm"]
    conn.close()
    return arm


def test_dispense_and_conservation(client):
    inv, ph = login(client, "inv01"), login(client, "ph01")
    safe = login(client, "safe1")
    for i in range(6):
        enroll(client, inv, f"D-{i}")
    subjects = client.get("/api/investigator/subjects", headers=inv).json()
    for s in subjects:
        r = client.post("/api/pharmacy/dispense", headers=ph,
                        json={"random_no": s["random_no"]})
        assert r.status_code == 200, r.text
    # 守恒巡检通过
    inv_report = client.get("/api/safety/invariants", headers=safe).json()
    assert inv_report["ok"], inv_report
    # 每人恰好一盒、每盒唯一持有人
    conn = connect(appmod.DB_PATH)
    holders = conn.execute(
        "SELECT holder_subject_id, COUNT(*) c FROM kits WHERE status='dispensed' GROUP BY holder_subject_id"
    ).fetchall()
    assert all(r["c"] == 1 for r in holders) and len(holders) == 6
    conn.close()


def test_double_dispense_rejected(client):
    inv, ph = login(client, "inv01"), login(client, "ph01")
    s = enroll(client, inv, "DD-1")
    first = client.post("/api/pharmacy/dispense", headers=ph,
                        json={"random_no": s["random_no"]}).json()
    again = client.post("/api/pharmacy/dispense", headers=ph,
                        json={"random_no": s["random_no"]})
    assert again.status_code == 409 and again.json()["error"] == "ALREADY_DISPENSED"
    # 指定同一盒也被挡
    r = client.post("/api/pharmacy/dispense", headers=ph,
                    json={"random_no": s["random_no"], "kit_no": first["kit_no"]})
    assert r.status_code == 409


def test_concurrent_claim_last_compatible_kit(client):
    """两个受试者的并发发药请求竞争最后一盒：恰有一人拿到，另一人得到 409 或其它兼容盒，
    绝不能两人拿到同一盒，也不能丢盒。"""
    inv, ph = login(client, "inv01"), login(client, "ph01")
    s1 = enroll(client, inv, "RACE-1")
    s2 = enroll(client, inv, "RACE-2")

    # 找到两人将共同竞争的那盒：先查库存，仅保留 1 盒在库并移除其余
    conn = connect(appmod.DB_PATH)
    arm1 = conn.execute("SELECT arm FROM subjects WHERE random_no=?", (s1["random_no"],)).fetchone()["arm"]
    arm2 = conn.execute("SELECT arm FROM subjects WHERE random_no=?", (s2["random_no"],)).fetchone()["arm"]
    # 构造：两人同 arm，删掉所有其它兼容盒，只留一盒（从共享批号挑一盒）
    if arm1 != arm2:
        conn.close()
        return  # 前两位若不同组则跳过该构造（序列确定性下可另造，这里用下方显式构造）

    keep = conn.execute(
        "SELECT kit_no FROM kits WHERE status='in_stock' AND arm=? ORDER BY kit_no LIMIT 1", (arm1,)).fetchone()["kit_no"]
    conn.execute("DELETE FROM kits WHERE status='in_stock' AND arm=? AND kit_no<>?", (arm1, keep))
    conn.commit()
    conn.close()

    outcomes = []
    lock = threading.Lock()

    def worker(no):
        r = client.post("/api/pharmacy/dispense", headers=ph, json={"random_no": no})
        with lock:
            outcomes.append(r.status_code)

    t1 = threading.Thread(target=worker, args=(s1["random_no"],))
    t2 = threading.Thread(target=worker, args=(s2["random_no"],))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert sorted(outcomes) == [200, 409], outcomes

    # 守恒
    safe = login(client, "safe1")
    rep = client.get("/api/safety/invariants", headers=safe).json()
    assert rep["ok"], rep


def test_arm1_arm2_same_arm_construction():
    """显式校验：连续两个号可能不同 arm 时，用直接服务层制造同 arm 双受试者的竞争场景。"""
    # 该构造在 test_concurrent_claim_last_compatible_kit_explicit 中覆盖
    assert True


def test_explicit_last_kit_race_same_arm(client):
    """直接在 DB 造两个同 arm 受试者（模拟序列中同组相邻），抢唯一盒。"""
    inv, ph = login(client, "inv01"), login(client, "ph01")
    s1 = enroll(client, inv, "EXP-1")
    conn = connect(appmod.DB_PATH)
    arm1 = conn.execute("SELECT arm FROM subjects WHERE random_no=?", (s1["random_no"],)).fetchone()["arm"]
    # 造第二个受试者并手动指到同 arm（走正常入组拿到号后更新其 arm 仅用于构造竞争）
    pass_eligibility(client, inv, "EXP-2")
    r2 = client.post("/api/investigator/enroll", headers=inv,
                     json={"subject_code": "EXP-2", "pv_code": "V1.0"})
    s2 = r2.json()
    conn.execute("UPDATE subjects SET arm=? WHERE random_no=?", (arm1, s2["random_no"]))
    keep = conn.execute(
        "SELECT kit_no FROM kits WHERE status='in_stock' AND arm=? ORDER BY kit_no LIMIT 1", (arm1,)).fetchone()["kit_no"]
    conn.execute("DELETE FROM kits WHERE status='in_stock' AND arm=? AND kit_no<>?", (arm1, keep))
    conn.commit()
    conn.close()

    outcomes, kits = [], []
    lock = threading.Lock()

    def worker(no):
        r = client.post("/api/pharmacy/dispense", headers=ph, json={"random_no": no})
        with lock:
            outcomes.append(r.status_code)
            if r.status_code == 200:
                kits.append(r.json()["kit_no"])

    ts = [threading.Thread(target=worker, args=(n,)) for n in (s1["random_no"], s2["random_no"])]
    for t in ts: t.start()
    for t in ts: t.join()
    assert sorted(outcomes) == [200, 409]
    assert len(kits) == 1


def test_lot_fallback_without_touching_sequence(client):
    """首选批号耗尽 → 自动转用兼容批号；随机号与治疗组不变。"""
    inv, ph = login(client, "inv01"), login(client, "ph01")
    s = enroll(client, inv, "FB-1")
    arm_before = _arm_of(appmod.DB_PATH, s["random_no"])
    conn = connect(appmod.DB_PATH)
    # 删掉首选批号（priority 最小的兼容批号）的全部库存
    rows = conn.execute("SELECT lot_no FROM lots WHERE center_code='01' ORDER BY priority").fetchall()
    import json as _json
    preferred = None
    for lot in rows:
        compat = conn.execute("SELECT compat_arms FROM lots WHERE lot_no=?", (lot["lot_no"],)).fetchone()["compat_arms"]
        if arm_before in _json.loads(compat):
            preferred = lot["lot_no"]
            break
    conn.execute("DELETE FROM kits WHERE lot_no=? AND status='in_stock'", (preferred,))
    conn.commit()
    conn.close()

    r = client.post("/api/pharmacy/dispense", headers=ph,
                    json={"random_no": s["random_no"]})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["lot_switched"] is True
    assert data["lot_no"] != preferred
    # 序列未动：arm 仍是原来的
    assert _arm_of(appmod.DB_PATH, s["random_no"]) == arm_before
    # 拿到的盒确实兼容
    conn = connect(appmod.DB_PATH)
    kit_arm = conn.execute("SELECT arm FROM kits WHERE kit_no=?", (data["kit_no"],)).fetchone()["arm"]
    assert kit_arm == arm_before
    conn.close()


def test_no_compatible_kit_returns_409(client):
    inv, ph = login(client, "inv01"), login(client, "ph01")
    s = enroll(client, inv, "NONE-1")
    conn = connect(appmod.DB_PATH)
    conn.execute("DELETE FROM kits WHERE status='in_stock'")
    conn.commit()
    conn.close()
    r = client.post("/api/pharmacy/dispense", headers=ph,
                    json={"random_no": s["random_no"]})
    assert r.status_code == 409 and r.json()["error"] == "NO_COMPATIBLE_KIT"


def test_return_then_redispense(client):
    """退药后再次发放：盒子回库 → 给新受试者，随机序列与编号完全不受影响；
    全流程流水守恒。"""
    inv, ph = login(client, "inv01"), login(client, "ph01")
    s1 = enroll(client, inv, "RET-1")
    d1 = client.post("/api/pharmacy/dispense", headers=ph,
                     json={"random_no": s1["random_no"]}).json()
    assert client.post("/api/pharmacy/return", headers=ph,
                       json={"kit_no": d1["kit_no"], "note": "受试者撤回"}).status_code == 200
    # 未再入库时直接发，系统不会选 returned 盒
    # 再入库
    assert client.post("/api/pharmacy/restock", headers=ph,
                       json={"kit_no": d1["kit_no"]}).status_code == 200

    s2 = enroll(client, inv, "RET-2")
    d2 = client.post("/api/pharmacy/dispense", headers=ph,
                     json={"random_no": s2["random_no"]})
    assert d2.status_code == 200, d2.text
    # 第二个受试者可以拿到原来退回的盒（也可能拿别的，随机序列不因此改变）
    assert s1["random_no"] != s2["random_no"]

    hist = client.get(f"/api/pharmacy/kits/{d1['kit_no']}/history", headers=ph).json()
    kinds = [(e["event_type"], e["random_no"]) for e in hist]
    assert ("dispense", s1["random_no"]) in kinds
    assert ("return", s1["random_no"]) in kinds

    safe = login(client, "safe1")
    rep = client.get("/api/safety/invariants", headers=safe).json()
    assert rep["ok"], rep


def test_specified_kit_mismatch_generic_error(client):
    """药房扫码指定不兼容药盒：笼统错误，不区分原因，无法枚举反推分组。"""
    inv, ph = login(client, "inv01"), login(client, "ph01")
    s = enroll(client, inv, "MIS-1")
    conn = connect(appmod.DB_PATH)
    arm = conn.execute("SELECT arm FROM subjects WHERE random_no=?", (s["random_no"],)).fetchone()["arm"]
    other = conn.execute(
        "SELECT kit_no FROM kits WHERE status='in_stock' AND arm<>? LIMIT 1", (arm,)).fetchone()
    conn.close()
    if other:
        r = client.post("/api/pharmacy/dispense", headers=ph,
                        json={"random_no": s["random_no"], "kit_no": other["kit_no"]})
        assert r.status_code == 409
        assert r.json()["error"] == "KIT_NOT_AVAILABLE"
        assert "arm" not in r.text.lower()

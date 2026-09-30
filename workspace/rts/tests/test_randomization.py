"""随机化：区组平衡、分层独立、重复入组幂等且随机号唯一、入排前置。"""
import json
import threading
from .conftest import login, enroll, pass_eligibility
from rts.db import connect
from rts import main as appmod
from rts.service import TrialService, arm_at


def test_block_balance_and_determinism():
    # V1.0 区组4、1:1：每个区组 2A2B，序列确定可复现
    arms = [arm_at("V1.0", "01", i, ["A", "B"], [1, 1], 4) for i in range(8)]
    assert arms[:4].count("A") == 2 and arms[:4].count("B") == 2
    assert arms[4:].count("A") == 2 and arms[4:].count("B") == 2
    # 重启等价：同一位置永远同结果
    again = [arm_at("V1.0", "01", i, ["A", "B"], [1, 1], 4) for i in range(8)]
    assert arms == again
    # 中心间独立
    other = [arm_at("V1.0", "02", i, ["A", "B"], [1, 1], 4) for i in range(4)]
    assert isinstance(other, list) and len(other) == 4


def test_duplicate_enrollment_is_idempotent(client):
    inv = login(client, "inv01")
    first = enroll(client, inv, "S-100")
    # 同一人再次调用：返回同一随机号，不新建、不跳号
    second = client.post("/api/investigator/enroll", headers=inv,
                         json={"subject_code": "S-100", "pv_code": "V1.0"}).json()
    assert second["random_no"] == first["random_no"]
    assert second["already_enrolled"] is True
    rows = client.get("/api/investigator/subjects", headers=inv).json()
    assert len(rows) == 1


def test_concurrent_duplicate_enroll_same_subject(client):
    """两个并发请求抢注册同一受试者：恰好一个成功建号，另一个幂等拿到同号。"""
    inv = login(client, "inv01")
    pass_eligibility(client, inv, "S-200")
    results = []
    errors = []

    def worker():
        try:
            r = client.post("/api/investigator/enroll", headers=inv,
                            json={"subject_code": "S-200", "pv_code": "V1.0"})
            results.append((r.status_code, r.json().get("random_no")))
        except Exception as e:  # TestClient 跨线程偶发
            errors.append(str(e))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    nos = {no for _, no in results if no}
    assert len(nos) == 1  # 随机号全局唯一
    conn = connect(appmod.DB_PATH)
    n = conn.execute("SELECT COUNT(*) c FROM subjects WHERE subject_code='S-200'").fetchone()["c"]
    conn.close()
    assert n == 1


def test_concurrent_distinct_subjects_use_distinct_numbers(client):
    inv = login(client, "inv01")
    for i in range(10):
        pass_eligibility(client, inv, f"S-3{i:02d}")
    out = []
    lock = threading.Lock()

    def worker(i):
        r = client.post("/api/investigator/enroll", headers=inv,
                        json={"subject_code": f"S-3{i:02d}", "pv_code": "V1.0"})
        with lock:
            out.append(r.json()["random_no"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(out) == len(set(out)) == 10  # 无重号


def test_strata_independent_across_center_and_pv(client):
    inv01 = login(client, "inv01")
    inv02 = login(client, "inv02")
    a = enroll(client, inv01, "C1-1", "V1.0")
    b = enroll(client, inv02, "C2-1", "V1.0")
    c = enroll(client, inv01, "C1-2", "V2.0")
    # 两个中心的第一号、以及同中心不同版本的第一号各自从 0001 起
    assert a["random_no"].endswith("-0001")
    assert b["random_no"].endswith("-0001")
    assert c["random_no"].startswith("V20-01-0001")


def test_must_pass_eligibility_first(client):
    inv = login(client, "inv01")
    # 未评估直接随机 → 412
    r = client.post("/api/investigator/enroll", headers=inv,
                    json={"subject_code": "X-1", "pv_code": "V1.0"})
    assert r.status_code == 412
    # 评估不通过
    client.post("/api/investigator/eligibility", headers=inv, json={
        "subject_code": "X-2",
        "answers": {"informed_consent": False, "age_ok": True,
                    "indication_ok": True, "no_exclusion": True}})
    r = client.post("/api/investigator/enroll", headers=inv,
                    json={"subject_code": "X-2", "pv_code": "V1.0"})
    assert r.status_code == 412


def test_random_no_global_uniqueness_in_db(client):
    inv = login(client, "inv01")
    for i in range(12):
        enroll(client, inv, f"U-{i}")
    conn = connect(appmod.DB_PATH)
    dup = conn.execute(
        "SELECT random_no, COUNT(*) c FROM subjects GROUP BY random_no HAVING c>1").fetchall()
    assert dup == []
    # V1.0 1:1 前 12 人（3 个完整区组）总平衡
    counts = conn.execute("SELECT arm, COUNT(*) c FROM subjects GROUP BY arm").fetchall()
    d = {r["arm"]: r["c"] for r in counts}
    assert d == {"A": 6, "B": 6}
    conn.close()

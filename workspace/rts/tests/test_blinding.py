"""盲态边界：研究者/药房任何接口都不能看到治疗组；
应急揭盲只给单个受试者；批号兼容关系不泄露分组。"""
from .conftest import login, enroll, pass_eligibility


def test_subject_view_never_contains_arm(client):
    inv = login(client, "inv01")
    info = enroll(client, inv, "S-001")
    assert "arm" not in info and "A" not in str(info.get("random_no"))
    listing = client.get("/api/investigator/subjects", headers=inv).json()
    assert all("arm" not in row for row in listing)
    # 原始文本也不得出现裸分组值泄露（审计/明细）
    r = client.get("/api/investigator/subjects", headers=inv).text
    assert '"arm"' not in r


def test_pharmacy_cannot_see_arm_or_compat(client):
    inv = login(client, "inv01")
    ph = login(client, "ph01")
    info = enroll(client, inv, "S-001")
    r = client.get("/api/pharmacy/kits", headers=ph)
    body = r.text
    assert '"arm"' not in body and "compat" not in body
    # 发药响应也不含 arm
    d = client.post("/api/pharmacy/dispense", headers=ph,
                    json={"random_no": info["random_no"]})
    assert d.status_code == 200
    assert "arm" not in d.json()


def test_role_isolation(client):
    inv = login(client, "inv01")
    ph = login(client, "ph01")
    safe = login(client, "safe1")
    # 研究者不能调药房/安全接口
    assert client.get("/api/pharmacy/kits", headers=inv).status_code == 403
    assert client.get("/api/safety/status", headers=inv).status_code == 403
    # 药房不能入组、不能锁数据
    assert client.get("/api/investigator/subjects", headers=ph).status_code == 403
    assert client.post("/api/safety/data-lock", headers=ph).status_code == 403
    # 安全管理员不能入组/发药
    assert client.get("/api/pharmacy/kits", headers=safe).status_code == 403
    assert client.get("/api/investigator/subjects", headers=safe).status_code == 403


def test_cross_center_forbidden(client):
    inv01 = login(client, "inv01")
    inv02 = login(client, "inv02")
    ph02 = login(client, "ph02")
    info = enroll(client, inv01, "S-001")
    # 上海研究者看不到北京受试者
    assert client.get("/api/investigator/subjects", headers=inv02).json() == []
    # 上海药房不能给北京随机号发药
    r = client.post("/api/pharmacy/dispense", headers=ph02,
                    json={"random_no": info["random_no"]})
    assert r.status_code == 403


def test_emergency_unblind_single_subject_only(client):
    inv = login(client, "inv01")
    i1 = enroll(client, inv, "S-001")
    i2 = enroll(client, inv, "S-002")
    # 原因必填
    r = client.post(f"/api/investigator/emergency-unblind/{i1['random_no']}",
                    headers=inv, json={"reason": ""})
    assert r.status_code == 422
    r = client.post(f"/api/investigator/emergency-unblind/{i1['random_no']}",
                    headers=inv, json={"reason": "SAE 急救需知道用药"})
    assert r.status_code == 200
    data = r.json()
    assert data["scope"] == "single_subject"
    assert data["subject_code"] == "S-001"
    assert data["arm"] in ("A", "B")
    # 响应里绝不能出现另一个人的随机号或分组
    assert i2["random_no"] not in r.text
    # 列表接口同样不含 arm
    safe = login(client, "safe1")
    lst = client.get("/api/safety/emergency-list", headers=safe).json()
    assert len(lst) == 1 and all("arm" not in e for e in lst)

"""批次召回与替换发放闭环测试。

覆盖：发布冻结与范围快照、回收/豁免/凭证/核销状态机、同一对象单次替换、
并发核销幂等、重复回收幂等、关闭/撤销规则、冻结库存不误恢复、
非法跳转统一冲突、盲态边界（响应/列表/审计零 arm）、重连后继续流程。
"""
import json
import threading

import pytest

from rts import main as appmod
from rts.db import connect
from rts.service import TrialService

from .conftest import login, enroll


# ------------------------------------------------------------------ 小工具
def _dispense(client, ph, random_no):
    r = client.post("/api/pharmacy/dispense", headers=ph, json={"random_no": random_no})
    assert r.status_code == 200, r.text
    return r.json()


def _create_recall(client, safe, lot_nos, reason="效价不合格"):
    r = client.post("/api/safety/recalls", headers=safe,
                    json={"lot_nos": lot_nos, "reason": reason})
    assert r.status_code == 200, r.text
    return r.json()


def _pharm_items(client, ph):
    r = client.get("/api/pharmacy/recall-items", headers=ph)
    assert r.status_code == 200, r.text
    return r.json()


def _item_of(client, ph, random_no):
    items = [it for it in _pharm_items(client, ph) if it["random_no"] == random_no]
    assert len(items) == 1, items
    return items[0]


def _recover(client, ph, item):
    r = client.post(f"/api/pharmacy/recall-items/{item['item_id']}/recover",
                    headers=ph, json={"kit_no": item["kit_no"]})
    assert r.status_code == 200, r.text
    return r.json()


def _voucher(client, ph, item_id):
    r = client.post(f"/api/pharmacy/recall-items/{item_id}/voucher", headers=ph)
    assert r.status_code == 200, r.text
    return r.json()


def _redeem(client, ph, voucher_no):
    r = client.post("/api/pharmacy/recall-vouchers/redeem",
                    headers=ph, json={"voucher_no": voucher_no})
    assert r.status_code == 200, r.text
    return r.json()


def _invariants_ok(client, safe):
    rep = client.get("/api/safety/invariants", headers=safe).json()
    assert rep["ok"], rep


def _kit_row(db_path, kit_no):
    conn = connect(db_path)
    row = conn.execute(
        "SELECT status, holder_subject_id, frozen, lot_no FROM kits WHERE kit_no=?",
        (kit_no,)).fetchone()
    conn.close()
    return row


# ------------------------------------------------------------------ 发布与快照
def test_publish_freezes_stock_and_snapshots_scope(client):
    """发布召回单：未领用库存立即冻结、已领用对象进入待处理；
    之后补录进该批号的盒不混入本单快照。"""
    inv, ph, safe = login(client, "inv01"), login(client, "ph01"), login(client, "safe1")
    s = enroll(client, inv, "RC-A1")
    d = _dispense(client, ph, s["random_no"])
    recalled_lot = d["lot_no"]

    r = _create_recall(client, safe, [recalled_lot])
    assert r["status"] == "active" and r["recall_no"].startswith("RC-")
    assert r["item_counts"]["pending"] == 1
    assert r["item_counts"]["frozen_stock"] >= 1

    # 库存被冻结：自动发药不能再拿到该批号的盒子
    s2 = enroll(client, inv, "RC-A2")
    d2 = _dispense(client, ph, s2["random_no"])
    assert d2["lot_no"] != recalled_lot

    # 可领取列表不再出现该批号
    avail = client.get("/api/pharmacy/kits", headers=ph).json()
    assert all(k["lot_no"] != recalled_lot for k in avail["kits"])

    # 手工指定被冻结盒 → 与"不存在/已发"同一笼统错误
    frozen_kit = _kit_row(appmod.DB_PATH, d["kit_no"])
    assert frozen_kit is not None
    conn = connect(appmod.DB_PATH)
    any_frozen = conn.execute(
        "SELECT kit_no FROM kits WHERE lot_no=? AND frozen=1 LIMIT 1",
        (recalled_lot,)).fetchone()
    conn.close()
    s3 = enroll(client, inv, "RC-A3")
    r3 = client.post("/api/pharmacy/dispense", headers=ph,
                     json={"random_no": s3["random_no"], "kit_no": any_frozen["kit_no"]})
    assert r3.status_code == 409 and r3.json()["error"] == "KIT_NOT_AVAILABLE"

    # 快照固化：发布后补录的盒不进本单
    before = sum(r["item_counts"].values())
    client.post("/api/safety/kits", headers=safe,
                json={"lot_no": recalled_lot, "count": 2})
    detail = client.get(f"/api/safety/recalls/{r['id']}", headers=safe).json()
    assert len(detail["items"]) == before
    # 但补录的盒同样受召回批号拦截，不能被发出
    s4 = enroll(client, inv, "RC-A4")
    d4 = _dispense(client, ph, s4["random_no"])
    assert d4["lot_no"] != recalled_lot
    _invariants_ok(client, safe)


def test_same_lot_cannot_be_recalled_twice(client):
    safe = login(client, "safe1")
    _create_recall(client, safe, ["L9001"])
    r = client.post("/api/safety/recalls", headers=safe,
                    json={"lot_nos": ["L9001"], "reason": "重复"})
    assert r.status_code == 409 and r.json()["error"] == "LOT_ALREADY_RECALLED"


# ------------------------------------------------------------------ 回收→凭证→核销
def test_full_recover_voucher_redeem_cycle(client):
    """完整闭环：待处理→已回收→可替换→已核销；替换包装来自未被召回批次；
    研究端只见是否需联系与阶段；关闭后结束。"""
    inv, ph, safe = login(client, "inv01"), login(client, "ph01"), login(client, "safe1")
    s = enroll(client, inv, "RC-B1")
    d = _dispense(client, ph, s["random_no"])
    recalled_lot = d["lot_no"]
    rec = _create_recall(client, safe, [recalled_lot])

    # 研究端：需要联系 + 待处理
    notices = client.get("/api/investigator/recall-notices", headers=inv).json()
    n = [x for x in notices if x["random_no"] == s["random_no"]][0]
    assert n["needs_contact"] is True and n["stage"] == "待处理"

    # 未扫码回收前不能签发凭证（非法跳转 → 统一冲突）
    item = _item_of(client, ph, s["random_no"])
    r = client.post(f"/api/pharmacy/recall-items/{item['item_id']}/voucher", headers=ph)
    assert r.status_code == 409 and r.json()["error"] == "RECALL_STATE_CONFLICT"

    # 扫错盒码 → 拒绝
    r = client.post(f"/api/pharmacy/recall-items/{item['item_id']}/recover",
                    headers=ph, json={"kit_no": "L9001-0001"})
    assert r.status_code == 409 and r.json()["error"] == "RECALL_KIT_MISMATCH"

    # 扫码回收 → 已回收；原盒冻结隔离
    item = _recover(client, ph, item)
    assert item["state"] == "recovered"
    k = _kit_row(appmod.DB_PATH, d["kit_no"])
    assert k["status"] == "returned" and k["frozen"] == 1 and k["holder_subject_id"] is None

    # 重复回收：幂等，不重复记流水
    again = _recover(client, ph, item)
    assert again["state"] == "recovered"
    hist = client.get(f"/api/pharmacy/kits/{d['kit_no']}/history", headers=ph).json()
    assert sum(1 for e in hist if e["event_type"] == "return") == 1

    # 签发一次性凭证 → 可替换；重复签发返回同一张
    v1 = _voucher(client, ph, item["item_id"])
    v2 = _voucher(client, ph, item["item_id"])
    assert v1["voucher_no"] == v2["voucher_no"] and v1["state"] == "replaceable"

    # 核销 → 替换包装来自未被召回批次
    rc = _redeem(client, ph, v1["voucher_no"])
    assert rc["status"] == "redeemed" and rc["kit_no"]
    new_kit = _kit_row(appmod.DB_PATH, rc["kit_no"])
    assert new_kit["lot_no"] != recalled_lot
    assert new_kit["status"] == "dispensed"

    # 重复核销：幂等同一回执，绝不双重发放
    rc2 = _redeem(client, ph, v1["voucher_no"])
    assert rc2["kit_no"] == rc["kit_no"] and rc2["already_redeemed"] is True
    conn = connect(appmod.DB_PATH)
    held = conn.execute(
        """SELECT COUNT(*) n FROM kits k JOIN subjects s ON s.id=k.holder_subject_id
           WHERE s.random_no=? AND k.status='dispensed'""", (s["random_no"],)).fetchone()["n"]
    conn.close()
    assert held == 1

    # 研究端：无需再联系，阶段已核销
    notices = client.get("/api/investigator/recall-notices", headers=inv).json()
    n = [x for x in notices if x["random_no"] == s["random_no"]][0]
    assert n["needs_contact"] is False and n["stage"] == "已核销"

    # 全部未决项清空后可关闭；重复关闭幂等
    closed = client.post(f"/api/safety/recalls/{rec['id']}/close", headers=safe)
    assert closed.status_code == 200 and closed.json()["status"] == "closed"
    again = client.post(f"/api/safety/recalls/{rec['id']}/close", headers=safe)
    assert again.status_code == 200 and again.json()["status"] == "closed"
    # 关闭后不可撤销
    r = client.post(f"/api/safety/recalls/{rec['id']}/revoke",
                    headers=safe, json={"reason": "x"})
    assert r.status_code == 409 and r.json()["error"] == "RECALL_STATE_CONFLICT"
    _invariants_ok(client, safe)


def test_close_blocked_until_open_items_cleared(client):
    inv, ph, safe = login(client, "inv01"), login(client, "ph01"), login(client, "safe1")
    s = enroll(client, inv, "RC-C1")
    d = _dispense(client, ph, s["random_no"])
    rec = _create_recall(client, safe, [d["lot_no"]])
    r = client.post(f"/api/safety/recalls/{rec['id']}/close", headers=safe)
    assert r.status_code == 409 and r.json()["error"] == "RECALL_OPEN_ITEMS"
    # 处置完成后可关
    item = _recover(client, ph, _item_of(client, ph, s["random_no"]))
    v = _voucher(client, ph, item["item_id"])
    _redeem(client, ph, v["voucher_no"])
    r = client.post(f"/api/safety/recalls/{rec['id']}/close", headers=safe)
    assert r.status_code == 200 and r.json()["open_items"] == 0


# ------------------------------------------------------------------ 豁免支路
def test_exemption_approve_issues_voucher_and_reject_returns_pending(client):
    inv, ph, safe = login(client, "inv01"), login(client, "ph01"), login(client, "safe1")
    s1 = enroll(client, inv, "RC-D1")
    s2 = enroll(client, inv, "RC-D2")
    d1 = _dispense(client, ph, s1["random_no"])
    d2 = _dispense(client, ph, s2["random_no"])
    lots = sorted({d1["lot_no"], d2["lot_no"]})
    rec = _create_recall(client, safe, lots)

    # 登记豁免（缺原因 → 422）
    it1 = _item_of(client, ph, s1["random_no"])
    r = client.post(f"/api/pharmacy/recall-items/{it1['item_id']}/exempt",
                    headers=ph, json={"reason": " "})
    assert r.status_code == 422
    r = client.post(f"/api/pharmacy/recall-items/{it1['item_id']}/exempt",
                    headers=ph, json={"reason": "无替代疗程，获益大于风险"})
    assert r.status_code == 200 and r.json()["state"] == "exempt_pending"
    # 重复登记幂等
    r = client.post(f"/api/pharmacy/recall-items/{it1['item_id']}/exempt",
                    headers=ph, json={"reason": "无替代疗程，获益大于风险"})
    assert r.status_code == 200 and r.json()["state"] == "exempt_pending"
    # 豁免待复核时不允许扫码回收（非法跳转统一冲突）
    r = client.post(f"/api/pharmacy/recall-items/{it1['item_id']}/recover",
                    headers=ph, json={"kit_no": it1["kit_no"]})
    assert r.status_code == 409 and r.json()["error"] == "RECALL_STATE_CONFLICT"

    # 风险控制批准豁免 → 可替换且凭证已签发
    r = client.post(f"/api/safety/recall-items/{it1['item_id']}/review-exemption",
                    headers=safe, json={"approve": True})
    assert r.status_code == 200 and r.json()["state"] == "replaceable"
    voucher_no = r.json()["voucher_no"]
    assert voucher_no
    # 重复复核 → 统一冲突
    r = client.post(f"/api/safety/recall-items/{it1['item_id']}/review-exemption",
                    headers=safe, json={"approve": True})
    assert r.status_code == 409 and r.json()["error"] == "RECALL_STATE_CONFLICT"

    # 豁免路径下对象仍持有旧盒：核销被挡，须先回收旧盒
    r = client.post("/api/pharmacy/recall-vouchers/redeem",
                    headers=ph, json={"voucher_no": voucher_no})
    assert r.status_code == 409 and r.json()["error"] == "SUBJECT_HOLDS_KIT"
    _recover(client, ph, {"item_id": it1["item_id"], "kit_no": it1["kit_no"]})
    # 回收后旧凭证依然有效，可核销
    rc = _redeem(client, ph, voucher_no)
    assert rc["status"] == "redeemed"

    # 第二个对象：豁免被驳回 → 回到待处理 → 走正常回收
    it2 = _item_of(client, ph, s2["random_no"])
    client.post(f"/api/pharmacy/recall-items/{it2['item_id']}/exempt",
                headers=ph, json={"reason": "试试看"})
    r = client.post(f"/api/safety/recall-items/{it2['item_id']}/review-exemption",
                    headers=safe, json={"approve": False})
    assert r.status_code == 200 and r.json()["state"] == "pending"
    it2 = _recover(client, ph, _item_of(client, ph, s2["random_no"]))
    v2 = _voucher(client, ph, it2["item_id"])
    _redeem(client, ph, v2["voucher_no"])

    r = client.post(f"/api/safety/recalls/{rec['id']}/close", headers=safe)
    assert r.status_code == 200 and r.json()["status"] == "closed"
    _invariants_ok(client, safe)


# ------------------------------------------------------------------ 并发核销
def test_concurrent_redeem_same_voucher_single_dispense(client):
    """两个配药站会话同时核销同一凭证：只有一笔发放，双方得到同一稳定回执。"""
    inv, safe = login(client, "inv01"), login(client, "safe1")
    ph_a, ph_b = login(client, "ph01"), login(client, "ph01")  # 两个并发会话
    s = enroll(client, inv, "RC-E1")
    d = _dispense(client, ph_a, s["random_no"])
    _create_recall(client, safe, [d["lot_no"]])
    item = _recover(client, ph_a, _item_of(client, ph_a, s["random_no"]))
    v = _voucher(client, ph_a, item["item_id"])

    outcomes, lock = [], threading.Lock()

    def worker(h):
        r = client.post("/api/pharmacy/recall-vouchers/redeem",
                        headers=h, json={"voucher_no": v["voucher_no"]})
        with lock:
            outcomes.append((r.status_code, r.json()))

    ts = [threading.Thread(target=worker, args=(h,)) for h in (ph_a, ph_b)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert all(code == 200 for code, _ in outcomes), outcomes
    kits = {body["kit_no"] for _, body in outcomes}
    assert len(kits) == 1  # 双方看到同一盒：绝无双重发放
    # 流水只有一笔替换发放
    conn = connect(appmod.DB_PATH)
    n = conn.execute(
        "SELECT COUNT(*) n FROM kit_events WHERE note='召回替换发放'").fetchone()["n"]
    vrow = conn.execute("SELECT status FROM replacement_vouchers WHERE voucher_no=?",
                        (v["voucher_no"],)).fetchone()
    conn.close()
    assert n == 1 and vrow["status"] == "redeemed"
    _invariants_ok(client, safe)


# ------------------------------------------------------------------ 撤销与冻结恢复
def test_revoke_voids_pending_but_keeps_stock_frozen(client):
    """未发生替换的召回可带原因撤销：未决项与凭证作废；
    冻结库存不自动恢复，需安全管理员逐盒解冻；撤销/关闭/重复操作幂等稳定。"""
    inv, ph, safe = login(client, "inv01"), login(client, "ph01"), login(client, "safe1")
    s = enroll(client, inv, "RC-F1")
    d = _dispense(client, ph, s["random_no"])
    rec = _create_recall(client, safe, [d["lot_no"]])
    item = _recover(client, ph, _item_of(client, ph, s["random_no"]))
    v = _voucher(client, ph, item["item_id"])

    # 缺原因 → 422
    r = client.post(f"/api/safety/recalls/{rec['id']}/revoke", headers=safe, json={"reason": ""})
    assert r.status_code == 422
    # 撤销
    r = client.post(f"/api/safety/recalls/{rec['id']}/revoke",
                    headers=safe, json={"reason": "误发，检验复核合格"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    # 重复撤销幂等
    r = client.post(f"/api/safety/recalls/{rec['id']}/revoke",
                    headers=safe, json={"reason": "再次"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    # 撤销后不能关闭
    r = client.post(f"/api/safety/recalls/{rec['id']}/close", headers=safe)
    assert r.status_code == 409 and r.json()["error"] == "RECALL_STATE_CONFLICT"
    # 凭证已作废
    r = client.post("/api/pharmacy/recall-vouchers/redeem",
                    headers=ph, json={"voucher_no": v["voucher_no"]})
    assert r.status_code == 409 and r.json()["error"] == "VOUCHER_VOID"
    # 配药端不再显示作废项
    assert _pharm_items(client, ph) == []

    # 冻结库存未误恢复
    conn = connect(appmod.DB_PATH)
    frozen = conn.execute(
        """SELECT k.kit_no FROM kits k JOIN recall_items ri ON ri.kit_no=k.kit_no
           WHERE ri.recall_id=? AND ri.state='frozen_stock' AND k.frozen=1""",
        (rec["id"],)).fetchall()
    assert frozen, "冻结库存在撤销后必须保持冻结"
    frozen_kit = frozen[0]["kit_no"]
    conn.close()
    # 安全管理员逐盒质检解冻后可再次发放
    r = client.post("/api/safety/recalls/unfreeze", headers=safe, json={"kit_no": frozen_kit})
    assert r.status_code == 200 and r.json()["frozen"] is False
    s2 = enroll(client, inv, "RC-F2")
    # 测试构造：把新受试者指到与解冻盒相同的组（沿用 test_kits 的构造方式）
    conn = connect(appmod.DB_PATH)
    kit_arm = conn.execute("SELECT arm FROM kits WHERE kit_no=?", (frozen_kit,)).fetchone()["arm"]
    conn.execute("UPDATE subjects SET arm=? WHERE random_no=?", (kit_arm, s2["random_no"]))
    conn.commit()
    conn.close()
    d2 = client.post("/api/pharmacy/dispense", headers=ph,
                     json={"random_no": s2["random_no"], "kit_no": frozen_kit})
    assert d2.status_code == 200
    _invariants_ok(client, safe)


def test_redeemed_recall_cannot_be_revoked_only_closed(client):
    inv, ph, safe = login(client, "inv01"), login(client, "ph01"), login(client, "safe1")
    s = enroll(client, inv, "RC-G1")
    d = _dispense(client, ph, s["random_no"])
    rec = _create_recall(client, safe, [d["lot_no"]])
    item = _recover(client, ph, _item_of(client, ph, s["random_no"]))
    v = _voucher(client, ph, item["item_id"])
    _redeem(client, ph, v["voucher_no"])
    r = client.post(f"/api/safety/recalls/{rec['id']}/revoke",
                    headers=safe, json={"reason": "想撤销"})
    assert r.status_code == 409 and r.json()["error"] == "RECALL_HAS_REDEEMED"
    r = client.post(f"/api/safety/recalls/{rec['id']}/close", headers=safe)
    assert r.status_code == 200 and r.json()["status"] == "closed"


# ------------------------------------------------------------------ 隔离与盲态
def test_cross_center_isolation_and_role_guard(client):
    inv2, ph1, ph2 = login(client, "inv02"), login(client, "ph01"), login(client, "ph02")
    safe = login(client, "safe1")
    s = enroll(client, inv2, "RC-H1", pv="V1.0")
    d = _dispense(client, ph2, s["random_no"])
    _create_recall(client, safe, [d["lot_no"]])
    # ph01 看不到中心 02 的处置项
    assert _pharm_items(client, ph1) == []
    item = _item_of(client, ph2, s["random_no"])
    # ph01 越权操作中心 02 的项 → 404（不泄露存在性）
    r = client.post(f"/api/pharmacy/recall-items/{item['item_id']}/recover",
                    headers=ph1, json={"kit_no": item["kit_no"]})
    assert r.status_code == 404
    # 非授权角色一律被拒
    inv1 = login(client, "inv01")
    assert client.get("/api/safety/recalls", headers=inv1).status_code == 403
    assert client.get("/api/pharmacy/recall-items", headers=inv1).status_code == 403
    assert client.get("/api/investigator/recall-notices", headers=ph1).status_code == 403


def test_no_arm_leak_in_recall_surfaces(client):
    """召回相关的响应、列表与审计都不得暴露分配臂。"""
    inv, ph, safe = login(client, "inv01"), login(client, "ph01"), login(client, "safe1")
    s1 = enroll(client, inv, "RC-I1")
    s2 = enroll(client, inv, "RC-I2")
    d1 = _dispense(client, ph, s1["random_no"])
    d2 = _dispense(client, ph, s2["random_no"])
    rec = _create_recall(client, safe, sorted({d1["lot_no"], d2["lot_no"]}))
    it1 = _item_of(client, ph, s1["random_no"])
    client.post(f"/api/pharmacy/recall-items/{it1['item_id']}/exempt",
                headers=ph, json={"reason": "临床需要"})
    client.post(f"/api/safety/recall-items/{it1['item_id']}/review-exemption",
                headers=safe, json={"approve": True})
    item = _recover(client, ph, _item_of(client, ph, s2["random_no"]))
    v = _voucher(client, ph, item["item_id"])
    _redeem(client, ph, v["voucher_no"])

    blobs = []
    blobs += _pharm_items(client, ph)
    blobs += client.get("/api/investigator/recall-notices", headers=inv).json()
    blobs.append(client.get(f"/api/safety/recalls/{rec['id']}", headers=safe).json())
    blobs += client.get("/api/safety/recalls", headers=safe).json()
    text = json.dumps(blobs, ensure_ascii=False)
    assert '"arm"' not in text
    # 配药端连批号都看不到（只有中性盒码与随机编码）
    for it in _pharm_items(client, ph):
        assert "lot_no" not in it and "arm" not in it
    # 研究端只有是否联系 + 阶段
    for n in client.get("/api/investigator/recall-notices", headers=inv).json():
        assert set(n) == {"subject_code", "random_no", "needs_contact", "stage"}
    # 审计明细无 arm
    audit = client.get("/api/safety/audit?limit=500", headers=safe).json()
    recall_entries = [a for a in audit if a["action"].startswith("recall_")]
    assert recall_entries
    for a in recall_entries:
        assert '"arm"' not in a["detail"]
    _invariants_ok(client, safe)


# ------------------------------------------------------------------ 重启续作
def test_recall_flow_survives_reconnect(client):
    """模拟进程重启（全新服务连接）：发布→回收后重启，
    凭证签发、核销、关闭全部基于落盘状态继续推进。"""
    inv, ph, safe = login(client, "inv01"), login(client, "ph01"), login(client, "safe1")
    s = enroll(client, inv, "RC-J1")
    d = _dispense(client, ph, s["random_no"])
    rec = _create_recall(client, safe, [d["lot_no"]])
    item = _recover(client, ph, _item_of(client, ph, s["random_no"]))

    # “重启”：绕过 HTTP 层，用全新连接直接驱动服务层续作
    svc = TrialService(connect(appmod.DB_PATH))
    safe_token = _token_of("safe1")
    ph_token = _token_of("ph01")
    view = svc.issue_voucher(ph_token, item["item_id"])
    assert view["state"] == "replaceable" and view["voucher_no"]
    rc = svc.redeem_voucher(ph_token, view["voucher_no"])
    assert rc["status"] == "redeemed"
    closed = svc.close_recall(safe_token, rec["id"])
    assert closed["status"] == "closed" and closed["open_items"] == 0
    assert svc.check_invariants()["ok"]


def _token_of(username):
    conn = connect(appmod.DB_PATH)
    row = conn.execute(
        """SELECT s.token FROM sessions s JOIN users u ON u.id=s.user_id
           WHERE u.username=? ORDER BY s.created_at DESC LIMIT 1""",
        (username,)).fetchone()
    conn.close()
    return row["token"]

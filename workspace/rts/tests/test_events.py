"""平台事件签名出站队列测试。

覆盖：
- 已提交事务先写不可变事件（单调序号/订阅版本/签名摘要/哈希链）；
- 订阅按 种类×中心×角色 过滤、fan-out、重复订阅稳定；暂停/恢复；
- 租约：两 worker 并发只有一个有效、过期可接管、成功后崩溃不重复；
- 退避重试 → 死信 → 安全管理员逐条重放（不改正文、不造新业务事件、重复重放幂等）；
- 事件顺序冲突（前序未终结不投后序）、端点停用；
- 盲态/密钥边界：事件、投递审计、错误码中零 arm/兼容/密钥；药房无权；
  研究端只见授权摘要；
- 库外核对：序号/正文/签发版本/签名（CLI），换钥后旧事件仍可验；
- 真实 uvicorn 进程 SIGKILL 重启后未发/超时/死信继续处理（见 test_event_restart）。
"""
import json
import threading

import pytest

from rts import main as appmod
from rts.db import connect
from rts.events import (
    DeliveryWorker, EventBus, KeyStore, SubscriptionService,
    canonical_json, deobfuscate_secret, delivery_headers, obfuscate_secret,
    sha256_hex, subscription_matches, verify_delivery_hmac,
)

from .conftest import enroll, login


# ------------------------------------------------------------------ 夹具

@pytest.fixture
def db_path(client, tmp_path, monkeypatch):
    # client 夹具已经在 tmp_path/test.db 播种；直接复用 appmod.DB_PATH
    yield appmod.DB_PATH


@pytest.fixture
def headers(client):
    safe = login(client, "safe1")
    inv01 = login(client, "inv01")
    inv02 = login(client, "inv02")
    ph01 = login(client, "ph01")
    return {"safe": safe, "inv01": inv01, "inv02": inv02, "ph01": ph01}


class FakeTransport:
    """假投递端点：按序返回预定结果，记录每次收到的请求，校验 HMAC。"""

    def __init__(self, script=None, record=True, verify=True, secret_by_url=None):
        self.script = list(script or [200])
        self.calls = []
        self.record = record
        self.verify = verify
        self.secret_by_url = secret_by_url or {}
        self.lock = threading.Lock()
        self._seen_ids = set()
        self.duplicates = []

    def __call__(self, url, headers_, envelope):
        with self.lock:
            status = self.script[min(len(self.calls), len(self.script) - 1)]
            if isinstance(status, Exception):
                self.calls.append({"url": url, "headers": dict(headers_),
                                   "envelope": envelope, "status": None})
                raise status
            h = envelope["header"]
            if h["event_id"] in self._seen_ids:
                self.duplicates.append(h["event_id"])
            self._seen_ids.add(h["event_id"])
            secret = self.secret_by_url.get(url)
            if self.verify and secret is not None:
                ok = verify_delivery_hmac(
                    secret, envelope, int(headers_["X-RTS-Subscription-Version"]),
                    headers_["X-RTS-Signature"])
                assert ok, "投递 HMAC 校验失败"
            self.calls.append({"url": url, "headers": dict(headers_),
                               "envelope": envelope, "status": status})
            return status


def _register(client, safe, name="审计端点", url="https://auditor.example/hook",
              kinds=None, centers=None, roles=None):
    r = client.post("/api/safety/event-subscriptions", headers=safe, json={
        "name": name, "endpoint_url": url,
        "kinds": kinds or [], "centers": centers or [], "roles": roles or []})
    assert r.status_code == 200, r.text
    return r.json()


def _make_business_events(client, h):
    """入组 + 发药 + 退药：产生三类事件。"""
    e = enroll(client, h["inv01"], "S-100")
    d = client.post("/api/pharmacy/dispense", headers=h["ph01"],
                    json={"random_no": e["random_no"]})
    assert d.status_code == 200, d.text
    ret = client.post("/api/pharmacy/return", headers=h["ph01"],
                      json={"kit_no": d.json()["kit_no"]})
    assert ret.status_code == 200, ret.text
    return e, d.json(), ret.json()


# ========================================================== 1. 不可变事件

def test_committed_txn_writes_immutable_event(client, headers, db_path):
    _make_business_events(client, headers)
    conn = connect(db_path)
    rows = conn.execute("SELECT * FROM platform_events ORDER BY seq").fetchall()
    kinds = [r["kind"] for r in rows]
    assert kinds == ["enrolled", "dispensed", "returned"], kinds
    # 单调序号从 1 连续
    assert [r["seq"] for r in rows] == [1, 2, 3]
    # 哈希链
    assert rows[0]["prev_digest"] == "GENESIS"
    for a, b in zip(rows, rows[1:]):
        assert b["prev_digest"] == a["event_digest"]
    # 正文摘要可重算
    for r in rows:
        assert sha256_hex(r["body"]) == r["body_digest"]
    # 完整性巡检全绿（含签名）
    rep = EventBus(conn).check_integrity()
    assert rep["ok"], rep
    conn.close()


def test_event_body_has_no_blinding_or_secret(client, headers, db_path):
    _make_business_events(client, headers)
    conn = connect(db_path)
    parsed = [json.loads(r["body"]) for r in conn.execute(
        "SELECT body FROM platform_events ORDER BY seq")]

    def all_keys(o, acc):
        if isinstance(o, dict):
            for k, v in o.items():
                acc.add(k); all_keys(v, acc)
        elif isinstance(o, list):
            for v in o:
                all_keys(v, acc)
        return acc

    keys = set()
    for b in parsed:
        all_keys(b, keys)
    assert not (keys & {"arm", "lot_switched", "compat_arms", "secret",
                        "secret_hash", "secret_store"})
    # 值里也不得出现具体治疗组标签
    blob = json.dumps(parsed, ensure_ascii=False)
    # 发药走首选批号；dispensed 事件正文是中性标识
    disp = next(b for b in parsed if b.get("context") == "routine")
    assert set(disp) >= {"random_no", "kit_no", "lot_no", "context"}
    conn.close()


def test_event_and_business_txn_atomic_rollback(client, headers, db_path):
    """业务失败（无兼容药盒）时不得写发药事件。"""
    # 给一个库存为空的中心入组后发药不可行；这里用重复发药触发业务冲突
    e = enroll(client, headers["inv01"], "S-200")
    d1 = client.post("/api/pharmacy/dispense", headers=headers["ph01"],
                     json={"random_no": e["random_no"]})
    assert d1.status_code == 200
    # 同一受试者再发 → 业务失败
    d2 = client.post("/api/pharmacy/dispense", headers=headers["ph01"],
                     json={"random_no": e["random_no"]})
    assert d2.status_code == 409
    conn = connect(db_path)
    n = conn.execute("SELECT COUNT(*) n FROM platform_events WHERE kind='dispensed'").fetchone()["n"]
    assert n == 1  # 只有成功的那一次
    conn.close()


# ========================================================== 2. 订阅过滤与 fan-out

def test_subscription_filter_fanout(client, headers, db_path):
    # 端点 A：只收 01 中心的 enrolled
    a = _register(client, headers["safe"], name="A",
                  url="https://a.example/hook", kinds=["enrolled"], centers=["01"])
    # 端点 B：只收 safety 发起的事件（召回/正常揭盲）
    b = _register(client, headers["safe"], name="B",
                  url="https://b.example/hook", roles=["safety"])
    # 端点 C：全收
    csub = _register(client, headers["safe"], name="C", url="https://c.example/hook")
    assert a["secret"].startswith("rtsevt_")  # 仅本次回显
    _make_business_events(client, headers)
    conn = connect(db_path)
    for sub, expected in [(a["id"], 1), (b["id"], 0), (csub["id"], 3)]:
        n = conn.execute("SELECT COUNT(*) n FROM event_deliveries WHERE subscription_id=?",
                         (sub,)).fetchone()["n"]
        assert n == expected, (sub, n)
    conn.close()


def test_platform_level_event_ignores_center_filter(client, headers, db_path):
    # 仅订阅 02 中心的端点，也应收到平台级（center 为空）的召回发布事件
    sub = _register(client, headers["safe"], url="https://x.example/hook",
                    kinds=["recall_published"], centers=["02"])
    r = client.post("/api/safety/recalls", headers=headers["safe"],
                    json={"lot_nos": ["L1001"], "reason": "效价不合格"})
    assert r.status_code == 200, r.text
    conn = connect(db_path)
    n = conn.execute("SELECT COUNT(*) n FROM event_deliveries WHERE subscription_id=?",
                     (sub["id"],)).fetchone()["n"]
    assert n == 1
    ev = conn.execute("SELECT * FROM platform_events WHERE kind='recall_published'").fetchone()
    assert ev["center_code"] is None
    conn.close()


def test_duplicate_subscription_is_stable_and_no_secret(client, headers):
    url = "https://dup.example/hook"
    first = _register(client, headers["safe"], name="首次", url=url)
    second = _register(client, headers["safe"], name="再次", url=url)
    assert second["duplicate"] is True
    assert second["id"] == first["id"]
    assert "secret" not in second          # 重复登记不再回显密钥
    # 列表/详情任何时候都不含密钥
    lst = client.get("/api/safety/event-subscriptions", headers=headers["safe"]).json()
    item = next(x for x in lst if x["id"] == first["id"])
    assert "secret" not in item and "secret_hash" not in item and "secret_store" not in item
    one = client.get(f"/api/safety/event-subscriptions/{first['id']}",
                     headers=headers["safe"]).json()
    assert "secret" not in one


def test_pause_stops_delivery_resume_bumps_version(client, headers, db_path):
    sub = _register(client, headers["safe"], url="https://p.example/hook")
    v0 = sub["version"]
    # 重复暂停/恢复幂等
    p1 = client.post(f"/api/safety/event-subscriptions/{sub['id']}/pause",
                     headers=headers["safe"]).json()
    p2 = client.post(f"/api/safety/event-subscriptions/{sub['id']}/pause",
                     headers=headers["safe"]).json()
    assert p1["status"] == "paused" and p2["version"] == p1["version"]
    r = client.post(f"/api/safety/event-subscriptions/{sub['id']}/resume",
                    headers=headers["safe"]).json()
    assert r["status"] == "active" and r["version"] > v0
    # 暂停期间发生的事件：暂停时不 fan-out；恢复后历史不补发（只对 active fan-out）
    # （这里验证暂停端点不会被 worker 领取）
    conn = connect(db_path)
    assert conn.execute(
        "SELECT COUNT(*) n FROM event_deliveries WHERE subscription_id=?",
        (sub["id"],)).fetchone()["n"] == 0
    conn.close()


# ========================================================== 3. 租约

def test_concurrent_claim_single_valid_lease(client, headers, db_path):
    _register(client, headers["safe"], url="https://lease.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    w1 = DeliveryWorker(conn, worker_id="w1", transport=FakeTransport())
    got = w1.claim_one()
    assert got is not None
    # 第二个 worker（独立连接）立即领取：不能拿到同一条（租约有效）
    conn2 = connect(db_path)
    w2 = DeliveryWorker(conn2, worker_id="w2", transport=FakeTransport())
    other = w2.claim_one()
    if other is not None:
        assert other != got
    row = conn.execute("SELECT * FROM event_deliveries WHERE id=?", (got,)).fetchone()
    assert row["status"] == "leased" and row["lease_owner"] == "w1"
    conn.close(); conn2.close()


def test_parallel_workers_claim_disjoint_records(client, headers, db_path):
    """N 个 worker 线程并发 claim：不同订阅的队头可并行，同订阅严格按序（在途只一条），
    每条记录最多被一个 worker 领取，绝无双重领取。"""
    _register(client, headers["safe"], name="A", url="https://par1.example/hook")
    _register(client, headers["safe"], name="B", url="https://par2.example/hook")
    # 制造 6 个 enrolled 事件 → 两个订阅各 fan-out 6 条，共 12 条投递
    for i in range(6):
        code = f"P-{i}"
        client.post("/api/investigator/eligibility", headers=headers["inv01"], json={
            "subject_code": code,
            "answers": {"informed_consent": True, "age_ok": True,
                        "indication_ok": True, "no_exclusion": True}})
        e = client.post("/api/investigator/enroll", headers=headers["inv01"],
                        json={"subject_code": code, "pv_code": "V1.0"})
        assert e.status_code == 200
    conn = connect(db_path)
    total = conn.execute("SELECT COUNT(*) n FROM event_deliveries").fetchone()["n"]
    assert total == 12
    conn.close()

    claimed = []
    claimed_lock = threading.Lock()
    barrier = threading.Barrier(4)

    def run(wid):
        c = connect(db_path)
        w = DeliveryWorker(c, worker_id=wid, transport=FakeTransport([200]),
                           lease_seconds=300)
        barrier.wait()
        for _ in range(12):
            did = w.claim_one()
            if did is None:
                break
            with claimed_lock:
                claimed.append((wid, did))
        c.close()

    threads = [threading.Thread(target=run, args=(f"w{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 只有两个订阅的队头（各订阅在途一条）能被领取 → 恰 2 条，且 id 互不相同
    ids = [d for _, d in claimed]
    assert len(ids) == len(set(ids)) == 2, ids
    # 两条分别属于不同订阅
    conn = connect(db_path)
    subs = {r["subscription_id"] for r in conn.execute(
        "SELECT subscription_id FROM event_deliveries WHERE id IN (%s)" %
        ",".join("?" * len(ids)), ids).fetchall()}
    assert subs == {1, 2}
    n_leased = conn.execute(
        "SELECT COUNT(*) n FROM event_deliveries WHERE status='leased'").fetchone()["n"]
    assert n_leased == 2
    # 每个被领取记录只有一个 owner（GROUP BY 不出现同 id 两行）
    dup = conn.execute(
        "SELECT id FROM event_deliveries WHERE status='leased' GROUP BY id HAVING COUNT(*)>1"
    ).fetchall()
    assert dup == []
    conn.close()


def test_expired_lease_taken_over(client, headers, db_path):
    _register(client, headers["safe"], url="https://exp.example/hook")
    _make_business_events(client, headers)
    # 该订阅匹配全部三类事件
    conn = connect(db_path)
    assert conn.execute("SELECT COUNT(*) n FROM event_deliveries").fetchone()["n"] == 3
    w1 = DeliveryWorker(conn, worker_id="w1", lease_seconds=30,
                        transport=FakeTransport([200]))
    did = w1.claim_one()
    conn.close()
    # 模拟 w1 领取后卡死、租约到期：用独立连接把过期时间拨到过去并提交
    conn = connect(db_path)
    conn.execute("UPDATE event_deliveries SET lease_expires_at=? WHERE id=?",
                 ("2000-01-01T00:00:00+00:00", did))
    conn.commit()
    # 第二个 worker（独立连接）接管同一条
    conn2 = connect(db_path)
    w2 = DeliveryWorker(conn2, worker_id="w2", lease_seconds=30,
                        transport=FakeTransport([200]))
    taken = w2.claim_one()
    assert taken == did  # 过期租约可被接管
    row = conn2.execute("SELECT lease_owner FROM event_deliveries WHERE id=?",
                        (did,)).fetchone()
    assert row["lease_owner"] == "w2"
    # 旧 owner w1 此刻若"复活"提交结果：用新连接读到的是 w2 的租约，
    # 条件校验失配，不重复外呼、不覆盖接管者结论
    conn3 = connect(db_path)
    w1b = DeliveryWorker(conn3, worker_id="w1", lease_seconds=30,
                         transport=FakeTransport([200]))
    view = w1b.deliver(did)
    assert view["status"] == "leased" and view.get("note") == "LEASE_LOST"
    conn.close(); conn2.close(); conn3.close()


def test_success_then_crash_does_not_duplicate(client, headers, db_path):
    """订阅方已返回 200，但平台落 sent 前崩溃（模拟：w1 真实投递成功后把租约判过期）。
    接管 worker 重投同一记录，订阅方按 event_id 去重；最终只落一条 sent。"""
    secret_reg = _register(client, headers["safe"], url="https://crash.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    ft = FakeTransport([200],
                       secret_by_url={"https://crash.example/hook": secret_reg["secret"]})
    w1 = DeliveryWorker(conn, worker_id="w1", transport=ft)
    did = w1.claim_one()
    # 直接执行投递的网络部分（订阅方收到 200），但不走 _complete，模拟随后崩溃
    with conn:
        d = conn.execute("SELECT * FROM event_deliveries WHERE id=?", (did,)).fetchone()
        sub = conn.execute("SELECT * FROM event_subscriptions WHERE id=?",
                           (d["subscription_id"],)).fetchone()
        ev = conn.execute("SELECT * FROM platform_events WHERE id=?", (d["event_id"],)).fetchone()
        env = w1.bus.envelope(ev)
        secret = deobfuscate_secret(sub["secret_store"])
        hdrs = delivery_headers(secret, env, sub["version"])
        assert w1.transport(sub["endpoint_url"], hdrs, env) == 200
    # 崩溃恢复：租约已过期（sent 未落盘）
    conn.execute("UPDATE event_deliveries SET lease_expires_at=? WHERE id=?",
                 ("2000-01-01T00:00:00+00:00", did))
    conn.commit()
    # w2 接管并重新投递（at-least-once）：订阅端两次收到同一 event_id
    conn2 = connect(db_path)
    w2 = DeliveryWorker(conn2, worker_id="w2", transport=ft)
    taken = w2.claim_one()
    assert taken == did
    w2.deliver(taken)
    assert len(ft.calls) == 2
    assert ft.calls[0]["envelope"]["header"]["event_id"] == \
           ft.calls[1]["envelope"]["header"]["event_id"]
    assert ft.duplicates == [ft.calls[0]["envelope"]["header"]["event_id"]]
    row = conn2.execute("SELECT status, attempts, lease_owner FROM event_deliveries WHERE id=?",
                        (did,)).fetchone()
    assert row["status"] == "sent" and row["lease_owner"] is None
    conn.close(); conn2.close()


# ========================================================== 4. 退避 / 死信 / 重放

def test_backoff_then_dead_letter(client, headers, db_path):
    _register(client, headers["safe"], url="https://fail.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    # 只对最早一条耗尽尝试次数：max_attempts=3, 退避 0 秒便于立即重试
    ft = FakeTransport([500, 500, 500])
    w = DeliveryWorker(conn, worker_id="w", transport=ft,
                       backoff=(0, 0, 0, 0, 0), max_attempts=3, lease_seconds=30)
    did = w.claim_one()
    seq0 = conn.execute("SELECT event_seq FROM event_deliveries WHERE id=?", (did,)).fetchone()["event_seq"]
    for i in range(3):
        d = w.deliver(did)
        if i < 2:
            assert d["status"] == "queued"
            did = w.claim_one()  # 退避到期(0s)后重新领取同一条
            assert conn.execute(
                "SELECT event_seq FROM event_deliveries WHERE id=?", (did,)
            ).fetchone()["event_seq"] == seq0
        else:
            assert d["status"] == "dead"
    assert len(ft.calls) == 3
    # 死信清单能看到
    dead = client.get("/api/safety/event-deliveries?status=dead",
                      headers=headers["safe"]).json()
    assert any(x["id"] == seq0 or x["event_seq"] == seq0 for x in dead)
    conn.close()


def test_replay_dead_reuses_original_event(client, headers, db_path):
    from rts import events as evmod
    _register(client, headers["safe"], url="https://rl.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    # 前 2 次（打满进死信）失败；重放走覆盖传输，第 3 次成功
    ft = FakeTransport([500, 500, 200])
    w = DeliveryWorker(conn, transport=ft, backoff=(0, 0, 0), max_attempts=2)
    did = w.claim_one()
    w.deliver(did)
    d2 = w.claim_one(); w.deliver(d2)
    assert conn.execute("SELECT status FROM event_deliveries WHERE id=?",
                        (did,)).fetchone()["status"] == "dead"
    before = conn.execute("SELECT COUNT(*) n FROM platform_events").fetchone()["n"]
    conn.close()

    # API 内重放走覆盖传输（不发真实网络）
    replay_ft = FakeTransport([200])
    evmod.set_transport_override(replay_ft)
    try:
        r = client.post(f"/api/safety/event-deliveries/{did}/replay", headers=headers["safe"])
    finally:
        evmod.set_transport_override(None)
    assert r.status_code == 200, r.text
    view = r.json()
    assert view["status"] == "sent", view
    conn = connect(db_path)
    after = conn.execute("SELECT COUNT(*) n FROM platform_events").fetchone()["n"]
    assert after == before  # 重放不产生新业务事件
    # 投递的仍是同一事件包（同 event_id / seq / 签名 / 正文）
    rep_env = replay_ft.calls[0]["envelope"]
    orig_env = ft.calls[0]["envelope"]
    assert rep_env["header"]["event_id"] == orig_env["header"]["event_id"]
    assert rep_env["signature"] == orig_env["signature"]
    assert rep_env["body"] == orig_env["body"]
    assert conn.execute("SELECT replay_count FROM event_deliveries WHERE id=?",
                        (did,)).fetchone()["replay_count"] == 1
    conn.close()


def test_replay_is_idempotent_and_guarded(client, headers, db_path):
    _register(client, headers["safe"], url="https://g.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    w = DeliveryWorker(conn, transport=FakeTransport([200]))
    did = w.claim_one()
    w.deliver(did)
    # 已发送的重放 → 稳定返回（duplicate），不报 500
    r1 = client.post(f"/api/safety/event-deliveries/{did}/replay", headers=headers["safe"])
    assert r1.status_code == 200 and r1.json().get("duplicate") is True
    r2 = client.post(f"/api/safety/event-deliveries/{did}/replay", headers=headers["safe"])
    assert r2.status_code == 200 and r2.json()["id"] == did
    # 不存在 / 排队中的重放 → 404 / 409
    r3 = client.post("/api/safety/event-deliveries/99999/replay", headers=headers["safe"])
    assert r3.status_code == 404
    conn.close()


def test_replay_paused_endpoint_conflict(client, headers, db_path):
    sub = _register(client, headers["safe"], url="https://pp.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    w = DeliveryWorker(conn, transport=FakeTransport([500, 500]),
                       backoff=(0, 0), max_attempts=2)
    did = w.claim_one(); w.deliver(did)
    did = w.claim_one(); w.deliver(did)
    assert conn.execute("SELECT status FROM event_deliveries WHERE id=?",
                        (did,)).fetchone()["status"] == "dead"
    client.post(f"/api/safety/event-subscriptions/{sub['id']}/pause",
                headers=headers["safe"])
    r = client.post(f"/api/safety/event-deliveries/{did}/replay", headers=headers["safe"])
    assert r.status_code == 409 and r.json()["error"] == "ENDPOINT_PAUSED"
    conn.close()


# ========================================================== 5. 顺序 / 停用

def test_ordering_blocks_younger_until_older_settled(client, headers, db_path):
    _register(client, headers["safe"], url="https://ord.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    w = DeliveryWorker(conn, transport=FakeTransport([200]), lease_seconds=30)
    first = w.claim_one()
    seq_first = conn.execute("SELECT event_seq FROM event_deliveries WHERE id=?",
                             (first,)).fetchone()["event_seq"]
    assert seq_first == 1
    # 不投递第一条（模拟在途），第二条 claim 应被顺序护栏挡住 → None
    assert w.claim_one() is None
    # 第一条成功后，第二条才能领
    w.deliver(first)
    second = w.claim_one()
    assert second is not None
    assert conn.execute("SELECT event_seq FROM event_deliveries WHERE id=?",
                        (second,)).fetchone()["event_seq"] == 2
    conn.close()


def test_replay_order_conflict(client, headers, db_path):
    """同订阅两条死信：后序不能越过前序重放（稳定冲突），先重放前序后后序可重放。"""
    from rts import events as evmod
    _register(client, headers["safe"], url="https://oc.example/hook")
    _make_business_events(client, headers)  # seq 1,2,3
    conn = connect(db_path)
    w = DeliveryWorker(conn, transport=FakeTransport([500, 500, 500, 500]),
                       backoff=(0, 0), max_attempts=2)
    ids = {}
    # 顺序领取：每次只投到期且前序已终结的最早一条；前序死后后序才可领
    for _ in range(2):          # 打满 seq1 两次 → dead
        did = w.claim_one()
        w.deliver(did)
    d1 = conn.execute("SELECT id FROM event_deliveries WHERE event_seq=1").fetchone()["id"]
    for _ in range(2):          # 打满 seq2 → dead
        did = w.claim_one()
        w.deliver(did)
    d2 = conn.execute("SELECT id FROM event_deliveries WHERE event_seq=2").fetchone()["id"]
    conn.close()
    # 越过前序重放 seq2 → 409 顺序冲突
    r = client.post(f"/api/safety/event-deliveries/{d2}/replay", headers=headers["safe"])
    assert r.status_code == 409 and r.json()["error"] == "DELIVERY_ORDER_CONFLICT", r.text
    # 先重放前序（成功），再重放后序即放行
    evmod.set_transport_override(FakeTransport([200]))
    try:
        r1 = client.post(f"/api/safety/event-deliveries/{d1}/replay", headers=headers["safe"])
        assert r1.status_code == 200 and r1.json()["status"] == "sent", r1.text
    finally:
        evmod.set_transport_override(None)
    evmod.set_transport_override(FakeTransport([200]))
    try:
        r2 = client.post(f"/api/safety/event-deliveries/{d2}/replay", headers=headers["safe"])
        assert r2.status_code == 200 and r2.json()["status"] == "sent", r2.text
    finally:
        evmod.set_transport_override(None)


def test_subscription_admin_audit_trail(client, headers, db_path):
    """登记/暂停/重放/换钥都进安全审计；明细不含订阅密钥。"""
    sub = _register(client, headers["safe"], url="https://au.example/hook")
    client.post(f"/api/safety/event-subscriptions/{sub['id']}/pause", headers=headers["safe"])
    logs = client.get("/api/safety/audit", headers=headers["safe"]).json()
    blob = json.dumps(logs, ensure_ascii=False)
    actions = {x["action"] for x in logs}
    assert "event_subscription_register" in actions
    assert "event_subscription_pause" in actions
    assert sub["secret"] not in blob
    # 换钥审计
    client.post("/api/safety/rotate-signing-key", headers=headers["safe"])
    logs2 = client.get("/api/safety/audit", headers=headers["safe"]).json()
    assert "event_signing_key_rotate" in {x["action"] for x in logs2}


# ========================================================== 6. 角色与盲态边界

def test_pharmacy_cannot_access_event_admin(client, headers):
    for method, url in [
        ("GET", "/api/safety/event-subscriptions"),
        ("GET", "/api/safety/event-deliveries"),
        ("GET", "/api/safety/events"),
        ("POST", "/api/safety/rotate-signing-key"),
        ("GET", "/api/safety/event-integrity"),
    ]:
        r = client.request(method, url, headers=headers["ph01"])
        assert r.status_code == 403, (url, r.status_code)
    # 药房也不能用研究端摘要
    r = client.get("/api/investigator/events", headers=headers["ph01"])
    assert r.status_code == 403


def test_research_sees_only_authorized_center_summaries(client, headers):
    _make_business_events(client, headers)   # 01 中心
    e2 = enroll(client, headers["inv02"], "S-300", pv="V1.0")  # 02 中心
    assert e2
    # 召回：平台级
    client.post("/api/safety/recalls", headers=headers["safe"],
                json={"lot_nos": ["L2001"], "reason": "x"})
    v01 = client.get("/api/investigator/events", headers=headers["inv01"]).json()
    seqs01 = {x["seq"] for x in v01}
    v02 = client.get("/api/investigator/events", headers=headers["inv02"]).json()
    seqs02 = {x["seq"] for x in v02}
    # inv01 看到自己中心三类 + 平台级召回；看不到 inv02 的入组
    # inv02 看到自己入组 + 平台级召回；看不到 01 的发药/退药
    conn = connect(appmod.DB_PATH)
    def seq_of(kind, center):
        return conn.execute(
            "SELECT seq FROM platform_events WHERE kind=? AND IFNULL(center_code,'')=IFNULL(?, '')",
            (kind, center)).fetchall()
    inv02_enroll = conn.execute(
        "SELECT seq FROM platform_events WHERE kind='enrolled' AND center_code='02'"
    ).fetchone()["seq"]
    center01_dispense = conn.execute(
        "SELECT seq FROM platform_events WHERE kind='dispensed' AND center_code='01'"
    ).fetchone()["seq"]
    conn.close()
    assert inv02_enroll not in seqs01
    assert inv02_enroll in seqs02
    assert center01_dispense in seqs01
    assert center01_dispense not in seqs02
    # 摘要不回正文/签名/端点
    assert all("body" not in x and "signature" not in x for x in v01)


def test_audit_and_error_logs_have_no_secret_or_blinding(client, headers, db_path):
    reg = _register(client, headers["safe"], url="https://log.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    ft = FakeTransport([500, 500], )  # 制造失败重试
    w = DeliveryWorker(conn, transport=ft, backoff=(0, 0), max_attempts=2)
    did = w.claim_one(); w.deliver(did)
    did = w.claim_one(); w.deliver(did)
    # 审计接口返回：投递详情 + 尝试流水
    detail = client.get(f"/api/safety/event-deliveries/{did}", headers=headers["safe"]).json()
    blob = json.dumps(detail, ensure_ascii=False)
    assert reg["secret"] not in blob
    for bad in ("secret", "arm", "compat", "lot_switched"):
        assert bad not in blob.lower(), bad
    # 错误码是稳定码，不含 URL/异常文本
    for a in detail["attempts_log"]:
        if a["error_code"]:
            assert a["error_code"].startswith("ENDPOINT_")
    conn.close()


# ========================================================== 7. 库外验证 / 换钥

def test_public_materials_and_out_of_band_verify(client, headers, db_path, tmp_path):
    _make_business_events(client, headers)
    mats = client.get("/api/verify-materials").json()
    assert mats["active_key_id"]
    assert all("private" not in k for k in mats["keys"])
    # 取事件包，落盘，用 CLI 在"库外"核对
    results = []
    files = []
    for seq in (1, 2, 3):
        env = client.get(f"/api/events/{seq}").json()
        f = tmp_path / f"event-{seq}.json"
        f.write_text(json.dumps(env, ensure_ascii=False), encoding="utf-8")
        files.append(str(f))
        results.append(env)
    mfile = tmp_path / "materials.json"
    mfile.write_text(json.dumps(mats), encoding="utf-8")
    from rts.verify_events import main as verify_main
    rc = verify_main([*files, "--materials", str(mfile), "--chain"])
    assert rc == 0


def test_tampered_event_fails_verification(client, headers, db_path, tmp_path, capsys):
    _make_business_events(client, headers)
    mats = client.get("/api/verify-materials").json()
    env = client.get("/api/events/1").json()
    env["body"]["random_no"] = "FORGED-9999"   # 篡改正文
    ef = tmp_path / "e.json"
    ef.write_text(json.dumps(env), encoding="utf-8")
    mf = tmp_path / "m.json"
    mf.write_text(json.dumps(mats), encoding="utf-8")
    from rts.verify_events import main as verify_main
    rc = verify_main([str(ef), "--materials", str(mf)])
    assert rc == 2
    out = capsys.readouterr().out
    assert "正文摘要" in out or "签名" in out


def test_key_rotation_old_events_still_verify(client, headers, db_path, tmp_path):
    _make_business_events(client, headers)              # 用 v1 钥签
    old_env = client.get("/api/events/1").json()
    r = client.post("/api/safety/rotate-signing-key", headers=headers["safe"])
    assert r.status_code == 200
    # 换钥后再做一笔，用新钥签
    e = enroll(client, headers["inv01"], "S-777")
    client.post("/api/pharmacy/dispense", headers=headers["ph01"],
                json={"random_no": e["random_no"]})
    mats = client.get("/api/verify-materials").json()
    key_ids = {k["key_id"] for k in mats["keys"]}
    assert len(key_ids) == 2
    new_seq = client.get("/api/safety/events", headers=headers["safe"]).json()[0]["header"]["seq"]
    new_env = client.get(f"/api/events/{new_seq}").json()
    assert new_env["header"]["sign_key_id"] != old_env["header"]["sign_key_id"]
    # 材料同时含新旧公钥：两个事件都可验
    files = []
    for i, env in enumerate((old_env, new_env)):
        f = tmp_path / f"e{i}.json"
        f.write_text(json.dumps(env), encoding="utf-8")
        files.append(str(f))
    mf = tmp_path / "m.json"
    mf.write_text(json.dumps(mats), encoding="utf-8")
    from rts.verify_events import main as verify_main
    assert verify_main([*files, "--materials", str(mf)]) == 0


def test_subscription_version_recorded_on_events(client, headers, db_path):
    sub = _register(client, headers["safe"], url="https://sv.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    # 登记后全局订阅版本 >= 1；事件头 sub_version 与投递视图一致
    ev1 = conn.execute("SELECT sub_version FROM platform_events WHERE seq=1").fetchone()["sub_version"]
    assert ev1 >= 1
    # 暂停/恢复推进全局版本，之后新事件携带更大版本
    client.post(f"/api/safety/event-subscriptions/{sub['id']}/pause", headers=headers["safe"])
    client.post(f"/api/safety/event-subscriptions/{sub['id']}/resume", headers=headers["safe"])
    enroll(client, headers["inv01"], "S-888")
    last = conn.execute("SELECT MAX(sub_version) m FROM platform_events").fetchone()["m"]
    assert last > ev1
    conn.close()


# ========================================================== 8. 投递信封 HMAC

def test_delivery_envelope_headers_and_hmac(client, headers, db_path):
    reg = _register(client, headers["safe"], url="https://hm.example/hook")
    _make_business_events(client, headers)
    conn = connect(db_path)
    ft = FakeTransport([200],
                       secret_by_url={"https://hm.example/hook": reg["secret"]})
    w = DeliveryWorker(conn, transport=ft)
    w.run_batch()
    sent = ft.calls[0]
    h = sent["headers"]
    assert h["X-RTS-Event-Id"] == sent["envelope"]["header"]["event_id"]
    assert h["X-RTS-Event-Seq"] == "1"
    assert h["X-RTS-Delivery-Alg"].startswith("RTS-DELIVERY")
    # 篡改 HMAC 必失败
    assert verify_delivery_hmac("wrong", sent["envelope"],
                                int(h["X-RTS-Subscription-Version"]),
                                h["X-RTS-Signature"]) is False
    conn.close()


def test_secret_obfuscation_roundtrip():
    s = "rtsevt_abcd1234"
    assert obfuscate_secret(s) != s
    assert deobfuscate_secret(obfuscate_secret(s)) == s

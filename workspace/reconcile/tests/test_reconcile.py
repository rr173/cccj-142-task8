import sqlite3
import threading

import pytest

import db as dbmod
import service


def snapshot(permit_id="P1", subject="S-A", version=1, effective="2026-08-01T00:00:00Z",
             scope=("BLOOD_DRAW",), purposes=None, snapshot_version=1):
    return {
        "permit_id": permit_id, "subject_id": subject, "family": "MAIN",
        "basis_version": version, "scope": list(scope),
        "allowed_purposes": purposes or [], "effective_at": effective,
        "snapshot_version": snapshot_version,
        "body_hash": "a" * 64,
    }


def claim(cid="C1", when="2026-09-02T09:00:00Z", op="BLOOD_DRAW", purpose="routine",
          subject="S-A", version=1, source="blood_station", **extra):
    body = {
        "claim_id": cid, "source_system": source, "source_claim_code": cid + "-SRC",
        "subject_id": subject, "neutral_op": op, "purpose": purpose,
        "occurred_at": when, "basis_family": "MAIN", "basis_version": version,
        "payload": {"note": "x"},
    }
    body.update(extra)
    return body


def results(version):
    return {i["claim_id"]: i["result"] for i in version["items"]}


def test_normal_matching_and_fiveway_classification(conn, comp):
    service.import_permit_snapshot(conn, snapshot(scope=("BLOOD_DRAW", "IMAGING")), comp)
    service.import_permit_snapshot(conn, snapshot(
        permit_id="P2", version=2, effective="2026-09-10T00:00:00Z",
        scope=("BLOOD_DRAW",), snapshot_version=2), comp)
    service.ingest_claim(conn, claim("OK"), comp)
    service.ingest_claim(conn, claim("MISSING", basis_version=2), comp)
    service.ingest_claim(conn, claim("WAIT", basis_version=9), comp)
    service.ingest_claim(conn, claim("SCOPE", op="MEDICATION"), comp)
    v = service.recompute(conn, "CY1", comp)
    assert results(v)["OK"] == "explained"
    assert results(v)["MISSING"] == "missing_basis"
    assert results(v)["WAIT"] == "awaiting_late_material"
    assert results(v)["SCOPE"] == "out_of_scope"

    # 后补的是更晚才生效的依据：新版本仍不得追认历史行为。
    service.import_permit_snapshot(conn, snapshot(
        permit_id="P9", version=9, effective="2026-09-10T00:00:00Z",
        scope=("BLOOD_DRAW",), snapshot_version=2), comp)
    v2 = service.recompute(conn, "CY1", comp)
    assert v2["version_no"] == 2
    assert results(v2)["WAIT"] == "missing_basis"

    # 输入不变再次重算只识别现有版本，不生成第三版或重复差异项。
    v3 = service.recompute(conn, "CY1", comp)
    assert v3["id"] == v2["id"]
    assert conn.execute("SELECT COUNT(*) n FROM reconciliation_versions").fetchone()["n"] == 2


def test_before_and_after_termination_split(conn, comp):
    service.import_permit_snapshot(conn, snapshot(scope=("BLOOD_DRAW",)), comp)
    service.ingest_claim(conn, claim("BEFORE", "2026-09-02T08:00:00Z"), comp)
    service.ingest_claim(conn, claim("AFTER", "2026-09-04T08:00:00Z"), comp)
    service.import_termination(conn, {
        "permit_id": "P1", "terminated_at": "2026-09-03T00:00:00Z",
        "reason": "withdrawn", "snapshot_version": 2,
    }, comp)
    v = service.recompute(conn, "CY1", comp)
    assert results(v)["BEFORE"] == "explained"
    assert results(v)["AFTER"] == "post_termination"


def test_late_claim_is_added_in_next_version_but_not_rewritten(conn, comp):
    service.import_permit_snapshot(conn, snapshot(), comp)
    service.ingest_claim(conn, claim("EARLY"), comp)
    v1 = service.recompute(conn, "CY1", comp)
    assert len(v1["items"]) == 1
    service.ingest_claim(conn, claim("LATE", "2026-09-05T00:00:00Z"), comp)
    v2 = service.recompute(conn, "CY1", comp)
    assert v2["version_no"] == 2
    assert [i["claim_id"] for i in v1["items"]] == ["EARLY"]
    assert results(v2)["LATE"] == "explained"


def test_same_identifier_same_body_receipt_but_different_body_rejected(conn, comp):
    r1 = service.ingest_claim(conn, claim("DUP"), comp)
    r2 = service.ingest_claim(conn, claim("DUP"), comp)
    assert r1["receipt"] == r2["receipt"] and r2["replayed"] is True

    conflict = service.ingest_claim(conn, claim("DUP", purpose="changed"), comp)
    assert conflict["accepted"] is False
    assert conflict["reject_code"] == "claim_identifier_conflict"
    detail = service.get_claim(conn, "DUP", comp)
    assert detail["current_version"] == 1
    assert len(detail["versions"]) == 1


def test_versioned_correction_keeps_diff_chain_without_overwrite(conn, comp):
    service.ingest_claim(conn, claim("COR", purpose="old"), comp)
    rejected = service.ingest_claim(conn, claim("COR", purpose="new"), comp)
    assert rejected["reject_code"] == "claim_identifier_conflict"
    bad_chain = service.ingest_claim(conn, claim("COR", purpose="new", replaces_version=9), comp)
    assert bad_chain["accepted"] is False
    assert bad_chain["reject_code"] == "correction_chain_conflict"
    fixed = service.ingest_claim(conn, claim("COR", purpose="new", replaces_version=1), comp)
    assert fixed["version_no"] == 2
    detail = service.get_claim(conn, "COR", comp)
    assert [v["version_no"] for v in detail["versions"]] == [1, 2]
    assert detail["versions"][1]["replaces_version"] == 1
    assert detail["versions"][1]["diff_from_previous"]["purpose"] == {"from": "old", "to": "new"}


def test_cross_institution_and_corrupt_batch_rollback(conn, comp, site_a):
    good = service.ingest_batch(conn, {"claims": [claim("A1")]}, site_a)
    assert good["accepted"] is True
    with pytest.raises(service.ServiceError) as exc:
        service.ingest_batch(conn, {"claims": [claim("A2"), claim("B2", subject="S-B")]}, site_a)
    assert exc.value.code == "cross_institution"
    # 合规批量中出现两个机构同样拒绝，且第二笔不可见。
    with pytest.raises(service.ServiceError):
        service.ingest_batch(conn, {"claims": [claim("A3"), claim("B3", subject="S-B")]}, comp)
    with pytest.raises(service.ServiceError) as exc:
        service.ingest_batch(conn, {"claims": [claim("BAD"), {"claim_id": "BROKEN"}]}, comp)
    assert exc.value.code == "bad_claim"
    assert conn.execute("SELECT COUNT(*) n FROM claim_current WHERE claim_id='BAD'").fetchone()["n"] == 0
    assert conn.execute("SELECT COUNT(*) n FROM import_batches").fetchone()["n"] == 1


def test_double_recompute_publishes_one_version(conn, comp):
    service.import_permit_snapshot(conn, snapshot(), comp)
    service.ingest_claim(conn, claim("CONCURRENT"), comp)
    barrier = threading.Barrier(2)
    outputs = []

    def worker():
        c = dbmod.get_conn()
        barrier.wait()
        try:
            outputs.append(service.recompute(c, "CY1", comp))
        except Exception as exc:
            outputs.append(exc)
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    success = [x for x in outputs if not isinstance(x, Exception)]
    assert success and len({x["id"] for x in success}) == 1
    assert conn.execute("SELECT COUNT(*) n FROM reconciliation_versions").fetchone()["n"] == 1
    assert conn.execute("SELECT COUNT(*) n FROM reconciliation_items").fetchone()["n"] == 1
    running = conn.execute(
        "SELECT COUNT(*) n FROM reconciliation_jobs WHERE status='running'").fetchone()["n"]
    assert running == 0


def test_disposition_becomes_stale_when_snapshot_changes_but_original_remains(conn, comp):
    service.import_permit_snapshot(conn, snapshot(scope=("BLOOD_DRAW",)), comp)
    service.ingest_claim(conn, claim("X", op="IMAGING"), comp)
    v1 = service.recompute(conn, "CY1", comp)
    item = next(i for i in v1["items"] if i["claim_id"] == "X")
    d = service.dispose_item(conn, item["id"], {
        "resolution": "documented_exception", "reason": "登记为例外",
        "adopted_snapshot_version": 1,
    }, comp)
    # 后补材料改变了当时结论（新版允许影像）。
    service.import_permit_snapshot(conn, snapshot(
        scope=("BLOOD_DRAW", "IMAGING"), snapshot_version=2), comp)
    service.recompute(conn, "CY1", comp)
    row = conn.execute("SELECT * FROM dispositions WHERE id=?", (d["id"],)).fetchone()
    assert row["review_status"] == "stale_pending_review"
    assert row["resolution"] == "documented_exception"
    assert row["reason"] == "登记为例外"
    service.review_stale_disposition(conn, d["id"], {"review_note": "原判断保留，已复核"}, comp)
    reviewed = conn.execute("SELECT * FROM dispositions WHERE id=?", (d["id"],)).fetchone()
    assert reviewed["review_note"] == "原判断保留，已复核"
    # 原结论字段没有被覆盖。
    assert reviewed["resolution"] == "documented_exception"


def test_disposition_becomes_stale_when_claim_corrected(conn, comp):
    service.import_permit_snapshot(conn, snapshot(scope=("BLOOD_DRAW",)), comp)
    service.ingest_claim(conn, claim("COR", op="MEDICATION"), comp)
    v1 = service.recompute(conn, "CY1", comp)
    item = next(i for i in v1["items"] if i["claim_id"] == "COR")
    service.dispose_item(conn, item["id"], {
        "resolution": "corrective_action", "reason": "纠正", "adopted_snapshot_version": 1}, comp)
    service.ingest_claim(conn, claim("COR", op="BLOOD_DRAW", replaces_version=1), comp)
    service.recompute(conn, "CY1", comp)
    stale = conn.execute(
        "SELECT stale_reason,resolution,reason FROM dispositions WHERE item_id=?",
        (item["id"],)).fetchone()
    assert stale["stale_reason"] == "source_claim_changed"
    assert stale["resolution"] == "corrective_action"


def test_immutable_tables_block_rewrite(conn, comp):
    service.import_permit_snapshot(conn, snapshot(), comp)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE permit_snapshots SET body_hash='b' WHERE permit_id='P1'")
    service.ingest_claim(conn, claim("IMMUT"), comp)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE claim_versions SET purpose='hacked' WHERE claim_id='IMMUT'")
    service.recompute(conn, "CY1", comp)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE reconciliation_items SET result='explained' WHERE claim_id='IMMUT'")


def test_cross_role_data_isolation(conn, comp, site_a, site_b, wang):
    service.import_permit_snapshot(conn, snapshot(), comp)
    service.ingest_claim(conn, claim("A1"), comp)
    service.ingest_claim(conn, claim("B1", subject="S-B"), comp)
    v = service.recompute(conn, "CY1", comp)
    a_view = service.version_view(conn, v["id"], site_a)
    b_view = service.version_view(conn, v["id"], site_b)
    w_view = service.version_view(conn, v["id"], wang)
    assert {i["claim_id"] for i in a_view["items"]} == {"A1"}
    assert {i["claim_id"] for i in b_view["items"]} == {"B1"}
    assert {i["claim_id"] for i in w_view["items"]} == {"A1"}
    with pytest.raises(service.ServiceError) as exc:
        service.ingest_claim(conn, claim("B1", subject="S-B"), site_a)
    assert exc.value.code == "cross_institution"
    basis = service.subject_basis_view(conn, wang)
    assert {e["claim_id"] for e in basis["executions"]} == {"A1"}

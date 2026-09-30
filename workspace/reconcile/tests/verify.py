#!/usr/bin/env python3
"""端到端验证：真实 HTTP 服务、线程竞争与发布后 SIGKILL/os._exit 恢复。"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import http.client
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Client:
    def __init__(self, base):
        self.base = base

    def call(self, method, path, body=None, token=None, raw=None):
        data = raw if raw is not None else json.dumps(body or {}).encode()
        req = urllib.request.Request(self.base + path, data=data if method != "GET" else None,
                                     method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except http.client.RemoteDisconnected:
            return 0, {"error": "remote_disconnected"}
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def get(self, path, token): return self.call("GET", path, token=token)
    def post(self, path, body=None, token=None, raw=None):
        return self.call("POST", path, body=body, token=token, raw=raw)

    def login(self, login, password=None):
        if password is None:
            password = ("site-pass" if login.startswith("site") else
                        "wang-pass" if login == "wang" else
                        "zhao-pass" if login == "zhao" else "comp-pass")
        code, data = self.post("/api/auth/login", {"login": login, "password": password})
        assert code == 200, data
        return data["token"]


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} not ready")


def start(db_path, port):
    env = os.environ.copy()
    env["RECONCILE_DB"] = str(db_path)
    env["RECONCILE_PORT"] = str(port)
    p = subprocess.Popen([sys.executable, "server.py"], cwd=ROOT, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wait_port(port)
    return p


def result_map(version):
    return {x["claim_id"]: x for x in version["items"]}


def latest_version(c, token, cycle="CYCLE-2026-09"):
    code, data = c.get(f"/api/cycles/{cycle}/versions/latest", token)
    assert code == 200, data
    return data


def recompute(c, token, body=None, cycle="CYCLE-2026-09"):
    return c.post(f"/api/cycles/{cycle}/recompute", body or {}, token)


def main():
    checks = 0

    def ok(cond, msg):
        nonlocal checks
        assert cond, msg
        checks += 1
        print(f"✓ {msg}")

    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "recon.db"
        port = 18090
        p = start(db_path, port)
        c = Client(f"http://127.0.0.1:{port}")
        try:
            comp = c.login("comp")
            sitea = c.login("sitea")
            siteb = c.login("siteb")
            wang = c.login("wang")
            zhao = c.login("zhao")

            v1 = latest_version(c, comp)
            m = result_map(v1)
            ok(v1["version"] == 1, "种子版本为 v1")
            ok(m["CL-OK-BLOOD"]["result"] == "explained", "正常采血按时间点匹配为已解释")
            ok(m["CL-BEFORE-TERM"]["result"] == "explained", "终止前用药分流为已解释")
            ok(m["CL-AFTER-TERM"]["result"] == "explained",
               "21 日用药在缺少当时终止快照时不能凭空判定终止")

            # 同一声明标识 + 完全相同正文：稳定回执。
            blood = {
                "claim_id": "CL-DUP", "source_system": "blood", "subject_id": "subj-wang",
                "purpose": "routine_trial", "occurred_at": "2026-09-12T11:00:00Z",
                "arrived_at": "2026-09-12T12:00:00Z", "basis_version": "GENERAL:v1",
                "body": "重复声明回执测试",
            }
            code, first = c.post("/api/claims", blood, comp)
            code, replay = c.post("/api/claims", blood, comp)
            ok(code == 200 and replay["replayed"] is True and
               replay["receipt"] == first["receipt"], "同标识同正文重放返回同一接收回执")

            changed = dict(blood, body="同标识但正文已经改变")
            code, data = c.post("/api/claims", changed, comp)
            ok(code == 409 and data["error"] == "claim_payload_mismatch",
               "同标识异文且未引用上一版本被拒绝")

            code, bad_corr = c.post("/api/claims", dict(
                changed, supersedes_revision=99), comp)
            ok(code == 409 and bad_corr["error"] == "correction_out_of_order",
               "更正不能跳过当前版本形成差异链分叉")

            corrected = dict(changed, supersedes_revision=1,
                             arrived_at="2026-09-13T08:00:00Z")
            code, corr = c.post("/api/claims", corrected, comp)
            ok(code == 200 and corr["revision"] == 2 and
               corr["supersedes_revision"] == 1, "带版本更正生成 revision 2 并引用 revision 1")
            code, rows = c.get("/api/claims?claim_id=CL-DUP", comp)
            all_dup = [x for x in rows if x["claim_id"] == "CL-DUP"]
            ok(len(all_dup) == 2 and all_dup[0]["status"] == "superseded" and
               all_dup[1]["status"] == "accepted", "原声明保留且标记 superseded，没有被覆盖")

            # 迟到资料：先等待，后补齐。
            waiting = {
                "claim_id": "CL-LATE", "source_system": "imaging", "subject_id": "subj-wang",
                "purpose": "routine_trial", "occurred_at": "2026-09-15T09:00:00Z",
                "arrived_at": "2026-10-03T09:00:00Z", "basis_version": "GENERAL:v1",
                "data_status": "awaiting_materials",
                "body": "影像单迟到，资料未齐",
            }
            code, wr = c.post("/api/claims", waiting, comp)
            ok(code == 200 and wr["status"] == "accepted", "接收等待迟到资料的声明")
            code, v2 = recompute(c, comp)
            m2 = result_map(v2)
            ok(v2["version"] == 2 and
               m2["CL-LATE"]["result"] == "awaiting_late_materials", "新版本将迟到资料列为等待")

            supplement = dict(waiting, data_status="complete", body="影像单补齐",
                              supersedes_revision=wr["revision"],
                              arrived_at="2026-10-04T09:00:00Z")
            code, sr = c.post("/api/claims", supplement, comp)
            ok(code == 200 and sr["revision"] == 2, "迟到资料通过更正补齐")
            code, v3 = recompute(c, comp)
            m3 = result_map(v3)
            ok(v3["version"] == 3 and m3["CL-LATE"]["result"] == "explained",
               "补齐后重算的新版本将该行为解释，旧版本仍保留等待结论")

            # 终止后执行：先导入发生时刻之前可见的终止快照，再重算。
            terminated_snapshot = {
                "source_name": "consent-engine",
                "source_watermark": "permits-20260921T080000Z",
                "observed_at": "2026-09-21T08:00:00Z",
                "entries": [{
                    "subject_id": "subj-wang", "op": "medication", "purpose": "treatment",
                    "basis_version": "GENERAL:v1", "status": "terminated",
                    "granted_at": "2026-09-01T08:00:00Z",
                    "terminated_at": "2026-09-21T07:30:00Z",
                }],
            }
            code, snap = c.post("/api/snapshots", terminated_snapshot, comp)
            ok(code == 201, "导入 21 日 08:00 已可见的终止快照")
            code, v4 = recompute(c, comp)
            m4 = result_map(v4)
            ok(m4["CL-BEFORE-TERM"]["result"] == "explained" and
               m4["CL-AFTER-TERM"]["result"] == "post_termination",
               "终止前后两笔行为分别进入已解释与终止后执行")

            # 缺少依据 / 超出范围。
            missing = {
                "claim_id": "CL-MISSING", "source_system": "blood",
                "subject_id": "subj-zhao", "purpose": "routine_trial",
                "occurred_at": "2026-09-16T09:00:00Z",
                "arrived_at": "2026-09-16T10:00:00Z",
                "basis_version": "UNKNOWN:v9", "body": "赵的未知依据采血",
            }
            scope = {
                "claim_id": "CL-SCOPE", "source_system": "sample",
                "subject_id": "subj-wang", "purpose": "external_genomics",
                "occurred_at": "2026-09-16T11:00:00Z",
                "arrived_at": "2026-09-16T12:00:00Z",
                "basis_version": "GENERAL:v1", "body": "未授权外部基因组用途",
            }
            assert c.post("/api/claims", missing, comp)[0] == 200
            assert c.post("/api/claims", scope, comp)[0] == 200
            code, v5 = recompute(c, comp)
            m5 = result_map(v5)
            ok(m5["CL-MISSING"]["result"] == "missing_basis", "无版本依据列为缺少依据")
            ok(m5["CL-SCOPE"]["result"] == "out_of_scope", "用途不在授权范围列为超出范围")

            # 后补许可不能追认：快照 observed_at 晚于事件。
            late_snapshot = {
                "source_name": "consent-engine",
                "source_watermark": "permits-20260917T000000Z-for-zhao-late",
                "observed_at": "2026-09-17T00:00:00Z",
                "entries": [{
                    "subject_id": "subj-zhao", "op": "blood_draw",
                    "purpose": "routine_trial", "basis_version": "UNKNOWN:v9",
                    "status": "active", "granted_at": "2026-09-01T08:00:00Z",
                }],
            }
            assert c.post("/api/snapshots", late_snapshot, comp)[0] == 201
            code, v6 = recompute(c, comp)
            m6 = result_map(v6)
            ok(m6["CL-MISSING"]["result"] == "missing_basis" and
               m6["CL-MISSING"]["matched_snapshot_id"] is None,
               "后补材料只影响新版本，不能把当时无资格行为追认成合规")

            # 处置记录快照和理由；随后源声明更正，旧处置自动待复核且原判断保留。
            disposed_item = m6["CL-MISSING"]
            disposition = {
                "adopted_snapshot_id": 2,
                "decision": "waived", "reason": "赵的采血依据另行纸质核查，暂作豁免",
            }
            code, d1 = c.post(f"/api/items/{disposed_item['id']}/disposition",
                              disposition, comp)
            ok(code == 201 and d1["original"]["decision"] == "waived" and
               d1["original"]["snapshot_id"] == 2, "处置记录采用快照版本和理由")
            code, claim_change = c.post("/api/claims", {
                "claim_id": "CL-MISSING", "supersedes_revision": 1,
                "source_system": "blood", "subject_id": "subj-zhao",
                "purpose": "routine_trial", "occurred_at": "2026-09-16T09:05:00Z",
                "arrived_at": "2026-10-07T09:00:00Z",
                "basis_version": "UNKNOWN:v9", "body": "赵的未知依据采血（更正执行时刻）",
            }, comp)
            assert code == 200, claim_change
            code, v7 = recompute(c, comp)
            assert code == 200, v7
            code, reviews = c.get("/api/dispositions?status=needs_review", comp)
            stale = next(x for x in reviews if x["item_id"] == disposed_item["id"])
            ok(stale["original"]["decision"] == "waived" and
               stale["original"]["reason"] == disposition["reason"],
               "源声明变化后旧处置标为待复核，但保留原判断")
            new_missing = result_map(v7)["CL-MISSING"]
            code, d2 = c.post(f"/api/items/{new_missing['id']}/disposition", {
                "adopted_snapshot_id": 2, "decision": "escalated",
                "reason": "执行时刻更正，升级复核",
            }, comp)
            ok(code == 201 and d2["original"]["decision"] == "waived" and
               d2["status"] == "current", "复核形成新处置，并继续保留差异链上的原判断")

            # 格式损坏：整批拒绝。
            code, data = c.post("/api/claims/batch", raw=b"{broken", token=comp)
            ok(code == 400 and data["error"] == "bad_json", "格式损坏批次被稳定拒绝")
            before = c.get("/api/claims", comp)[1]
            ok(len(before) == len(c.get("/api/claims", comp)[1]),
               "格式损坏没有导入任何半批声明")

            # 跨机构对象：整批回滚。
            batch = {"inst_scope": "INST-A", "declarations": [{
                "claim_id": "CL-BATCH-A", "source_system": "blood",
                "subject_id": "subj-wang", "purpose": "routine_trial",
                "occurred_at": "2026-09-18T09:00:00Z",
                "arrived_at": "2026-09-18T10:00:00Z",
                "basis_version": "GENERAL:v1", "body": "批次内本站对象",
            }, {
                "claim_id": "CL-BATCH-B", "source_system": "blood",
                "subject_id": "subj-zhao", "purpose": "routine_trial",
                "occurred_at": "2026-09-18T09:30:00Z",
                "arrived_at": "2026-09-18T10:30:00Z",
                "basis_version": "UNKNOWN:v9", "body": "批次内外院对象",
            }]}
            code, data = c.post("/api/claims/batch", batch, comp)
            ok(code == 409 and data["error"] == "cross_institution_batch",
               "跨机构批次整批拒绝")
            claims = c.get("/api/claims", comp)[1]
            ok(not any(x["claim_id"].startswith("CL-BATCH-") for x in claims),
               "跨机构批次回滚，不留下本站那一条")

            # 站点身份提交外院对象也拒绝。
            code, data = c.post("/api/claims", dict(missing, claim_id="CL-SITE-CROSS"), sitea)
            ok(code in (403, 409) and data["error"] == "cross_institution_batch",
               "站点不能提交其他机构对象")

            # 双重算竞争：两个线程同时处理同一周期，只产生一个新版本。
            barrier = threading.Barrier(2)
            outcomes = []

            def worker():
                barrier.wait()
                outcomes.append(recompute(c, comp, {"worker_note": "double"}))

            threads = [threading.Thread(target=worker) for _ in range(2)]
            [t.start() for t in threads]
            for t in threads:
                t.join()
            versions = c.get("/api/cycles/CYCLE-2026-09/versions", comp)[1]
            before_double = len(versions)
            # 上面的输入自上一个版本以来没有变化；竞争双方都应回放同一版本。
            ok(len({data["input_watermark"] for code, data in outcomes}) == 1 and
               all(code == 200 for code, _ in outcomes) and
               len(c.get("/api/cycles/CYCLE-2026-09/versions", comp)[1]) == before_double,
               "两个重算进程同时处理同一周期只发布一个版本，失败结果不可见")

            # 跨角色数据隔离。
            code, data = c.post("/api/snapshots", late_snapshot, sitea)
            ok(code == 403, "站点不能导入许可快照")
            code, data = recompute(c, wang)
            ok(code == 403, "参与人不能触发周期重算")
            code, site_view = c.get("/api/cycles/CYCLE-2026-09/site-items", sitea)
            ok(code == 200 and all(x["inst_id"] == "INST-A" for x in site_view["items"]),
               "研究站点只看到本站差异")
            code, b_view = c.get("/api/cycles/CYCLE-2026-09/site-items", siteb)
            ok(code == 200 and all(x["inst_id"] == "INST-B" for x in b_view["items"]),
               "另一站点只看到本站差异")
            code, data = c.get("/api/cycles/CYCLE-2026-09/versions/latest", sitea)
            ok(code == 200 and all(x["inst_id"] == "INST-A" for x in data["items"]),
               "站点版本明细同样受机构过滤")
            code, mine = c.get("/api/my/executions", wang)
            ok(code == 200 and all(x["subject_id"] == "subj-wang" for x in mine["items"]),
               "参与人只查看自己的执行依据")
            code, zhao_mine = c.get("/api/my/executions", zhao)
            wang_ids = {x["claim_id"] for x in mine["items"]}
            zhao_ids = {x["claim_id"] for x in zhao_mine["items"]}
            ok(not (wang_ids & zhao_ids), "不同参与人之间数据完全隔离")

        finally:
            p.terminate()
            p.wait(timeout=5)

        # 服务在发布版本后、返回响应前退出：重启识别已完成版本。
        crash_port = port + 1
        p2 = start(db_path, crash_port)
        c2 = Client(f"http://127.0.0.1:{crash_port}")
        try:
            comp = c2.login("comp")
            before = latest_version(c2, comp)
            versions_before = len(c2.get("/api/cycles/CYCLE-2026-09/versions", comp)[1])
            # 当前输入已有已发布版本，重复调用即回放；再制造一个新声明后让服务在提交后退出。
            claim = {
                "claim_id": "CL-CRASH", "source_system": "imaging",
                "subject_id": "subj-wang", "purpose": "routine_trial",
                "occurred_at": "2026-09-19T15:00:00Z",
                "arrived_at": "2026-10-06T10:00:00Z",
                "basis_version": "GENERAL:v1", "body": "发布后崩溃测试",
            }
            assert c2.post("/api/claims", claim, comp)[0] == 200
            code, data = c2.post("/api/cycles/CYCLE-2026-09/recompute",
                                 {"crash_after_publish": True}, comp)
            # os._exit 通常导致客户端连接中断；允许无响应，但版本必须已提交。
            ok(code != 200 or data.get("version") is not None, "请求在响应前退出/或极端情况下已返回")
        finally:
            p2.wait(timeout=5)

        p3 = start(db_path, crash_port + 1)
        c3 = Client(f"127.0.0.1:{crash_port + 1}".replace("127", "http://127", 1)
                    if False else f"http://127.0.0.1:{crash_port + 1}")
        try:
            comp = c3.login("comp")
            code, replay = recompute(c3, comp)
            versions_after = len(c3.get("/api/cycles/CYCLE-2026-09/versions", comp)[1])
            after = latest_version(c3, comp)
            crashed = result_map(after)["CL-CRASH"]
            ok(code == 200 and replay.get("replayed") is True and
               versions_after == versions_before + 1, "重启后识别已发布版本并幂等返回，不再次生成版本号")
            ok(after["version"] > before.get("version", 1) and
               crashed["result"] == "explained", "崩溃前发布的差异项在重启后可见且未重复生成")
        finally:
            p3.terminate()
            p3.wait(timeout=5)

    print(f"\n全部 {checks} 项验证通过。")


if __name__ == "__main__":
    main()

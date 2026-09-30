"""演示种子：两机构、三类角色、固定 2026-09 周期与许可时间线。"""
import secrets

from db import begin_tx, hash_pw
import service

INSTITUTIONS = [
    ("INST-A", "北京研究中心"),
    ("INST-B", "上海研究中心"),
]
USERS = [
    # id, inst, role, login, password, name
    ("u-comp", None, "compliance", "comp", "comp-pass", "合规复核员"),
    ("u-site-a", "INST-A", "site", "sitea", "site-pass", "北京站点"),
    ("u-site-b", "INST-B", "site", "siteb", "site-pass", "上海站点"),
    ("u-wang", "INST-A", "participant", "wang", "wang-pass", "王参与人"),
    ("u-zhao", "INST-B", "participant", "zhao", "zhao-pass", "赵参与人"),
]
SUBJECTS = [
    ("subj-wang", "INST-A", "王参与人", "u-wang"),
    ("subj-zhao", "INST-B", "赵参与人", "u-zhao"),
]

CYCLE = {
    "id": "CYCLE-2026-09",
    "title": "2026 年 9 月医疗行为对账周期",
    "starts_at": "2026-09-01T00:00:00Z",
    "cutoff_at": "2026-10-01T00:00:00Z",
}

# 10 日观察：当时覆盖采血、影像、用药、留样；用药 20 日终止。
SNAPSHOT_1 = {
    "source_name": "consent-engine",
    "source_watermark": "permits-20260910T000000Z",
    "observed_at": "2026-09-10T00:00:00Z",
    "entries": [
        {"subject_id": "subj-wang", "op": "blood_draw", "purpose": "routine_trial",
         "basis_version": "GENERAL:v1", "status": "active",
         "granted_at": "2026-09-01T08:00:00Z"},
        {"subject_id": "subj-wang", "op": "imaging", "purpose": "routine_trial",
         "basis_version": "GENERAL:v1", "status": "active",
         "granted_at": "2026-09-01T08:00:00Z"},
        {"subject_id": "subj-wang", "op": "medication", "purpose": "treatment",
         "basis_version": "GENERAL:v1", "status": "active",
         "granted_at": "2026-09-01T08:00:00Z"},
        {"subject_id": "subj-wang", "op": "sample_retention", "purpose": "biobank",
         "basis_version": "GENERAL:v1", "status": "active",
         "granted_at": "2026-09-01T08:00:00Z"},
    ],
}

# 25 日观察：用药已经在 20 日终止；该快照晚于 21 日行为，不能在首版中追溯裁定。
SNAPSHOT_2 = {
    "source_name": "consent-engine",
    "source_watermark": "permits-20260925T000000Z",
    "observed_at": "2026-09-25T00:00:00Z",
    "entries": [
        {"subject_id": "subj-wang", "op": "blood_draw", "purpose": "routine_trial",
         "basis_version": "GENERAL:v1", "status": "active",
         "granted_at": "2026-09-01T08:00:00Z"},
        {"subject_id": "subj-wang", "op": "imaging", "purpose": "routine_trial",
         "basis_version": "GENERAL:v1", "status": "active",
         "granted_at": "2026-09-01T08:00:00Z"},
        {"subject_id": "subj-wang", "op": "medication", "purpose": "treatment",
         "basis_version": "GENERAL:v1", "status": "terminated",
         "granted_at": "2026-09-01T08:00:00Z",
         "terminated_at": "2026-09-20T12:00:00Z"},
        {"subject_id": "subj-wang", "op": "sample_retention", "purpose": "biobank",
         "basis_version": "GENERAL:v1", "status": "active",
         "granted_at": "2026-09-01T08:00:00Z"},
    ],
}

CLAIMS = [
    {
        "claim_id": "CL-OK-BLOOD", "source_system": "blood",
        "subject_id": "subj-wang", "purpose": "routine_trial",
        "occurred_at": "2026-09-12T09:00:00Z", "arrived_at": "2026-09-12T10:00:00Z",
        "basis_version": "GENERAL:v1", "body": "按方案采集 8ml 静脉血",
    },
    {
        "claim_id": "CL-BEFORE-TERM", "source_system": "medication",
        "subject_id": "subj-wang", "purpose": "treatment",
        "occurred_at": "2026-09-19T09:00:00Z", "arrived_at": "2026-09-19T10:00:00Z",
        "basis_version": "GENERAL:v1", "body": "终止前给予研究药物",
    },
    {
        "claim_id": "CL-AFTER-TERM", "source_system": "medication",
        "subject_id": "subj-wang", "purpose": "treatment",
        "occurred_at": "2026-09-21T09:00:00Z", "arrived_at": "2026-09-21T10:00:00Z",
        "basis_version": "GENERAL:v1", "body": "终止后给予研究药物",
    },
]


def ensure_seed(conn):
    if conn.execute("SELECT COUNT(*) c FROM institutions").fetchone()["c"]:
        return
    begin_tx(conn)
    try:
        for iid, name in INSTITUTIONS:
            conn.execute("INSERT INTO institutions(id,name) VALUES(?,?)", (iid, name))
        for uid, inst, role, login, password, name in USERS:
            salt = secrets.token_hex(8)
            conn.execute(
                "INSERT INTO users(id,inst_id,role,login,name,pw_hash,pw_salt)"
                " VALUES(?,?,?,?,?,?,?)",
                (uid, inst, role, login, name, hash_pw(salt, password), salt))
        for sid, inst, name, uid in SUBJECTS:
            conn.execute("INSERT INTO subjects(id,inst_id,name,user_id) VALUES(?,?,?,?)",
                         (sid, inst, name, uid))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    comp = {"id": "u-comp", "role": "compliance", "inst_id": None}
    service.create_cycle(conn, CYCLE, comp)
    service.import_snapshot(conn, SNAPSHOT_1, comp)
    service.import_snapshot(conn, SNAPSHOT_2, comp)
    for claim in CLAIMS:
        service.submit_claim(conn, claim, comp)
    service.recompute(conn, CYCLE["id"], comp)

"""演示种子数据：两机构、规则维护员、现场账号、参与人账号、一份封存材料。

仅在空库时执行，保证重启后数据延续而不是重置。
"""
import json
import secrets
import db as dbmod
from db import hash_pw
import engine

SEED = [
    ("INST-A", "协和分院"),
    ("INST-B", "仁济分院"),
]

USERS = [
    # id, inst, role, login, password, name
    ("u-admin", None, "admin", "admin", "admin-pass", "规则维护员"),
    ("u-site-a", "INST-A", "site", "sitea", "site-pass", "A院现场负责人"),
    ("u-site-b", "INST-B", "site", "siteb", "site-pass", "B院现场负责人"),
    ("u-wang", "INST-A", "subject", "wang", "wang-pass", "王 participant"),
    ("u-li", "INST-A", "subject", "li", "li-pass", "李 participant"),
    ("u-zhao", "INST-B", "subject", "zhao", "zhao-pass", "赵 participant"),
]

SUBJECTS = [
    # id, inst, name, user_id, language, conditions
    ("subj-wang", "INST-A", "王 participant", "u-wang", "zh", {"adult": True, "cohort": "trial-A"}),
    ("subj-li", "INST-A", "李 participant", "u-li", "zh", {"adult": True, "cohort": "trial-B"}),
    ("subj-zhao", "INST-B", "赵 participant", "u-zhao", "zh", {"adult": True, "cohort": "trial-A"}),
]

INITIAL_MATERIAL = {
    "family": "GENERAL-TRIAL",
    "inst_id": "INST-A",
    "language": "zh",
    "conditions": {"adult": True},
    "roles": ["subject", "witness", "site_owner"],
    "scope": ["blood_draw", "imaging", "medication", "sample_reuse"],
    "body": (
        "【通用临床试验告知书 v1】\n"
        "1. 您将接受常规采血、医学影像检查，并可能使用研究药物；\n"
        "2. 留存血样可能在去标识后用于本方案既定的再次利用；\n"
    ),
}


def ensure_seed(conn):
    if conn.execute("SELECT COUNT(*) c FROM institutions").fetchone()["c"]:
        return
    try:
        dbmod.begin_tx(conn)
        for iid, name in SEED:
            conn.execute("INSERT INTO institutions(id,name) VALUES(?,?)", (iid, name))
        for uid, inst, role, login, pw, name in USERS:
            salt = secrets.token_hex(8)
            conn.execute(
                "INSERT INTO users(id,inst_id,role,login,name,pw_hash,pw_salt)"
                " VALUES(?,?,?,?,?,?,?)",
                (uid, inst, role, login, name, hash_pw(salt, pw), salt))
        for sid, inst, name, uid, lang, cond in SUBJECTS:
            conn.execute(
                "INSERT INTO subjects(id,inst_id,name,user_id,language,conditions_json)"
                " VALUES(?,?,?,?,?,?)",
                (sid, inst, name, uid, lang,
                 json.dumps(cond, ensure_ascii=False)))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    engine.publish_material(
        dbmod.get_conn(), **INITIAL_MATERIAL,
        principal={"id": "u-admin", "role": "admin"})

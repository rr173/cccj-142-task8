"""演示种子：两个研究站点、合规员、参与人，以及一个空白对账周期。"""
import json
import secrets

from db import begin_tx, hash_pw, now_ms


def _pw(password):
    salt = secrets.token_hex(8)
    return salt, hash_pw(salt, password)


def ensure_seed(conn):
    begin_tx(conn)
    try:
        if conn.execute("SELECT 1 FROM users WHERE login='compliance'").fetchone():
            conn.execute("ROLLBACK")
            return
        institutions = [("INST-A", "北京研究中心"), ("INST-B", "上海研究中心")]
        for iid, name in institutions:
            conn.execute("INSERT INTO institutions(id,name) VALUES(?,?)", (iid, name))

        users = [
            ("U-COMP", None, "compliance", "compliance", "合规人员", "demo1234"),
            ("U-SITE-A", "INST-A", "site", "sitea", "北京站点", "demo1234"),
            ("U-SITE-B", "INST-B", "site", "siteb", "上海站点", "demo1234"),
            ("U-WANG", "INST-A", "subject", "wang", "王受试者", "demo1234"),
            ("U-ZHAO", "INST-B", "subject", "zhao", "赵受试者", "demo1234"),
        ]
        for uid, inst, role, login, name, password in users:
            salt, digest = _pw(password)
            conn.execute(
                "INSERT INTO users(id,inst_id,role,login,name,pw_hash,pw_salt) "
                "VALUES(?,?,?,?,?,?,?)", (uid, inst, role, login, name, digest, salt))
        conn.execute(
            "INSERT INTO subjects(id,inst_id,name,user_id) VALUES(?,?,?,?)",
            ("SUBJ-WANG", "INST-A", "王受试者", "U-WANG"))
        conn.execute(
            "INSERT INTO subjects(id,inst_id,name,user_id) VALUES(?,?,?,?)",
            ("SUBJ-ZHAO", "INST-B", "赵受试者", "U-ZHAO"))
        conn.execute(
            "INSERT INTO cycles(id,starts_at,ends_at,created_at) VALUES(?,?,?,?)",
            ("CYCLE-2026-09", "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", now_ms()))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


if __name__ == "__main__":
    import db
    db.init_db()
    ensure_seed(db.get_conn())
    print("seeded")

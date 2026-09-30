"""标准库测试运行器：在受限环境没有 pytest 时也能执行全部场景。"""
import contextlib
import os
import pathlib
import sqlite3
import sys
import tempfile
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


class ExpectedError(Exception):
    pass


@contextlib.contextmanager
def raises(error_type):
    cm = types.SimpleNamespace(value=None)
    try:
        yield cm
    except error_type as exc:
        cm.value = exc
        return
    raise AssertionError(f"expected {error_type.__name__}")


fake_pytest = types.SimpleNamespace(fixture=lambda fn: fn, raises=raises)
sys.modules["pytest"] = fake_pytest

import db as dbmod  # noqa: E402
import test_reconcile  # noqa: E402


def make_conn(tmp):
    db_path = os.path.join(tmp, "reconcile.db")
    dbmod.DB_PATH = db_path
    dbmod._initialized = False
    dbmod.init_db()
    c = dbmod.get_conn()
    c.execute("INSERT INTO institutions(id,name) VALUES('INST-A','A'),('INST-B','B')")
    c.execute("INSERT INTO users(id,inst_id,role,login,name,pw_hash,pw_salt) VALUES"
              "('U-C',NULL,'compliance','c','合规','h','s'),"
              "('U-A','INST-A','site','a','A站','h','s'),"
              "('U-B','INST-B','site','b','B站','h','s'),"
              "('U-W','INST-A','subject','w','王','h','s'),"
              "('U-Z','INST-B','subject','z','赵','h','s')")
    c.execute("INSERT INTO subjects(id,inst_id,name,user_id) VALUES"
              "('S-A','INST-A','A对象','U-W'),('S-B','INST-B','B对象','U-Z')")
    c.execute("INSERT INTO cycles(id,starts_at,ends_at,created_at) VALUES"
              "('CY1','2026-09-01T00:00:00Z','2026-10-01T00:00:00Z','2026-09-01T00:00:00Z')")
    c.commit()
    return c


def main():
    tests = [(name, fn) for name, fn in vars(test_reconcile).items()
             if name.startswith("test_") and callable(fn)]
    passed = 0
    for name, fn in tests:
        with tempfile.TemporaryDirectory() as tmp:
            conn = make_conn(tmp)
            fixtures = {
                "conn": conn,
                "comp": {"id": "U-C", "inst_id": None, "role": "compliance", "name": "合规"},
                "site_a": {"id": "U-A", "inst_id": "INST-A", "role": "site", "name": "A站"},
                "site_b": {"id": "U-B", "inst_id": "INST-B", "role": "site", "name": "B站"},
                "wang": {"id": "U-W", "inst_id": "INST-A", "role": "subject", "name": "王"},
            }
            args = [fixtures[p] for p in fn.__code__.co_varnames[:fn.__code__.co_argcount]]
            try:
                fn(*args)
            finally:
                conn.close()
        print(f"PASS {name}")
        passed += 1
    print(f"\n{passed}/{len(tests)} scenarios passed")


if __name__ == "__main__":
    main()

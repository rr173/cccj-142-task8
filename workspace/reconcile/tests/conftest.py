import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import db as dbmod


@pytest.fixture()
def conn(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONCILE_DB", str(tmp_path / "reconcile.db"))
    dbmod.DB_PATH = str(tmp_path / "reconcile.db")
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
    yield c
    c.close()


@pytest.fixture()
def comp():
    return {"id": "U-C", "inst_id": None, "role": "compliance", "name": "合规"}


@pytest.fixture()
def site_a():
    return {"id": "U-A", "inst_id": "INST-A", "role": "site", "name": "A站"}


@pytest.fixture()
def site_b():
    return {"id": "U-B", "inst_id": "INST-B", "role": "site", "name": "B站"}


@pytest.fixture()
def wang():
    return {"id": "U-W", "inst_id": "INST-A", "role": "subject", "name": "王"}

"""演示数据初始化（幂等，重复执行不会重复造数据）。

账号 / 密码（仅演示用）
  研究者: inv01 / inv02        密码 demo1234   分别绑定中心 01 / 02
  药房:   ph01  / ph02         密码 demo1234   分别绑定中心 01 / 02
  安全:   safe1 / safe2        密码 demo1234   双人正常揭盲各算一票

方案版本 V1.0：1:1，区组 4；V2.0：A:B = 1:2，区组 6。
批号命名保持中性（不含组别名），兼容关系只存在库里，不对药房/研究者展示。
"""
from __future__ import annotations

import json
import sys

from .db import connect, init_db
from .service import TrialService, hash_password, now

DEMO_PW = "demo1234"


def seed(db_path: str) -> None:
    init_db(db_path)
    conn = connect(db_path)
    svc = TrialService(conn)
    conn.execute("BEGIN IMMEDIATE")
    try:
        # ---- 中心
        for code, name in [("01", "北京中心"), ("02", "上海中心")]:
            conn.execute("INSERT OR IGNORE INTO centers(code,name) VALUES(?,?)", (code, name))

        # ---- 用户
        users = [
            ("inv01", "王研究(北京)", "investigator", "01"),
            ("inv02", "李研究(上海)", "investigator", "02"),
            ("ph01", "赵药师(北京)", "pharmacy", "01"),
            ("ph02", "钱药师(上海)", "pharmacy", "02"),
            ("safe1", "孙安全官", "safety", None),
            ("safe2", "周安全官", "safety", None),
        ]
        for username, display, role, center in users:
            if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                salt, pw = hash_password(DEMO_PW)
                conn.execute(
                    "INSERT INTO users(username,display,role,center_code,salt,pwhash) VALUES(?,?,?,?,?,?)",
                    (username, display, role, center, salt, pw),
                )

        # ---- 方案版本
        pvs = [
            ("V1.0", 4, ["A", "B"], [1, 1]),
            ("V2.0", 6, ["A", "B"], [1, 2]),
        ]
        for code, bs, names, ratios in pvs:
            if not conn.execute("SELECT 1 FROM protocol_versions WHERE code=?", (code,)).fetchone():
                conn.execute(
                    "INSERT INTO protocol_versions(code,block_size,arm_names,arm_ratios,active,created_at) VALUES(?,?,?,?,1,?)",
                    (code, bs, json.dumps(names), json.dumps(ratios), now()),
                )

        # ---- 批号（中性命名）与药盒
        # 每中心：L-10x 为组内首选（兼容集不对外展示），L-90x 为共享兼容批号（短缺时转用）
        lot_plan = [
            ("01", [("L1001", ["A"], 10), ("L1002", ["B"], 10), ("L9001", ["A", "B"], 90)]),
            ("02", [("L2001", ["A"], 10), ("L2002", ["B"], 10), ("L9002", ["A", "B"], 90)]),
        ]
        for center, lots in lot_plan:
            for lot_no, compat, prio in lots:
                if not conn.execute("SELECT 1 FROM lots WHERE lot_no=?", (lot_no,)).fetchone():
                    conn.execute(
                        "INSERT INTO lots(lot_no,center_code,compat_arms,priority,created_at) VALUES(?,?,?,?,?)",
                        (lot_no, center, json.dumps(compat), prio, now()),
                    )
                    n_existing = 0
                    # 首选批号 6 盒（按兼容组循环装箱）；共享批号 4 盒
                    count = 6 if prio < 90 else 4
                    for i in range(count):
                        arm = compat[(n_existing + i) % len(compat)]
                        kit_no = f"{lot_no}-{i + 1:04d}"
                        conn.execute(
                            "INSERT INTO kits(kit_no,lot_no,center_code,arm,status) VALUES(?,?,?,?,'in_stock')",
                            (kit_no, lot_no, center, arm),
                        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    print(f"seed done -> {db_path}")


if __name__ == "__main__":
    import os
    from pathlib import Path
    db = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
        "RTS_DB", str(Path(__file__).parent / "data" / "rts.db"))
    seed(db)

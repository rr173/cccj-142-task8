"""领域服务：随机分组与盲态药盒分配的全部业务规则。

设计原则
--------
1. 随机序列：按 (方案版本, 中心) 分层；每一层是确定可复现的置换区组序列，
   游标在写事务内前进，序列本身不物化，崩溃重启后同一位置永远推出同一治疗组
   （"不破坏既定随机序列"）。
2. 盲态：治疗组(arm) 对研究者/药房接口完全不可见；药房只能看到中性药盒号。
   arm 只在 dispense 内部参与匹配，以及揭盲流程中经授权释放。
3. 药盒守恒：每盒状态 in_stock/dispensed/returned 三态，只经 append-only
   kit_events 流转；同一时刻最多一个持有人；退回(returned)的盒子可再发。
4. 全部写操作走 BEGIN IMMEDIATE 串行事务，关键更新带条件，靠数据库唯一约束兜底。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from .db import transaction
from .events import EventBus


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ServiceError(Exception):
    def __init__(self, code: str, message: str, http: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http = http


# ---------------------------------------------------------------- 密码与登录

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return salt, dk.hex()


def verify_password(password: str, salt: str, pwhash: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt)[1], pwhash)


# ------------------------------------------------------------ 确定的随机序列

def _block_order(pv_code: str, center_code: str, block_index: int,
                 block_size: int) -> list[int]:
    """用 (方案版本, 中心, 区组序号) 派生种子做确定性 Fisher–Yates。

    不依赖随机库的内部状态，也不存"序列表"，因此：
    - 任何时候重启，同一位置推出同一顺序（序列既定且可复现）；
    - 不同中心/版本相互独立。
    """
    seed_material = f"rts|{pv_code}|{center_code}|blk{block_index}".encode()
    order = list(range(block_size))
    for i in range(block_size - 1, 0, -1):
        h = hashlib.sha256(seed_material + i.to_bytes(4, "big")).digest()
        j = int.from_bytes(h[:8], "big") % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def arm_at(pv_code: str, center_code: str, index: int,
           arm_names: list[str], arm_ratios: list[int], block_size: int) -> str:
    """序列第 index 个（0 起）分配对应的治疗组。

    比例 r_i 表示相对构成；一个区组内每组数量 = r_i * block_size/sum(r)，
    因此 1:1 + 区组4 ⇒ 每区组 2A2B；1:2 + 区组6 ⇒ 2A4B。"""
    ratio_sum = sum(arm_ratios)
    if block_size % ratio_sum != 0:
        raise ServiceError("BAD_BLOCK", "区组大小必须是各组比例之和的整数倍", 500)
    unit = block_size // ratio_sum
    per_block: list[str] = []
    for name, ratio in zip(arm_names, arm_ratios):
        per_block.extend([name] * ratio * unit)
    block_index, offset = divmod(index, block_size)
    order = _block_order(pv_code, center_code, block_index, block_size)
    return per_block[order[offset]]


def _format_random_no(pv_code: str, center_code: str, seq: int) -> str:
    return f"{pv_code.replace('.', '')}-{center_code}-{seq:04d}"


# ================================================================== 服务

class TrialService:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.bus = EventBus(conn)

    # ------------------------------------------------------------ 小工具
    def _audit(self, c: sqlite3.Connection, actor: Optional[str],
               action: str, detail: dict[str, Any]) -> None:
        c.execute(
            "INSERT INTO audit_log(actor,action,detail,created_at) VALUES(?,?,?,?)",
            (actor, action, json.dumps(detail, ensure_ascii=False), now()),
        )

    def _user(self, token: Optional[str]) -> sqlite3.Row:
        if not token:
            raise ServiceError("UNAUTHENTICATED", "请先登录", 401)
        row = self.conn.execute(
            """SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
               WHERE s.token=?""", (token,)).fetchone()
        if not row:
            raise ServiceError("UNAUTHENTICATED", "会话已失效，请重新登录", 401)
        return row

    def _require(self, user: sqlite3.Row, role: str) -> None:
        if user["role"] != role:
            raise ServiceError("FORBIDDEN", f"该操作仅{ {'investigator':'研究者','pharmacy':'药房','safety':'安全管理员'}[role] }可执行", 403)

    def _require_center(self, user: sqlite3.Row, center_code: str) -> None:
        if user["center_code"] != center_code:
            raise ServiceError("FORBIDDEN", "不能跨中心操作", 403)

    def _pv(self, c: sqlite3.Connection, code: str) -> sqlite3.Row:
        row = c.execute("SELECT * FROM protocol_versions WHERE code=?", (code,)).fetchone()
        if not row:
            raise ServiceError("PV_NOT_FOUND", f"方案版本 {code} 不存在", 404)
        if not row["active"]:
            raise ServiceError("PV_INACTIVE", f"方案版本 {code} 已停用", 400)
        return row

    # ------------------------------------------------------------ 登录
    def login(self, username: str, password: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not verify_password(password, row["salt"], row["pwhash"]):
            raise ServiceError("BAD_CREDENTIALS", "用户名或密码错误", 401)
        token = secrets.token_urlsafe(32)
        with transaction(self.conn) as c:
            c.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",
                      (token, row["id"], now()))
            self._audit(c, username, "login", {"role": row["role"]})
        return {
            "token": token,
            "username": row["username"],
            "display": row["display"],
            "role": row["role"],
            "center_code": row["center_code"],
        }

    def logout(self, token: str) -> None:
        with transaction(self.conn) as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))

    def me(self, token: str) -> dict[str, Any]:
        u = self._user(token)
        return {"username": u["username"], "display": u["display"],
                "role": u["role"], "center_code": u["center_code"]}

    # -------------------------------------------------- 研究者：入排 + 随机
    def evaluate_eligibility(self, token: Optional[str], subject_code: str,
                             answers: dict[str, bool]) -> dict[str, Any]:
        """入排标准判定：必须全部关键标准通过。不产生受试者记录。"""
        user = self._user(token)
        self._require(user, "investigator")
        if not subject_code.strip():
            raise ServiceError("BAD_SUBJECT", "受试者编码不能为空")
        required = ["informed_consent", "age_ok", "indication_ok", "no_exclusion"]
        missing = [k for k in required if k not in answers]
        if missing:
            raise ServiceError("BAD_ANSWERS", f"缺少入排项: {','.join(missing)}", 422)
        failures = [k for k in required if not bool(answers[k])]
        passed = not failures
        with transaction(self.conn) as c:
            c.execute(
                """INSERT INTO eligibility_events
                   (subject_code,center_code,pv_code,passed,detail,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (subject_code, user["center_code"], None, int(passed),
                 json.dumps({"answers": answers, "failures": failures}, ensure_ascii=False),
                 now()),
            )
        return {"subject_code": subject_code, "eligible": passed,
                "failures": failures}

    def enroll(self, token: Optional[str], subject_code: str,
               pv_code: str, idem_key: Optional[str] = None) -> dict[str, Any]:
        """入排已通过的受试者取得随机号。

        并发/重复保护：
        - subject_code 全局唯一 → 重复入组被数据库拒绝；
        - 同一 subject_code 再次调用 → 幂等返回原随机号（研究者重复点按钮不发新号）；
        - 分层游标在写事务内自增，两个中心、两个版本互不干扰。
        idem_key: 可选幂等键，保留同一调用重试语义。
        """
        user = self._user(token)
        self._require(user, "investigator")
        center_code = user["center_code"]

        with transaction(self.conn) as c:
            pv = self._pv(c, pv_code)
            arm_names = json.loads(pv["arm_names"])
            arm_ratios = json.loads(pv["arm_ratios"])
            block_size = pv["block_size"]

            # 幂等：已入组直接回原号；已登记但未入组（理论上不走这条路）也不新建
            existing = c.execute(
                "SELECT * FROM subjects WHERE subject_code=?", (subject_code,)
            ).fetchone()
            if existing:
                if not existing["random_no"]:
                    raise ServiceError("SUBJECT_NOT_RANDOMIZED", "受试者状态异常", 409)
                if existing["center_code"] != center_code:
                    raise ServiceError("FORBIDDEN", "该受试者属于其他中心", 403)
                return self._subject_view(existing, c, already=True)

            # 入排须通过（查最近一条该受试者的判定记录）
            ev = c.execute(
                """SELECT passed FROM eligibility_events
                   WHERE subject_code=? ORDER BY id DESC LIMIT 1""",
                (subject_code,),
            ).fetchone()
            if not ev or not ev["passed"]:
                raise ServiceError("NOT_ELIGIBLE", "受试者尚未通过入排标准", 412)

            # 取/建分层游标（行锁在 IMMEDIATE 事务内天然串行）
            stratum = c.execute(
                "SELECT * FROM strata WHERE pv_code=? AND center_code=?",
                (pv_code, center_code),
            ).fetchone()
            if stratum is None:
                c.execute(
                    "INSERT INTO strata(pv_code,center_code,next_assignment) VALUES(?,?,0)",
                    (pv_code, center_code),
                )
                stratum = c.execute(
                    "SELECT * FROM strata WHERE pv_code=? AND center_code=?",
                    (pv_code, center_code),
                ).fetchone()

            index = stratum["next_assignment"]
            arm = arm_at(pv_code, center_code, index, arm_names, arm_ratios, block_size)
            seq = index + 1
            random_no = _format_random_no(pv_code, center_code, seq)

            c.execute(
                "UPDATE strata SET next_assignment=? WHERE id=? AND next_assignment=?",
                (seq, stratum["id"], index),
            )
            cur = c.execute(
                """INSERT INTO subjects
                   (subject_code,center_code,pv_code,random_no,arm,enrolled_at,withdrawn)
                   VALUES(?,?,?,?,?,?,0)""",
                (subject_code, center_code, pv_code, random_no, arm, now()),
            )
            subject_id = cur.lastrowid
            self._audit(c, user["username"], "randomize",
                        {"subject_code": subject_code, "random_no": random_no,
                         "pv_code": pv_code, "center_code": center_code,
                         "idem_key": idem_key})
            # 注意：arm 不写进审计明细（审计本身也是研究者可见面的一部分）
            self.bus.publish(
                c, "enrolled", center_code, "investigator",
                {"subject_code": subject_code, "random_no": random_no,
                 "pv_code": pv_code},
            )
            row = c.execute("SELECT * FROM subjects WHERE id=?", (subject_id,)).fetchone()
            return self._subject_view(row, c)

    def _subject_view(self, s: sqlite3.Row, c: sqlite3.Connection,
                      already: bool = False) -> dict[str, Any]:
        """研究者视图：永不返回 arm。附带当前是否已发药/药盒号（药盒号中性）。"""
        kit = c.execute(
            "SELECT kit_no,lot_no,status FROM kits WHERE holder_subject_id=? AND status='dispensed'",
            (s["id"],),
        ).fetchone()
        return {
            "subject_code": s["subject_code"],
            "center_code": s["center_code"],
            "pv_code": s["pv_code"],
            "random_no": s["random_no"],
            "dispensed": kit is not None,
            "kit_no": kit["kit_no"] if kit else None,
            "lot_no": kit["lot_no"] if kit else None,
            "already_enrolled": already,
        }

    def list_subjects(self, token: Optional[str]) -> list[dict[str, Any]]:
        user = self._user(token)
        self._require(user, "investigator")
        with transaction(self.conn) as c:
            rows = c.execute(
                "SELECT * FROM subjects WHERE center_code=? ORDER BY id",
                (user["center_code"],),
            ).fetchall()
            return [self._subject_view(r, c) for r in rows]

    # ------------------------------------------------------------ 药房视图
    def _active_recall_lots(self, c: sqlite3.Connection) -> set[str]:
        """进行中召回单波及的全部批号：这些批号的药盒一律不可发放/再入库。
        （发布时快照进 recall_items 的盒子另有 frozen=1 标记；此处兜底
        召回发布后补录进该批号、未进快照的盒子。）"""
        rows = c.execute(
            """SELECT DISTINCT rl.lot_no FROM recall_lots rl
               JOIN recalls r ON r.id=rl.recall_id
               WHERE r.status='active'"""
        ).fetchall()
        return {r["lot_no"] for r in rows}

    def available_kits(self, token: Optional[str]) -> dict[str, Any]:
        """药房只能看到本中心、可领取的药盒：中性药盒号 + 批号。
        不返回 arm，不返回 compat_arms（兼容集会反推治疗组）。
        被召回冻结的盒子与召回中批号的盒子不出现在可领取列表。
        只给库存层面信息，药房无法据此推断任何人的分组。"""
        user = self._user(token)
        self._require(user, "pharmacy")
        excluded = self._active_recall_lots(self.conn)
        rows = self.conn.execute(
            """SELECT k.kit_no,k.lot_no,k.center_code
               FROM kits k WHERE k.center_code=? AND k.status='in_stock' AND k.frozen=0
               ORDER BY k.lot_no, k.kit_no""",
            (user["center_code"],),
        ).fetchall()
        rows = [r for r in rows if r["lot_no"] not in excluded]
        # 库存只按批号汇总数量 + 明细列表；任何字段都与治疗组无关
        by_lot: dict[str, int] = {}
        for r in rows:
            by_lot[r["lot_no"]] = by_lot.get(r["lot_no"], 0) + 1
        return {
            "center_code": user["center_code"],
            "lots": [{"lot_no": lot, "in_stock": n} for lot, n in sorted(by_lot.items())],
            "kits": [{"kit_no": r["kit_no"], "lot_no": r["lot_no"]} for r in rows],
        }

    def dispense(self, token: Optional[str], random_no: str,
                 kit_no: Optional[str] = None) -> dict[str, Any]:
        """发药。

        盲态匹配（药房无感）：系统内部按受试者 arm 选兼容药盒。
        - 不传 kit_no：系统自动挑，优先当前批号（同 arm 专属批号），
          当前批号无库存则按 lot.priority 转用"兼容批号"，记 lot_switched=1，
          既定随机序列（受试者→治疗组）不变，变的只是发货批号。
        - 传 kit_no：扫码指定；若该药盒与受试者治疗组不兼容，返回 409 且
          错误信息不说明是"组别不符"还是别的，避免药房枚举反推分组。
        并发：条件 UPDATE ... WHERE status='in_stock'，最后一盒只有一个请求成功。
        重复发药：受试者已有在持药盒 → 409；同一盒已发 → 409。
        """
        user = self._user(token)
        self._require(user, "pharmacy")

        with transaction(self.conn) as c:
            s = c.execute("SELECT * FROM subjects WHERE random_no=?", (random_no,)).fetchone()
            if not s:
                raise ServiceError("RANDOM_NOT_FOUND", "随机号不存在", 404)
            self._require_center(user, s["center_code"])
            if s["withdrawn"]:
                raise ServiceError("SUBJECT_WITHDRAWN", "受试者已退出，不能发药", 409)

            held = c.execute(
                "SELECT id FROM kits WHERE holder_subject_id=? AND status='dispensed'",
                (s["id"],),
            ).fetchone()
            if held:
                raise ServiceError("ALREADY_DISPENSED", "该受试者已有在持药盒，请先退药", 409)

            arm = s["arm"]  # 内部使用，绝不进任何返回/日志明文
            excluded_lots = self._active_recall_lots(c)

            if kit_no:
                kit = c.execute("SELECT * FROM kits WHERE kit_no=?", (kit_no,)).fetchone()
                if not kit or kit["center_code"] != user["center_code"]:
                    raise ServiceError("KIT_NOT_AVAILABLE", "该药盒当前不可领取", 409)
                if kit["status"] != "in_stock":
                    raise ServiceError("KIT_NOT_AVAILABLE", "该药盒当前不可领取", 409)
                if kit["frozen"] or kit["lot_no"] in excluded_lots:
                    # 召回冻结/召回批号：与"不存在/已发/不兼容"同一笼统错误
                    raise ServiceError("KIT_NOT_AVAILABLE", "该药盒当前不可领取", 409)
                if kit["arm"] != arm:
                    # 同一笼统错误，杜绝枚举区分"不存在/已发/不兼容"
                    raise ServiceError("KIT_NOT_AVAILABLE", "该药盒当前不可领取", 409)
                chosen = kit
                switched = self._is_switched(c, user["center_code"], chosen["lot_no"], arm)
            else:
                chosen = self._pick_kit(c, user["center_code"], arm, excluded_lots)
                if chosen is None:
                    self._audit(c, user["username"], "dispense_failed",
                                {"random_no": random_no, "reason": "no_compatible_kit"}
                    )
                    raise ServiceError("NO_COMPATIBLE_KIT",
                                       "没有与该随机号兼容的可用药盒（含兼容批号），请联系管理员调拨", 409)
                switched = self._is_switched(c, user["center_code"], chosen["lot_no"], arm)

            # 原子占位：条件更新，并发下 rowcount=0 即失败
            cur = c.execute(
                """UPDATE kits SET status='dispensed', holder_subject_id=?
                   WHERE id=? AND status='in_stock' AND frozen=0 AND holder_subject_id IS NULL""",
                (s["id"], chosen["id"]),
            )
            if cur.rowcount != 1:
                raise ServiceError("KIT_TAKEN", "药盒刚被他人领取，请重试", 409)

            c.execute(
                """INSERT INTO kit_events
                   (kit_no,event_type,subject_id,random_no,lot_no,lot_switched,actor,note,created_at)
                   VALUES(?, 'dispense', ?,?,?,?,?,?,?)""",
                (chosen["kit_no"], s["id"], random_no, chosen["lot_no"],
                 int(switched), user["username"],
                 "兼容批号转用" if switched else None, now()),
            )
            self._audit(c, user["username"], "dispense",
                        {"random_no": random_no, "kit_no": chosen["kit_no"],
                         "lot_no": chosen["lot_no"], "lot_switched": bool(switched)})
            # 平台事件正文：中性标识，绝不带 lot_switched/批号兼容/arm
            self.bus.publish(
                c, "dispensed", user["center_code"], "pharmacy",
                {"random_no": random_no, "kit_no": chosen["kit_no"],
                 "lot_no": chosen["lot_no"], "context": "routine"})
            return {"random_no": random_no, "kit_no": chosen["kit_no"],
                    "lot_no": chosen["lot_no"], "lot_switched": bool(switched)}

    def _is_switched(self, c: sqlite3.Connection, center_code: str,
                     lot_no: str, arm: str) -> bool:
        """首选批号 = 本中心 compat_arms 含该 arm、priority 最小的批号；
        从非首选批号发出即视为"转用兼容批号"。"""
        lot = c.execute("SELECT priority FROM lots WHERE lot_no=?", (lot_no,)).fetchone()
        if not lot:
            return False
        pref = self._preferred_lot_no(c, center_code, arm)
        return pref is not None and pref != lot_no

    def _preferred_lot_no(self, c: sqlite3.Connection, center_code: str,
                          arm: str) -> Optional[str]:
        row = c.execute(
            "SELECT * FROM lots WHERE center_code=? ORDER BY priority, lot_no",
            (center_code,),
        ).fetchall()
        for lot in row:
            if arm in json.loads(lot["compat_arms"]):
                return lot["lot_no"]
        return None

    def _pick_kit(self, c: sqlite3.Connection, center_code: str,
                  arm: str, excluded_lots: Optional[set[str]] = None) -> Optional[sqlite3.Row]:
        """按批号优先级挑选一盒与 arm 兼容的在库药盒。
        兼容 = 该批号 compat_arms 包含 arm；同优先级按 lot_no、kit_no 确定序，
        保证行为可复现，也让"最后一盒"竞争有唯一赢家。
        召回冻结（frozen=1）与召回中批号（excluded_lots）一律跳过。"""
        excluded_lots = excluded_lots or set()
        lots = c.execute(
            "SELECT * FROM lots WHERE center_code=? ORDER BY priority, lot_no",
            (center_code,),
        ).fetchall()
        for lot in lots:
            if lot["lot_no"] in excluded_lots:
                continue
            if arm not in json.loads(lot["compat_arms"]):
                continue
            kit = c.execute(
                """SELECT * FROM kits WHERE lot_no=? AND center_code=?
                         AND status='in_stock' AND frozen=0 AND arm=?
                         ORDER BY kit_no LIMIT 1""",
                (lot["lot_no"], center_code, arm),
            ).fetchone()
            if kit:
                return kit
        return None

    def return_kit(self, token: Optional[str], kit_no: str,
                   note: Optional[str] = None) -> dict[str, Any]:
        """退药：盒子从 dispensed → returned，解除持有人；记流水。
        returned 的盒子由管理员决定是否再入库再发（本系统允许直接再发：
        见 restock）。退药后再次发放走正常 dispense，随机序列不受影响。"""
        user = self._user(token)
        self._require(user, "pharmacy")
        with transaction(self.conn) as c:
            kit = c.execute("SELECT * FROM kits WHERE kit_no=?", (kit_no,)).fetchone()
            if not kit or kit["center_code"] != user["center_code"]:
                raise ServiceError("KIT_NOT_FOUND", "药盒不存在", 404)
            if kit["status"] != "dispensed":
                raise ServiceError("KIT_NOT_DISPENSED", "该药盒不在发放状态，无法退", 409)
            s = c.execute("SELECT * FROM subjects WHERE id=?", (kit["holder_subject_id"],)).fetchone()
            # 若该盒属于进行中召回的范围项，退回的同时冻结隔离，杜绝质检前回流；
            # 已冻结的盒（如召回关闭/撤销时兜底冻结）只升不降，绝不误恢复
            in_recall = c.execute(
                """SELECT 1 FROM recall_items ri JOIN recalls r ON r.id=ri.recall_id
                   WHERE ri.kit_no=? AND r.status='active' AND ri.state!='void'""",
                (kit_no,),
            ).fetchone()
            c.execute(
                """UPDATE kits SET status='returned', holder_subject_id=NULL,
                   frozen=MAX(frozen, ?) WHERE id=? AND status='dispensed'""",
                (1 if in_recall else 0, kit["id"]),
            )
            c.execute(
                """INSERT INTO kit_events
                   (kit_no,event_type,subject_id,random_no,lot_no,lot_switched,actor,note,created_at)
                   VALUES(?, 'return', ?,?,?,0,?,?,?)""",
                (kit_no, s["id"] if s else None, s["random_no"] if s else None,
                 kit["lot_no"], user["username"], note, now()),
            )
            self._audit(c, user["username"], "return",
                        {"kit_no": kit_no, "random_no": s["random_no"] if s else None,
                         "note": note})
            self.bus.publish(
                c, "returned", user["center_code"], "pharmacy",
                {"kit_no": kit_no,
                 "random_no": s["random_no"] if s else None,
                 "lot_no": kit["lot_no"]})
            return {"kit_no": kit_no, "status": "returned"}

    def restock_returned(self, token: Optional[str], kit_no: str) -> dict[str, Any]:
        """退回的药盒经质检再入库，之后可按兼容规则再次发放给新受试者。
        被召回冻结、或属于进行中召回范围的盒子禁止再入库（笼统 409，不说明原因）。"""
        user = self._user(token)
        self._require(user, "pharmacy")
        with transaction(self.conn) as c:
            kit = c.execute("SELECT * FROM kits WHERE kit_no=?", (kit_no,)).fetchone()
            if not kit or kit["center_code"] != user["center_code"]:
                raise ServiceError("KIT_NOT_FOUND", "药盒不存在", 404)
            if kit["status"] != "returned":
                raise ServiceError("KIT_NOT_RETURNED", "只有已退回药盒可再入库", 409)
            if kit["frozen"]:
                raise ServiceError("KIT_NOT_RESTOCKABLE", "该药盒当前不允许再入库", 409)
            in_recall = c.execute(
                """SELECT 1 FROM recall_items ri JOIN recalls r ON r.id=ri.recall_id
                   WHERE ri.kit_no=? AND r.status='active' AND ri.state!='void'""",
                (kit_no,),
            ).fetchone()
            if in_recall or kit["lot_no"] in self._active_recall_lots(c):
                raise ServiceError("KIT_NOT_RESTOCKABLE", "该药盒当前不允许再入库", 409)
            c.execute("UPDATE kits SET status='in_stock' WHERE id=? AND status='returned'", (kit["id"],))
            self._audit(c, user["username"], "restock", {"kit_no": kit_no})
            return {"kit_no": kit_no, "status": "in_stock"}

    def kit_history(self, token: Optional[str], kit_no: str) -> list[dict[str, Any]]:
        """单盒去向流水（药房/安全管理员可查，不含 arm）。"""
        user = self._user(token)
        if user["role"] not in ("pharmacy", "safety"):
            raise ServiceError("FORBIDDEN", "无权查询药盒流水", 403)
        q = "SELECT * FROM kit_events WHERE kit_no=? ORDER BY id"
        params: list[Any] = [kit_no]
        if user["role"] == "pharmacy":
            row = self.conn.execute("SELECT center_code FROM kits WHERE kit_no=?", (kit_no,)).fetchone()
            if not row or row["center_code"] != user["center_code"]:
                raise ServiceError("FORBIDDEN", "不能跨中心查询", 403)
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    # ------------------------------------------------------------ 应急揭盲
    def emergency_unblind(self, token: Optional[str], random_no: str,
                          reason: str) -> dict[str, Any]:
        """应急揭盲：只开放请求中的这一个受试者；返回且仅返回该人的 arm。

        - 研究者可发起（临床急救场景），必须写明原因；
        - 每个受试者仅可应急揭盲一次（重复请求幂等返回同一结果并再次留痕）；
        - 审计明细只含该受试者，服务层不 join 同区组其他人，杜绝横向泄露。
        """
        user = self._user(token)
        self._require(user, "investigator")
        if not reason or not reason.strip():
            raise ServiceError("REASON_REQUIRED", "应急揭盲必须填写原因", 422)
        with transaction(self.conn) as c:
            s = c.execute("SELECT * FROM subjects WHERE random_no=?", (random_no,)).fetchone()
            if not s:
                raise ServiceError("RANDOM_NOT_FOUND", "随机号不存在", 404)
            self._require_center(user, s["center_code"])
            ex = c.execute("SELECT * FROM emergency_unblinds WHERE subject_id=?", (s["id"],)).fetchone()
            c.execute(
                """INSERT INTO emergency_unblinds(subject_id,reason,actor,created_at)
                   VALUES(?,?,?,?) ON CONFLICT(subject_id) DO UPDATE SET reason=excluded.reason""",
                (s["id"], reason.strip(), user["username"], now()),
            )
            self._audit(c, user["username"], "emergency_unblind",
                        {"subject_code": s["subject_code"], "random_no": random_no,
                         "reason": reason.strip(), "repeat": ex is not None})
            # 事件正文只声明"对谁、以什么范围揭盲"，不含 arm（盲态边界）
            self.bus.publish(
                c, "unblinded", s["center_code"], "investigator",
                {"scope": "single_subject", "random_no": random_no,
                 "subject_code": s["subject_code"], "reason": reason.strip()})
            return {"random_no": random_no, "subject_code": s["subject_code"],
                    "arm": s["arm"], "scope": "single_subject"}

    # -------------------------------------------------- 安全管理员：数据锁定
    def lock_data(self, token: Optional[str]) -> dict[str, Any]:
        user = self._user(token)
        self._require(user, "safety")
        with transaction(self.conn) as c:
            c.execute("UPDATE study_state SET data_locked=1, locked_at=?, locked_by=? WHERE id=1",
                      (now(), user["username"]))
            self._audit(c, user["username"], "data_lock", {})
        return {"data_locked": True}

    def study_status(self, token: Optional[str]) -> dict[str, Any]:
        user = self._user(token)
        self._require(user, "safety")
        st = self.conn.execute("SELECT * FROM study_state WHERE id=1").fetchone()
        counts = {
            "subjects": self.conn.execute("SELECT COUNT(*) n FROM subjects").fetchone()["n"],
            "kits_in_stock": self.conn.execute("SELECT COUNT(*) n FROM kits WHERE status='in_stock'").fetchone()["n"],
            "kits_dispensed": self.conn.execute("SELECT COUNT(*) n FROM kits WHERE status='dispensed'").fetchone()["n"],
            "kits_returned": self.conn.execute("SELECT COUNT(*) n FROM kits WHERE status='returned'").fetchone()["n"],
            "emergency_unblinds": self.conn.execute("SELECT COUNT(*) n FROM emergency_unblinds").fetchone()["n"],
        }
        return {"data_locked": bool(st["data_locked"]), "locked_at": st["locked_at"],
                "locked_by": st["locked_by"], **counts}

    # ------------------------------------------------------------ 正常揭盲
    def request_unblind(self, token: Optional[str], reason: str) -> dict[str, Any]:
        user = self._user(token)
        self._require(user, "safety")
        if not reason or not reason.strip():
            raise ServiceError("REASON_REQUIRED", "揭盲申请必须填写原因", 422)
        with transaction(self.conn) as c:
            if not c.execute("SELECT data_locked FROM study_state WHERE id=1").fetchone()["data_locked"]:
                raise ServiceError("DATA_NOT_LOCKED", "正常揭盲前必须先锁定数据", 409)
            pend = c.execute("SELECT id FROM unblind_requests WHERE status='pending'").fetchone()
            if pend:
                raise ServiceError("REQUEST_PENDING", "已有待审批的揭盲申请", 409)
            cur = c.execute(
                """INSERT INTO unblind_requests(status,reason,created_by,created_at)
                   VALUES('pending',?,?,?)""",
                (reason.strip(), user["username"], now()),
            )
            # 发起人自动算作第一审批人
            c.execute("INSERT OR IGNORE INTO unblind_approvals(request_id,approver,created_at) VALUES(?,?,?)",
                      (cur.lastrowid, user["username"], now()))
            self._audit(c, user["username"], "unblind_request", {"request_id": cur.lastrowid})
            return self._unblind_view(cur.lastrowid, c)

    def approve_unblind(self, token: Optional[str], request_id: int) -> dict[str, Any]:
        user = self._user(token)
        self._require(user, "safety")
        with transaction(self.conn) as c:
            req = c.execute("SELECT * FROM unblind_requests WHERE id=?", (request_id,)).fetchone()
            if not req:
                raise ServiceError("REQUEST_NOT_FOUND", "揭盲申请不存在", 404)
            if req["status"] != "pending":
                raise ServiceError("REQUEST_CLOSED", "该申请已结束", 409)
            if not c.execute("SELECT data_locked FROM study_state WHERE id=1").fetchone()["data_locked"]:
                raise ServiceError("DATA_NOT_LOCKED", "数据锁已解除，不能继续审批", 409)
            approvals = c.execute(
                "SELECT approver FROM unblind_approvals WHERE request_id=?", (request_id,)
            ).fetchall()
            names = {a["approver"] for a in approvals}
            if user["username"] in names:
                raise ServiceError("ALREADY_APPROVED_BY_YOU", "你已审批过，等待另一名安全管理员", 409)
            c.execute("INSERT INTO unblind_approvals(request_id,approver,created_at) VALUES(?,?,?)",
                      (request_id, user["username"], now()))
            names.add(user["username"])
            approved = len(names) >= 2
            if approved:
                c.execute("UPDATE unblind_requests SET status='approved', decided_at=? WHERE id=?",
                          (now(), request_id))
                # 正常揭盲是全平台事件：只记审批事实与审批人，不含分组表明细
                self.bus.publish(
                    c, "unblinded", None, "safety",
                    {"scope": "all", "request_id": request_id,
                     "approvers": sorted(names), "required_approvals": 2})
            self._audit(c, user["username"], "unblind_approve",
                        {"request_id": request_id, "approved": approved,
                         "approver_count": len(names)})
            return self._unblind_view(request_id, c, include_arms=approved)

    def _unblind_view(self, request_id: int, c: sqlite3.Connection,
                      include_arms: bool = False) -> dict[str, Any]:
        req = c.execute("SELECT * FROM unblind_requests WHERE id=?", (request_id,)).fetchone()
        approvals = [r["approver"] for r in c.execute(
            "SELECT approver FROM unblind_approvals WHERE request_id=? ORDER BY id",
            (request_id,)).fetchall()]
        result = {"id": req["id"], "status": req["status"], "reason": req["reason"],
                  "created_by": req["created_by"], "created_at": req["created_at"],
                  "decided_at": req["decided_at"], "approvals": approvals,
                  "required_approvals": 2}
        if include_arms:
            # 双人审批通过后，分组才在这里一次性释放；只在 approved 响应里出现
            rows = c.execute(
                """SELECT subject_code,random_no,center_code,pv_code,arm,withdrawn
                   FROM subjects ORDER BY id""").fetchall()
            result["unblinded_table"] = [
                {"subject_code": r["subject_code"], "random_no": r["random_no"],
                 "center_code": r["center_code"], "pv_code": r["pv_code"],
                 "arm": r["arm"], "withdrawn": bool(r["withdrawn"])}
                for r in rows
            ]
        return result

    def list_unblind_requests(self, token: Optional[str]) -> list[dict[str, Any]]:
        user = self._user(token)
        self._require(user, "safety")
        return [self._unblind_view(r["id"], self.conn)
                for r in self.conn.execute("SELECT id FROM unblind_requests ORDER BY id").fetchall()]

    def get_unblind_request(self, token: Optional[str],
                            request_id: int) -> dict[str, Any]:
        """只有 status='approved' 的申请才会带出完整分组表（持久授权结果）。"""
        user = self._user(token)
        self._require(user, "safety")
        with transaction(self.conn) as c:
            req = c.execute("SELECT * FROM unblind_requests WHERE id=?", (request_id,)).fetchone()
            if not req:
                raise ServiceError("REQUEST_NOT_FOUND", "揭盲申请不存在", 404)
            return self._unblind_view(request_id, c,
                                      include_arms=req["status"] == "approved")

    def emergency_list(self, token: Optional[str]) -> list[dict[str, Any]]:
        """应急揭盲登记列表：逐条对应单个受试者，不含治疗组明细，
        治疗组只在申请人当次的应急揭盲响应中出现。"""
        user = self._user(token)
        self._require(user, "safety")
        rows = self.conn.execute(
            """SELECT e.id,e.reason,e.actor,e.created_at,
                      s.subject_code,s.random_no,s.center_code
               FROM emergency_unblinds e JOIN subjects s ON s.id=e.subject_id
               ORDER BY e.id"""
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------ 审计查询
    def audit_log(self, token: Optional[str], limit: int = 200) -> list[dict[str, Any]]:
        user = self._user(token)
        self._require(user, "safety")
        rows = self.conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(limit, 1000),)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------ 库存维护
    def add_lot(self, token: Optional[str], lot_no: str, center_code: str,
                compat_arms: list[str], priority: int) -> dict[str, Any]:
        user = self._user(token)
        self._require(user, "safety")
        with transaction(self.conn) as c:
            pv = c.execute("SELECT arm_names FROM protocol_versions WHERE active=1 ORDER BY id LIMIT 1").fetchone()
            valid = set(json.loads(pv["arm_names"])) if pv else set()
            if not set(compat_arms) <= valid:
                raise ServiceError("BAD_ARMS", f"兼容组必须是 {sorted(valid)} 的子集", 422)
            try:
                c.execute(
                    "INSERT INTO lots(lot_no,center_code,compat_arms,priority,created_at) VALUES(?,?,?,?,?)",
                    (lot_no, center_code, json.dumps(sorted(compat_arms)), priority, now()),
                )
            except sqlite3.IntegrityError:
                raise ServiceError("LOT_EXISTS", "批号已存在", 409)
            self._audit(c, user["username"], "add_lot",
                        {"lot_no": lot_no, "center_code": center_code, "priority": priority})
            return {"lot_no": lot_no, "center_code": center_code, "priority": priority}

    def add_kits(self, token: Optional[str], lot_no: str, count: int,
                 arm: Optional[str] = None) -> dict[str, Any]:
        """按批号补药盒。arm 只在补库时由管理员按实际包装录入；
        对外（药房/研究者）永不暴露。arm=None 时按该批号兼容组循环装箱。"""
        user = self._user(token)
        self._require(user, "safety")
        if count <= 0 or count > 10000:
            raise ServiceError("BAD_COUNT", "数量需在 1..10000", 422)
        with transaction(self.conn) as c:
            lot = c.execute("SELECT * FROM lots WHERE lot_no=?", (lot_no,)).fetchone()
            if not lot:
                raise ServiceError("LOT_NOT_FOUND", "批号不存在", 404)
            compat = json.loads(lot["compat_arms"])
            if arm is not None and arm not in compat:
                raise ServiceError("BAD_ARM", "该药盒治疗组不在批号兼容集内", 422)
            existing = c.execute("SELECT COUNT(*) n FROM kits WHERE lot_no=?", (lot_no,)).fetchone()["n"]
            made = []
            for i in range(count):
                use_arm = arm or compat[(existing + i) % len(compat)]
                kit_no = f"{lot_no}-{existing + i + 1:04d}"
                try:
                    c.execute(
                        "INSERT INTO kits(kit_no,lot_no,center_code,arm,status) VALUES(?,?,?,?,'in_stock')",
                        (kit_no, lot_no, lot["center_code"], use_arm),
                    )
                    made.append(kit_no)
                except sqlite3.IntegrityError:
                    raise ServiceError("KIT_EXISTS", f"药盒 {kit_no} 已存在", 409)
            self._audit(c, user["username"], "add_kits",
                        {"lot_no": lot_no, "count": count, "kit_nos": made})
            # 补库动作记录的 kit_no 中性；arm 不入审计明细
            return {"lot_no": lot_no, "added": len(made), "kit_nos": made}

    # ============================================================ 批次召回
    # 状态机（recall_items.state）：
    #   frozen_stock  未领用库存，发布即冻结；撤销/关闭/重启都不自动解冻
    #   pending       待处理（已领用，待回收或登记豁免）
    #   recovered     已回收（药房扫码确认实物）→ 可签发替换凭证
    #   exempt_pending 豁免待复核 → 安全管理员批准→replaceable / 驳回→pending
    #   replaceable   可替换（一次性凭证已签发）→ 核销后 redeemed
    #   redeemed      已核销（终态）      void 已作废（召回撤销，终态）
    # 除上述箭头外的一切跳转（尤其逆向）都返回统一 RECALL_STATE_CONFLICT。
    RECALL_OPEN_STATES = ("pending", "recovered", "exempt_pending", "replaceable")
    RECALL_ITEM_LABELS = {
        "frozen_stock": "库存已冻结",
        "pending": "待处理",
        "recovered": "已回收",
        "exempt_pending": "豁免待复核",
        "replaceable": "可替换",
        "redeemed": "已核销",
        "void": "已作废",
    }

    def _recall_conflict(self, message: str = "召回单或处置项当前状态不允许该操作") -> ServiceError:
        return ServiceError("RECALL_STATE_CONFLICT", message, 409)

    def _get_recall(self, c: sqlite3.Connection, recall_id: int) -> sqlite3.Row:
        r = c.execute("SELECT * FROM recalls WHERE id=?", (recall_id,)).fetchone()
        if not r:
            raise ServiceError("RECALL_NOT_FOUND", "召回单不存在", 404)
        return r

    def _recall_view(self, recall_id: int, c: sqlite3.Connection) -> dict[str, Any]:
        """风险控制端视图：跨中心汇总只有计数，不含任何可反推分组的字段。"""
        r = self._get_recall(c, recall_id)
        lots = [row["lot_no"] for row in c.execute(
            "SELECT lot_no FROM recall_lots WHERE recall_id=? ORDER BY lot_no",
            (recall_id,)).fetchall()]
        items = c.execute(
            "SELECT state,center_code FROM recall_items WHERE recall_id=?",
            (recall_id,)).fetchall()
        by_state: dict[str, int] = {}
        by_center: dict[str, dict[str, int]] = {}
        for it in items:
            by_state[it["state"]] = by_state.get(it["state"], 0) + 1
            cc = by_center.setdefault(it["center_code"], {})
            cc[it["state"]] = cc.get(it["state"], 0) + 1
        return {
            "id": r["id"], "recall_no": r["recall_no"], "reason": r["reason"],
            "status": r["status"], "lot_nos": lots,
            "created_by": r["created_by"], "created_at": r["created_at"],
            "closed_at": r["closed_at"], "closed_by": r["closed_by"],
            "revoked_at": r["revoked_at"], "revoked_by": r["revoked_by"],
            "revoke_reason": r["revoke_reason"],
            "item_counts": by_state,
            "open_items": sum(by_state.get(s, 0) for s in self.RECALL_OPEN_STATES),
            "center_summary": [
                {"center_code": cc, "counts": counts}
                for cc, counts in sorted(by_center.items())
            ],
        }

    def create_recall(self, token: Optional[str], lot_nos: list[str],
                      reason: str) -> dict[str, Any]:
        """发布召回单：固化范围快照，未领用库存立即冻结。
        快照只含发布瞬间该批号下的药盒；之后补录的盒不混入本单
        （但其批号在召回期间仍被发放/再入库拦截）。"""
        user = self._user(token)
        self._require(user, "safety")
        lot_nos = [x.strip() for x in dict.fromkeys(lot_nos or []) if x and x.strip()]
        if not lot_nos:
            raise ServiceError("BAD_LOTS", "至少指定一个受影响批号", 422)
        if not reason or not reason.strip():
            raise ServiceError("REASON_REQUIRED", "召回单必须填写原因", 422)
        with transaction(self.conn) as c:
            for lot_no in lot_nos:
                if not c.execute("SELECT 1 FROM lots WHERE lot_no=?", (lot_no,)).fetchone():
                    raise ServiceError("LOT_NOT_FOUND", f"批号 {lot_no} 不存在", 404)
            ph = ",".join("?" * len(lot_nos))
            clash = c.execute(
                f"""SELECT rl.lot_no, r.recall_no FROM recall_lots rl
                    JOIN recalls r ON r.id=rl.recall_id
                    WHERE r.status='active' AND rl.lot_no IN ({ph})""",
                lot_nos,
            ).fetchall()
            if clash:
                raise ServiceError(
                    "LOT_ALREADY_RECALLED",
                    f"批号 {clash[0]['lot_no']} 已在进行中的召回单 {clash[0]['recall_no']} 内", 409)
            seq = c.execute("SELECT COUNT(*) n FROM recalls").fetchone()["n"] + 1
            recall_no = f"RC-{seq:04d}"
            cur = c.execute(
                "INSERT INTO recalls(recall_no,reason,status,created_by,created_at) VALUES(?,?,'active',?,?)",
                (recall_no, reason.strip(), user["username"], now()),
            )
            recall_id = cur.lastrowid
            for lot_no in lot_nos:
                c.execute("INSERT INTO recall_lots(recall_id,lot_no) VALUES(?,?)",
                          (recall_id, lot_no))
            kits = c.execute(f"SELECT * FROM kits WHERE lot_no IN ({ph})", lot_nos).fetchall()
            ts = now()
            for k in kits:
                if k["status"] == "dispensed":
                    state, sid, rno = "pending", k["holder_subject_id"], None
                    if sid:
                        subj = c.execute("SELECT random_no FROM subjects WHERE id=?",
                                         (sid,)).fetchone()
                        rno = subj["random_no"] if subj else None
                else:  # in_stock / returned：未领用库存，立即冻结
                    state, sid, rno = "frozen_stock", None, None
                    c.execute("UPDATE kits SET frozen=1 WHERE id=?", (k["id"],))
                c.execute(
                    """INSERT INTO recall_items
                       (recall_id,kit_no,lot_no,center_code,subject_id,random_no,state,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (recall_id, k["kit_no"], k["lot_no"], k["center_code"],
                     sid, rno, state, ts, ts),
                )
            self._audit(c, user["username"], "recall_create",
                        {"recall_no": recall_no, "lot_nos": lot_nos,
                         "reason": reason.strip(), "snapshot_items": len(kits)})
            # 召回是跨中心的风险控制事件：center_code=None 平台级广播。
            # 正文只含中性批号/召回单号/各中心计数，不含兼容关系与 arm。
            center_counts: dict[str, int] = {}
            for k in kits:
                center_counts[k["center_code"]] = center_counts.get(k["center_code"], 0) + 1
            self.bus.publish(
                c, "recall_published", None, "safety",
                {"recall_no": recall_no, "lot_nos": lot_nos,
                 "snapshot_items": len(kits),
                 "centers": [{"center_code": cc, "items": n}
                             for cc, n in sorted(center_counts.items())]})
            return self._recall_view(recall_id, c)

    def list_recalls(self, token: Optional[str]) -> list[dict[str, Any]]:
        user = self._user(token)
        self._require(user, "safety")
        return [self._recall_view(r["id"], self.conn)
                for r in self.conn.execute("SELECT id FROM recalls ORDER BY id").fetchall()]

    def get_recall(self, token: Optional[str], recall_id: int) -> dict[str, Any]:
        """召回单详情：逐盒处置项（中性盒码/随机号/状态），不含治疗组。"""
        user = self._user(token)
        self._require(user, "safety")
        with transaction(self.conn) as c:
            view = self._recall_view(recall_id, c)
            rows = c.execute(
                """SELECT ri.*, rv.voucher_no, rv.status AS voucher_status
                   FROM recall_items ri
                   LEFT JOIN replacement_vouchers rv ON rv.item_id=ri.id
                   WHERE ri.recall_id=? ORDER BY ri.id""",
                (recall_id,),
            ).fetchall()
            view["items"] = [{
                "item_id": r["id"], "kit_no": r["kit_no"], "lot_no": r["lot_no"],
                "center_code": r["center_code"], "random_no": r["random_no"],
                "state": r["state"], "state_label": self.RECALL_ITEM_LABELS[r["state"]],
                "exemption_reason": r["exemption_reason"],
                "exemption_by": r["exemption_by"],
                "reviewed_by": r["reviewed_by"],
                "voucher_no": r["voucher_no"], "voucher_status": r["voucher_status"],
                "updated_at": r["updated_at"],
            } for r in rows]
            return view

    # ---------------------------------------------------- 配药端召回处置
    def pharmacy_recall_items(self, token: Optional[str]) -> list[dict[str, Any]]:
        """配药端只见本站需要处置的项：中性盒码 + 随机编码 + 处置阶段。
        不返回批号、不返回治疗组；已撤销召回的作废项不再展示。"""
        user = self._user(token)
        self._require(user, "pharmacy")
        rows = self.conn.execute(
            """SELECT ri.id, ri.kit_no, ri.random_no, ri.state, ri.updated_at,
                      ri.exemption_reason, r.recall_no,
                      rv.voucher_no, rv.status AS voucher_status
               FROM recall_items ri
               JOIN recalls r ON r.id=ri.recall_id
               LEFT JOIN replacement_vouchers rv ON rv.item_id=ri.id
               WHERE ri.center_code=? AND r.status='active' AND ri.state NOT IN ('frozen_stock','void')
               ORDER BY ri.id""",
            (user["center_code"],),
        ).fetchall()
        return [{
            "item_id": r["id"], "recall_no": r["recall_no"],
            "kit_no": r["kit_no"], "random_no": r["random_no"],
            "state": r["state"], "state_label": self.RECALL_ITEM_LABELS[r["state"]],
            "voucher_no": r["voucher_no"], "voucher_status": r["voucher_status"],
            "exemption_reason": r["exemption_reason"],
            "updated_at": r["updated_at"],
        } for r in rows]

    def _pharm_recall_item(self, c: sqlite3.Connection, item_id: int,
                           user: sqlite3.Row) -> sqlite3.Row:
        it = c.execute(
            """SELECT ri.*, r.status AS recall_status, r.recall_no
               FROM recall_items ri JOIN recalls r ON r.id=ri.recall_id
               WHERE ri.id=?""",
            (item_id,),
        ).fetchone()
        if not it or it["center_code"] != user["center_code"]:
            raise ServiceError("RECALL_ITEM_NOT_FOUND", "处置项不存在", 404)
        return it

    def _item_view(self, c: sqlite3.Connection, item_id: int) -> dict[str, Any]:
        r = c.execute(
            """SELECT ri.id, ri.kit_no, ri.random_no, ri.state, ri.updated_at,
                      r.recall_no, rv.voucher_no, rv.status AS voucher_status
               FROM recall_items ri
               JOIN recalls r ON r.id=ri.recall_id
               LEFT JOIN replacement_vouchers rv ON rv.item_id=ri.id
               WHERE ri.id=?""",
            (item_id,),
        ).fetchone()
        return {
            "item_id": r["id"], "recall_no": r["recall_no"],
            "kit_no": r["kit_no"], "random_no": r["random_no"],
            "state": r["state"], "state_label": self.RECALL_ITEM_LABELS[r["state"]],
            "voucher_no": r["voucher_no"], "voucher_status": r["voucher_status"],
            "updated_at": r["updated_at"],
        }

    def _set_item_state(self, c: sqlite3.Connection, item_id: int,
                        from_states: tuple[str, ...], to_state: str) -> None:
        """条件状态推进：非法/逆向跳转统一冲突，并发下只有一个事务能推进。"""
        cur = c.execute(
            f"UPDATE recall_items SET state=?, updated_at=? WHERE id=? AND state IN ({','.join('?' * len(from_states))})",
            (to_state, now(), item_id, *from_states),
        )
        if cur.rowcount != 1:
            raise self._recall_conflict()

    def recover_item(self, token: Optional[str], item_id: int,
                     kit_no: str) -> dict[str, Any]:
        """药房扫描回收实物：pending → recovered。
        豁免路径（replaceable 但旧盒仍在对象手中）允许补扫码回收实物，状态保持
        replaceable；扫码盒码必须与快照记录一致；重复回收幂等，不重复记流水。"""
        user = self._user(token)
        self._require(user, "pharmacy")
        with transaction(self.conn) as c:
            it = self._pharm_recall_item(c, item_id, user)
            if it["recall_status"] != "active":
                raise self._recall_conflict("召回单已结束，不能再登记回收")
            if kit_no != it["kit_no"]:
                raise ServiceError("RECALL_KIT_MISMATCH", "扫描药盒与待回收记录不符", 409)
            if it["state"] in ("recovered", "redeemed"):
                return self._item_view(c, item_id)  # 重复回收：幂等
            if it["state"] not in ("pending", "replaceable"):
                raise self._recall_conflict()
            kit = c.execute("SELECT * FROM kits WHERE kit_no=?", (it["kit_no"],)).fetchone()
            if not kit:
                raise ServiceError("KIT_NOT_FOUND", "药盒不存在", 404)
            if kit["status"] == "dispensed":
                # 正常路径：从持有人处收回，同时冻结，禁止再入库
                cur = c.execute(
                    """UPDATE kits SET status='returned', holder_subject_id=NULL, frozen=1
                       WHERE id=? AND status='dispensed'""",
                    (kit["id"],),
                )
                if cur.rowcount != 1:
                    raise self._recall_conflict()
                c.execute(
                    """INSERT INTO kit_events
                       (kit_no,event_type,subject_id,random_no,lot_no,lot_switched,actor,note,created_at)
                       VALUES(?, 'return', ?,?,?,0,?,?,?)""",
                    (kit["kit_no"], it["subject_id"], it["random_no"], kit["lot_no"],
                     user["username"], "召回回收", now()),
                )
            elif kit["status"] == "returned":
                # 已先走普通退药回到药房：只补冻结，不重复记流水（避免去向流水失衡）
                c.execute("UPDATE kits SET frozen=1 WHERE id=?", (kit["id"],))
            else:
                raise self._recall_conflict("药盒当前不在受试者手中，状态异常")
            if it["state"] == "pending":
                self._set_item_state(c, item_id, ("pending",), "recovered")
            self._audit(c, user["username"], "recall_recover",
                        {"recall_no": it["recall_no"], "kit_no": it["kit_no"],
                         "random_no": it["random_no"]})
            return self._item_view(c, item_id)

    def register_exemption(self, token: Optional[str], item_id: int,
                           reason: str) -> dict[str, Any]:
        """登记医疗豁免：pending → exempt_pending，等待风险控制复核。"""
        user = self._user(token)
        self._require(user, "pharmacy")
        if not reason or not reason.strip():
            raise ServiceError("REASON_REQUIRED", "医疗豁免必须填写原因", 422)
        with transaction(self.conn) as c:
            it = self._pharm_recall_item(c, item_id, user)
            if it["recall_status"] != "active":
                raise self._recall_conflict("召回单已结束，不能再登记豁免")
            if it["state"] == "exempt_pending":
                return self._item_view(c, item_id)  # 重复登记：幂等
            if it["state"] != "pending":
                raise self._recall_conflict()
            self._set_item_state(c, item_id, ("pending",), "exempt_pending")
            c.execute(
                "UPDATE recall_items SET exemption_reason=?, exemption_by=?, exemption_at=? WHERE id=?",
                (reason.strip(), user["username"], now(), item_id),
            )
            self._audit(c, user["username"], "recall_exempt",
                        {"recall_no": it["recall_no"], "random_no": it["random_no"],
                         "reason": reason.strip()})
            return self._item_view(c, item_id)

    def review_exemption(self, token: Optional[str], item_id: int,
                         approve: bool) -> dict[str, Any]:
        """风险控制复核豁免：批准 → replaceable（自动签发一次性替换凭证）；
        驳回 → pending（这是设计内的合法回退，其余逆向跳转一律冲突）。"""
        user = self._user(token)
        self._require(user, "safety")
        with transaction(self.conn) as c:
            it = c.execute(
                """SELECT ri.*, r.status AS recall_status, r.recall_no
                   FROM recall_items ri JOIN recalls r ON r.id=ri.recall_id
                   WHERE ri.id=?""",
                (item_id,),
            ).fetchone()
            if not it:
                raise ServiceError("RECALL_ITEM_NOT_FOUND", "处置项不存在", 404)
            if it["recall_status"] != "active":
                raise self._recall_conflict("召回单已结束，不能复核")
            if it["state"] != "exempt_pending":
                raise self._recall_conflict()
            c.execute(
                "UPDATE recall_items SET reviewed_by=?, reviewed_at=? WHERE id=?",
                (user["username"], now(), item_id),
            )
            if approve:
                self._set_item_state(c, item_id, ("exempt_pending",), "replaceable")
                voucher = self._issue_voucher_row(c, it, user["username"])
                self._audit(c, user["username"], "recall_exempt_approve",
                            {"recall_no": it["recall_no"], "random_no": it["random_no"],
                             "voucher_no": voucher["voucher_no"]})
            else:
                self._set_item_state(c, item_id, ("exempt_pending",), "pending")
                self._audit(c, user["username"], "recall_exempt_reject",
                            {"recall_no": it["recall_no"], "random_no": it["random_no"]})
            return self._item_view(c, item_id)

    def _issue_voucher_row(self, c: sqlite3.Connection, item: sqlite3.Row,
                           actor: str) -> sqlite3.Row:
        """签发一次性替换凭证。UNIQUE(recall_id, subject_id) 与 UNIQUE(item_id)
        双保险：同一对象对同一召回单最多一张凭证。"""
        existing = c.execute(
            "SELECT * FROM replacement_vouchers WHERE item_id=?", (item["id"],)
        ).fetchone()
        if existing:
            return existing
        seq = c.execute("SELECT COUNT(*) n FROM replacement_vouchers").fetchone()["n"] + 1
        voucher_no = f"RV-{seq:04d}"
        c.execute(
            """INSERT INTO replacement_vouchers
               (voucher_no,recall_id,item_id,subject_id,random_no,center_code,status,issued_by,issued_at)
               VALUES(?,?,?,?,?,?,'issued',?,?)""",
            (voucher_no, item["recall_id"], item["id"], item["subject_id"],
             item["random_no"], item["center_code"], actor, now()),
        )
        return c.execute(
            "SELECT * FROM replacement_vouchers WHERE voucher_no=?", (voucher_no,)
        ).fetchone()

    def issue_voucher(self, token: Optional[str], item_id: int) -> dict[str, Any]:
        """回收完成后签发替换凭证：recovered → replaceable。
        重复签发幂等返回同一张凭证。"""
        user = self._user(token)
        self._require(user, "pharmacy")
        with transaction(self.conn) as c:
            it = self._pharm_recall_item(c, item_id, user)
            if it["recall_status"] != "active":
                raise self._recall_conflict("召回单已结束，不能签发凭证")
            if it["state"] in ("replaceable", "redeemed"):
                return self._item_view(c, item_id)  # 已签发：幂等
            if it["state"] != "recovered":
                raise self._recall_conflict("须先扫描回收实物才能取得替换资格")
            self._set_item_state(c, item_id, ("recovered",), "replaceable")
            voucher = self._issue_voucher_row(c, it, user["username"])
            self._audit(c, user["username"], "recall_voucher_issue",
                        {"recall_no": it["recall_no"], "random_no": it["random_no"],
                         "voucher_no": voucher["voucher_no"]})
            return self._item_view(c, item_id)

    def _voucher_receipt(self, v: sqlite3.Row, already: bool) -> dict[str, Any]:
        return {
            "voucher_no": v["voucher_no"], "random_no": v["random_no"],
            "status": v["status"], "kit_no": v["redeemed_kit_no"],
            "redeemed_at": v["redeemed_at"], "redeemed_by": v["redeemed_by"],
            "already_redeemed": already,
        }

    def redeem_voucher(self, token: Optional[str], voucher_no: str,
                       kit_no: Optional[str] = None) -> dict[str, Any]:
        """核销一次性替换凭证：从**未被召回**的批号中取兼容包装发给原对象。

        - 同一对象对同一召回单最多核销一次（数据库唯一约束兜底）；
        - 条件 UPDATE ... WHERE status='issued'：两个配药站同时核销同一凭证，
          只有一个事务完成发放，另一个读到已核销结果——双方得到同一稳定回执；
        - 重复核销幂等返回同一回执，绝不双重发放；
        - 核销对象当前不得持有药盒（豁免路径须先完成旧盒回收）。
        """
        user = self._user(token)
        self._require(user, "pharmacy")
        with transaction(self.conn) as c:
            v = c.execute(
                """SELECT rv.*, r.status AS recall_status, r.recall_no AS recall_no
                   FROM replacement_vouchers rv JOIN recalls r ON r.id=rv.recall_id
                   WHERE rv.voucher_no=?""",
                (voucher_no,),
            ).fetchone()
            if not v or v["center_code"] != user["center_code"]:
                raise ServiceError("VOUCHER_NOT_FOUND", "替换凭证不存在", 404)
            if v["status"] == "redeemed":
                return self._voucher_receipt(v, already=True)  # 幂等/并发败者同结果
            if v["status"] == "void" or v["recall_status"] != "active":
                raise ServiceError("VOUCHER_VOID", "替换凭证已作废", 409)

            held = c.execute(
                "SELECT kit_no FROM kits WHERE holder_subject_id=? AND status='dispensed'",
                (v["subject_id"],),
            ).fetchone()
            if held:
                raise ServiceError(
                    "SUBJECT_HOLDS_KIT",
                    "该对象尚有在持药盒，须先完成召回回收再核销替换", 409)

            s = c.execute("SELECT * FROM subjects WHERE id=?", (v["subject_id"],)).fetchone()
            if not s or s["withdrawn"]:
                raise ServiceError("SUBJECT_WITHDRAWN", "受试者已退出，不能发放替换", 409)
            arm = s["arm"]  # 仅内部匹配，绝不外泄
            excluded = self._active_recall_lots(c)  # 未被召回批次之外一律排除

            if kit_no:
                kit = c.execute("SELECT * FROM kits WHERE kit_no=?", (kit_no,)).fetchone()
                if (not kit or kit["center_code"] != user["center_code"]
                        or kit["status"] != "in_stock" or kit["frozen"]
                        or kit["lot_no"] in excluded or kit["arm"] != arm):
                    raise ServiceError("KIT_NOT_AVAILABLE", "该药盒当前不可领取", 409)
                chosen = kit
            else:
                chosen = self._pick_kit(c, user["center_code"], arm, excluded)
                if chosen is None:
                    raise ServiceError(
                        "NO_COMPATIBLE_KIT",
                        "未被召回批次中暂无兼容包装，请联系管理员调拨", 409)

            # 原子核销：只有 issued 能转 redeemed，并发下只有一个事务成功
            cur = c.execute(
                """UPDATE replacement_vouchers
                   SET status='redeemed', redeemed_at=?, redeemed_by=?, redeemed_kit_no=?
                   WHERE id=? AND status='issued'""",
                (now(), user["username"], chosen["kit_no"], v["id"]),
            )
            if cur.rowcount != 1:
                v2 = c.execute(
                    "SELECT * FROM replacement_vouchers WHERE id=?", (v["id"],)
                ).fetchone()
                return self._voucher_receipt(v2, already=True)
            cur = c.execute(
                """UPDATE kits SET status='dispensed', holder_subject_id=?
                   WHERE id=? AND status='in_stock' AND frozen=0 AND holder_subject_id IS NULL""",
                (v["subject_id"], chosen["id"]),
            )
            if cur.rowcount != 1:
                raise ServiceError("KIT_TAKEN", "药盒刚被他人领取，请重试", 409)
            switched = self._is_switched(c, user["center_code"], chosen["lot_no"], arm)
            c.execute(
                """INSERT INTO kit_events
                   (kit_no,event_type,subject_id,random_no,lot_no,lot_switched,actor,note,created_at)
                   VALUES(?, 'dispense', ?,?,?,?,?,?,?)""",
                (chosen["kit_no"], v["subject_id"], v["random_no"], chosen["lot_no"],
                 int(switched), user["username"], "召回替换发放", now()),
            )
            self._set_item_state(c, v["item_id"], ("replaceable",), "redeemed")
            self.bus.publish(
                c, "dispensed", user["center_code"], "pharmacy",
                {"random_no": v["random_no"], "kit_no": chosen["kit_no"],
                 "lot_no": chosen["lot_no"], "context": "recall_replacement",
                 "recall_no": v["recall_no"]})
            self._audit(c, user["username"], "recall_redeem",
                        {"recall_no": v["recall_no"], "voucher_no": voucher_no,
                         "random_no": v["random_no"], "kit_no": chosen["kit_no"],
                         "lot_no": chosen["lot_no"]})
            v2 = c.execute(
                "SELECT * FROM replacement_vouchers WHERE id=?", (v["id"],)
            ).fetchone()
            return self._voucher_receipt(v2, already=False)

    # ---------------------------------------------------- 关闭 / 撤销 / 解冻
    def close_recall(self, token: Optional[str], recall_id: int) -> dict[str, Any]:
        """关闭召回单：必须先清空全部未决项（pending/recovered/exempt_pending/
        replaceable）。冻结库存保持冻结，不随关闭恢复。重复关闭幂等。"""
        user = self._user(token)
        self._require(user, "safety")
        with transaction(self.conn) as c:
            r = self._get_recall(c, recall_id)
            if r["status"] == "closed":
                return self._recall_view(recall_id, c)  # 幂等
            if r["status"] == "revoked":
                raise self._recall_conflict("已撤销的召回单不能关闭")
            open_n = c.execute(
                f"""SELECT COUNT(*) n FROM recall_items
                    WHERE recall_id=? AND state IN ({','.join('?' * len(self.RECALL_OPEN_STATES))})""",
                (recall_id, *self.RECALL_OPEN_STATES),
            ).fetchone()["n"]
            if open_n:
                raise ServiceError(
                    "RECALL_OPEN_ITEMS",
                    f"还有 {open_n} 个未决处置项，清空后才能关闭", 409)
            cur = c.execute(
                "UPDATE recalls SET status='closed', closed_at=?, closed_by=? WHERE id=? AND status='active'",
                (now(), user["username"], recall_id),
            )
            if cur.rowcount != 1:
                raise self._recall_conflict()
            # 兜底：本单全部快照盒保持冻结（在持/在库/已回收一律隔离，不随关闭回流）
            c.execute(
                """UPDATE kits SET frozen=1 WHERE kit_no IN
                   (SELECT kit_no FROM recall_items WHERE recall_id=?)""",
                (recall_id,),
            )
            self._audit(c, user["username"], "recall_close", {"recall_no": r["recall_no"]})
            return self._recall_view(recall_id, c)

    def revoke_recall(self, token: Optional[str], recall_id: int,
                      reason: str) -> dict[str, Any]:
        """撤销召回单：仅当尚未发生任何替换核销；必须填写原因。
        未决项与未核销凭证作废；**冻结库存不自动恢复**（防止误恢复），
        需安全管理员逐盒质检解冻。重复撤销幂等；已关闭/已核销的召回不可撤销。"""
        user = self._user(token)
        self._require(user, "safety")
        if not reason or not reason.strip():
            raise ServiceError("REASON_REQUIRED", "撤销召回必须填写原因", 422)
        with transaction(self.conn) as c:
            r = self._get_recall(c, recall_id)
            if r["status"] == "revoked":
                return self._recall_view(recall_id, c)  # 幂等
            if r["status"] == "closed":
                raise self._recall_conflict("已关闭的召回单不能撤销")
            redeemed = c.execute(
                "SELECT COUNT(*) n FROM recall_items WHERE recall_id=? AND state='redeemed'",
                (recall_id,),
            ).fetchone()["n"]
            if redeemed:
                raise ServiceError(
                    "RECALL_HAS_REDEEMED",
                    "已发生替换核销的召回只能关闭，不能撤销", 409)
            cur = c.execute(
                """UPDATE recalls SET status='revoked', revoked_at=?, revoked_by=?, revoke_reason=?
                   WHERE id=? AND status='active'""",
                (now(), user["username"], reason.strip(), recall_id),
            )
            if cur.rowcount != 1:
                raise self._recall_conflict()
            c.execute(
                f"""UPDATE recall_items SET state='void', updated_at=?
                    WHERE recall_id=? AND state IN ({','.join('?' * len(self.RECALL_OPEN_STATES))})""",
                (now(), recall_id, *self.RECALL_OPEN_STATES),
            )
            c.execute(
                "UPDATE replacement_vouchers SET status='void' WHERE recall_id=? AND status='issued'",
                (recall_id,),
            )
            # 冻结库存保持冻结（不自动恢复，防止误恢复）；其余快照盒同样兜底隔离
            c.execute(
                """UPDATE kits SET frozen=1 WHERE kit_no IN
                   (SELECT kit_no FROM recall_items WHERE recall_id=?)""",
                (recall_id,),
            )
            self._audit(c, user["username"], "recall_revoke",
                        {"recall_no": r["recall_no"], "reason": reason.strip()})
            return self._recall_view(recall_id, c)

    def unfreeze_kit(self, token: Optional[str], kit_no: str) -> dict[str, Any]:
        """安全管理员逐盒质检解冻。召回单仍进行中时禁止解冻；
        除此之外（已关闭/已撤销/人工冻结）显式放行，全程审计。"""
        user = self._user(token)
        self._require(user, "safety")
        with transaction(self.conn) as c:
            kit = c.execute("SELECT * FROM kits WHERE kit_no=?", (kit_no,)).fetchone()
            if not kit:
                raise ServiceError("KIT_NOT_FOUND", "药盒不存在", 404)
            if not kit["frozen"]:
                return {"kit_no": kit_no, "frozen": False}  # 幂等
            active_item = c.execute(
                """SELECT 1 FROM recall_items ri JOIN recalls r ON r.id=ri.recall_id
                   WHERE ri.kit_no=? AND r.status='active'""",
                (kit_no,),
            ).fetchone()
            if active_item:
                raise self._recall_conflict("召回单仍进行中，不能解冻该药盒")
            c.execute("UPDATE kits SET frozen=0 WHERE id=? AND frozen=1", (kit["id"],))
            self._audit(c, user["username"], "recall_unfreeze", {"kit_no": kit_no})
            return {"kit_no": kit_no, "frozen": False}

    # ---------------------------------------------------- 研究端召回通知
    def investigator_recall_notices(self, token: Optional[str]) -> list[dict[str, Any]]:
        """研究端只见：是否需要联系受试者 + 当前处置阶段。
        不含盒码去向细节之外的任何字段，更不含批号/治疗组。"""
        user = self._user(token)
        self._require(user, "investigator")
        rows = self.conn.execute(
            """SELECT s.subject_code, ri.random_no, ri.state
               FROM recall_items ri
               JOIN recalls r ON r.id=ri.recall_id
               JOIN subjects s ON s.id=ri.subject_id
               WHERE r.status='active' AND ri.center_code=? AND ri.subject_id IS NOT NULL
               ORDER BY ri.id""",
            (user["center_code"],),
        ).fetchall()
        return [{
            "subject_code": r["subject_code"],
            "random_no": r["random_no"],
            "needs_contact": r["state"] == "pending",
            "stage": self.RECALL_ITEM_LABELS[r["state"]],
        } for r in rows]

    # ------------------------------------------------------------ 不变量自检
    def check_invariants(self) -> dict[str, Any]:
        """供测试/巡检调用：校验随机号唯一与药盒去向守恒。"""
        c = self.conn
        problems: list[str] = []

        dup_no = c.execute(
            "SELECT random_no, COUNT(*) n FROM subjects WHERE random_no IS NOT NULL GROUP BY random_no HAVING n>1"
        ).fetchall()
        if dup_no:
            problems.append(f"随机号重复: {[dict(r) for r in dup_no]}")

        dup_subject = c.execute(
            "SELECT subject_code, COUNT(*) n FROM subjects GROUP BY subject_code HAVING n>1"
        ).fetchall()
        if dup_subject:
            problems.append("受试者编码重复")

        # 守恒 1：每个药盒的 dispensed 次数 - return 次数 ∈ {0,1}，
        # 且 =1 当且仅当当前 status='dispensed' 且有持有人
        rows = c.execute("SELECT kit_no, status, holder_subject_id FROM kits").fetchall()
        for k in rows:
            agg = c.execute(
                """SELECT
                   SUM(event_type='dispense') d, SUM(event_type='return') r
                   FROM kit_events WHERE kit_no=?""", (k["kit_no"],)).fetchone()
            d, r = agg["d"] or 0, agg["r"] or 0
            if d - r not in (0, 1):
                problems.append(f"药盒 {k['kit_no']} 流水不平衡 d={d} r={r}")
            if d - r == 1:
                if k["status"] != "dispensed" or k["holder_subject_id"] is None:
                    problems.append(f"药盒 {k['kit_no']} 流水显示在外但状态为 {k['status']}")
            else:
                if k["status"] == "dispensed" or k["holder_subject_id"] is not None:
                    problems.append(f"药盒 {k['kit_no']} 无未结流水却显示发放中")

        # 守恒 2：一个受试者最多持有一盒
        multi = c.execute(
            """SELECT holder_subject_id, COUNT(*) n FROM kits
               WHERE status='dispensed' GROUP BY holder_subject_id HAVING n>1"""
        ).fetchall()
        if multi:
            problems.append("存在受试者同时持有多盒")

        # 守恒 3：每盒的持有人与其流水末次 dispense 指向的受试者一致
        for k in c.execute("SELECT * FROM kits WHERE status='dispensed'").fetchall():
            last = c.execute(
                "SELECT subject_id FROM kit_events WHERE kit_no=? ORDER BY id DESC LIMIT 1",
                (k["kit_no"],)).fetchone()
            if not last or last["subject_id"] != k["holder_subject_id"]:
                problems.append(f"药盒 {k['kit_no']} 持有人与流水不一致")

        # 召回守恒 1：同一对象对同一召回单最多一张已核销凭证（唯一约束兜底，此处巡检）
        multi_v = c.execute(
            """SELECT recall_id, subject_id, COUNT(*) n FROM replacement_vouchers
               WHERE status='redeemed' GROUP BY recall_id, subject_id HAVING n>1"""
        ).fetchall()
        if multi_v:
            problems.append("存在同一对象对同一召回单核销多张凭证")

        # 召回守恒 2：已核销凭证 ↔ 替换盒确实发给该对象、处置项已核销、且替换盒不来自本召回批号
        for v in c.execute("SELECT * FROM replacement_vouchers WHERE status='redeemed'").fetchall():
            kit = c.execute("SELECT * FROM kits WHERE kit_no=?",
                            (v["redeemed_kit_no"],)).fetchone()
            if not kit or kit["status"] != "dispensed" or kit["holder_subject_id"] != v["subject_id"]:
                problems.append(f"凭证 {v['voucher_no']} 已核销但替换盒去向异常")
            elif kit["lot_no"] in {
                r["lot_no"] for r in c.execute(
                    "SELECT lot_no FROM recall_lots WHERE recall_id=?", (v["recall_id"],)).fetchall()
            }:
                problems.append(f"凭证 {v['voucher_no']} 的替换盒来自被召回批号")
            item = c.execute("SELECT state FROM recall_items WHERE id=?",
                             (v["item_id"],)).fetchone()
            if not item or item["state"] != "redeemed":
                problems.append(f"凭证 {v['voucher_no']} 已核销但处置项状态为 {item['state'] if item else '缺失'}")

        # 召回守恒 3：可替换/已核销项必须有凭证；进行中召回的冻结库存必须保持 frozen=1
        for it in c.execute("SELECT * FROM recall_items").fetchall():
            if it["state"] in ("replaceable", "redeemed"):
                v = c.execute(
                    "SELECT status FROM replacement_vouchers WHERE item_id=?",
                    (it["id"],)).fetchone()
                if not v:
                    problems.append(f"处置项 {it['id']} 处于 {it['state']} 但无替换凭证")
            if it["state"] == "frozen_stock":
                k = c.execute("SELECT frozen FROM kits WHERE kit_no=?",
                              (it["kit_no"],)).fetchone()
                r = c.execute("SELECT status FROM recalls WHERE id=?",
                              (it["recall_id"],)).fetchone()
                if r and r["status"] == "active" and (not k or not k["frozen"]):
                    problems.append(f"召回进行中但冻结库存 {it['kit_no']} 被解冻")

        # 平台事件出站队列守恒：不可变事件链（序号/哈希链/正文摘要/签名）
        # 与投递引用完整性。任何对历史事件的回写都会在此暴露。
        ev_report = self.bus.check_integrity()
        if not ev_report["ok"]:
            problems.extend(ev_report["problems"])
        # 队列守恒：同 (订阅,事件) 唯一已由 UNIQUE 约束；这里校验事件序号与投递一致
        bad_seq = c.execute(
            """SELECT d.id FROM event_deliveries d
               JOIN platform_events e ON e.id=d.event_id
               WHERE d.event_seq != e.seq"""
        ).fetchall()
        if bad_seq:
            problems.append(f"{len(bad_seq)} 条投递的事件序号与事件表不一致")

        return {"ok": not problems, "problems": problems,
                "platform_events": ev_report["events"]}

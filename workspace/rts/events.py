"""平台事件签名出站队列。

四条主线
--------
1. 不可变事件（EventBus）：已提交的业务事务（入组/发药/退药/召回/揭盲）
   在**同一数据库事务内**先写 platform_events：全平台单调 seq、哈希链 prev_digest、
   规范正文 body_digest、签发瞬间的订阅配置版本 sub_version、Ed25519 签名。
   历史事件只追加、永不回写（check_integrity 与库外 CLI 都可证伪篡改）。
2. 订阅（SubscriptionService）：安全管理员登记按 事件种类 × 中心 × 角色
   过滤的端点；同一 URL 重复订阅返回稳定结果；暂停/恢复使全局订阅配置版本自增。
3. 出站投递（DeliveryWorker）：后台队列异步投递；租约（leased）保证两个
   worker 同时只有一个持有有效租约，租约过期后另一 worker 可接管；
   失败按指数退避重试，达上限进死信；安全管理员可逐条重放，重放不改原事件正文、
   不产生新业务事件；同订阅严格按 seq 顺序，前序未终结不投后序。
4. 库外可验证：公布的验证材料（公钥集 + 链锚点）+ 独立 CLI（verify_events.py）
   即可核对序号连续、正文摘要、签发版本与签名，无需访问本数据库。

盲态/密钥边界（与 service.py 一致）
-----------------------------------
- 事件正文、投递日志、错误响应绝不含 arm（治疗组/分配臂）、批号兼容关系、
  兼容转用标记或订阅 HMAC 密钥；投递失败只记稳定错误码（非原始异常文本）。
- 药房角色不能调用本模块任何管理/审计接口，也读不到密钥或其他中心事件；
  研究端只能看本中心/本人被授权的事件摘要。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from .db import transaction

# ---------------------------------------------------------------- 常量

EVENT_KINDS = (
    "enrolled",          # 入组（取得随机号）
    "dispensed",         # 发药（含召回替换发放）
    "returned",          # 退药
    "recall_published",  # 批次召回单发布
    "unblinded",         # 揭盲（正常双人 / 应急单受试者）
)
ACTOR_ROLES = ("investigator", "pharmacy", "safety", "system")

EVENT_ALG = "RTS-PLATFORM-EVENT-ED25519-SHA256/v1"
DELIVERY_ALG = "RTS-DELIVERY-HMAC-SHA256/v1"

# 退避（秒）：第 n 次失败后取 BACKOFF[min(n-1, 末档)]
DEFAULT_BACKOFF = (2, 5, 15, 40, 90)
DEFAULT_MAX_ATTEMPTS = 6            # 首发 + 5 次重试，仍失败即死信
DEFAULT_LEASE_SECONDS = 30

# 事件正文/投递日志中永远禁止出现的键（盲态与订阅密钥边界）
_FORBIDDEN_BODY_KEYS = {"arm", "lot_switched", "compat_arms", "secret", "secret_hash",
                        "secret_store"}

# 服务端混淆投递密钥用的固定 pepper（演示平台；生产应由部署环境注入）
_SECRET_PEPPER = b"rts-event-delivery-pepper-v1"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


class EventError(Exception):
    def __init__(self, code: str, message: str, http: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http = http


# -------------------------------------------------------- 规范 JSON 与摘要

def canonical_json(obj: Any) -> str:
    """确定性 JSON：键排序、无空白、非 ASCII 不转义。
    所有摘要/签名都基于它，库外按同一规则重算即可核对。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_hex(data: "str | bytes") -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _all_keys(obj: Any) -> set[str]:
    """递归收集正文里出现过的全部键名，用于盲态/密钥护栏。"""
    found: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            found.add(k)
            found |= _all_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            found |= _all_keys(v)
    return found


# -------------------------------------------------------- 投递密钥的混淆存储

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def obfuscate_secret(secret: str) -> str:
    """可逆混淆（非加密学机密性，仅避免明文落盘）。机密性靠"接口/日志零回显"。"""
    stream = hashlib.sha256(_SECRET_PEPPER).digest()
    # 用计数器扩展密钥流，长度无上限
    out = bytearray()
    raw = secret.encode()
    counter = 0
    while len(out) < len(raw):
        block = hashlib.sha256(_SECRET_PEPPER + counter.to_bytes(4, "big")).digest()
        out.extend(block)
        counter += 1
    return base64.b64encode(_xor_bytes(raw, bytes(out[:len(raw)]))).decode()


def deobfuscate_secret(stored: str) -> str:
    raw = base64.b64decode(stored.encode())
    out = bytearray()
    counter = 0
    while len(out) < len(raw):
        out.extend(hashlib.sha256(_SECRET_PEPPER + counter.to_bytes(4, "big")).digest())
        counter += 1
    return _xor_bytes(raw, bytes(out[:len(raw)])).decode()


# ================================================================== 签发密钥

class KeyStore:
    """Ed25519 签发密钥的持久化、轮换与公布材料。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    @staticmethod
    def _key_id(public_pem: str) -> str:
        return hashlib.sha256(public_pem.encode()).hexdigest()[:32]

    def ensure_initial_key(self) -> None:
        """首次使用/老库升级时生成一把活动密钥（幂等）。"""
        row = self.conn.execute("SELECT COUNT(*) n FROM event_signing_keys").fetchone()
        if row["n"] == 0:
            self.rotate(actor="system")

    def active_key(self, c: sqlite3.Connection) -> sqlite3.Row:
        row = c.execute("SELECT * FROM event_signing_keys WHERE active=1").fetchone()
        if not row:
            raise EventError("NO_SIGNING_KEY", "平台签发密钥尚未初始化", 500)
        return row

    def rotate(self, actor: str = "safety") -> dict[str, Any]:
        """换钥：旧密钥转 inactive（保留验旧事件），新密钥 active；订阅版本自增。"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        key_id = self._key_id(pub_pem)
        with transaction(self.conn) as c:
            version = c.execute(
                "SELECT COALESCE(MAX(version),0) m FROM event_signing_keys"
            ).fetchone()["m"] + 1
            c.execute("UPDATE event_signing_keys SET active=0, rotated_at=? WHERE active=1",
                      (now(),))
            c.execute(
                """INSERT INTO event_signing_keys
                   (id,version,public_pem,private_pem,active,created_at)
                   VALUES(?,?,?,?,1,?)""",
                (key_id, version, pub_pem, priv_pem, now()),
            )
            bump_subscription_version(c)
        return {"key_id": key_id, "version": version, "active": True}

    def public_materials(self) -> dict[str, Any]:
        """公布的验证材料：全部公钥（含已轮换的，用于核对历史）+ 当前链锚点。
        不含任何私钥材料。校验方带外保存后，可在库外核对任意事件包。"""
        rows = self.conn.execute(
            "SELECT id,version,public_pem,active,created_at,rotated_at "
            "FROM event_signing_keys ORDER BY version"
        ).fetchall()
        keys = [{
            "key_id": r["id"], "version": r["version"], "public_pem": r["public_pem"],
            "active": bool(r["active"]), "created_at": r["created_at"],
            "rotated_at": r["rotated_at"],
        } for r in rows]
        head = self.conn.execute(
            "SELECT seq, event_digest FROM platform_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return {
            "event_algorithm": EVENT_ALG,
            "delivery_algorithm": DELIVERY_ALG,
            "keys": keys,
            "active_key_id": next((k["key_id"] for k in keys if k["active"]), None),
            "chain_head": ({"seq": head["seq"], "event_digest": head["event_digest"]}
                           if head else None),
            "released_at": now(),
        }

    @staticmethod
    def load_private_key(pem: str):
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_private_key(pem.encode(), password=None)

    @staticmethod
    def load_public_key(pem: str):
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_public_key(pem.encode())


def bump_subscription_version(c: sqlite3.Connection) -> int:
    """全局订阅配置版本自增：登记/暂停/恢复/换钥都推进，事件包携带签发瞬间值。"""
    c.execute(
        "UPDATE event_state SET subscription_version = subscription_version + 1 WHERE id=1"
    )
    return c.execute(
        "SELECT subscription_version v FROM event_state WHERE id=1"
    ).fetchone()["v"]


# ================================================================== 事件总线

class EventBus:
    """不可变事件的签发、查询与完整性巡检。"""

    def __init__(self, conn: sqlite3.Connection, keys: Optional[KeyStore] = None):
        self.conn = conn
        self.keys = keys or KeyStore(conn)

    def _sign(self, c: sqlite3.Connection, header: dict[str, Any]) -> tuple[str, str]:
        key = self.keys.active_key(c)
        priv = KeyStore.load_private_key(key["private_pem"])
        sig = priv.sign(canonical_json(header).encode())
        return key["id"], base64.b64encode(sig).decode()

    @staticmethod
    def _validate_body(kind: str, actor_role: str, body: dict[str, Any]) -> None:
        if kind not in EVENT_KINDS:
            raise EventError("BAD_EVENT_KIND", f"不支持的事件种类 {kind}", 422)
        if actor_role not in ACTOR_ROLES:
            raise EventError("BAD_ACTOR_ROLE", "事件发起人角色非法", 422)
        if not isinstance(body, dict):
            raise EventError("BAD_EVENT_BODY", "事件正文必须是对象", 422)
        leaked = _FORBIDDEN_BODY_KEYS & _all_keys(body)
        if leaked:
            # 平台内部护栏：任何带盲态/密钥字段的正文一律拒绝签发
            raise EventError("EVENT_BODY_FORBIDDEN",
                             "事件正文包含禁止外发的盲态或密钥字段", 500)

    def publish(self, c: sqlite3.Connection, kind: str,
                center_code: Optional[str], actor_role: str,
                body: dict[str, Any]) -> sqlite3.Row:
        """在**调用方的数据库事务内**写一条不可变事件并 fan-out 投递行。

        必须与业务变更同一事务：业务回滚则事件不发生；业务提交则事件先于一切
        外部投递落盘。返回新事件行。"""
        self._validate_body(kind, actor_role, body)
        sub_version = c.execute(
            "SELECT subscription_version v FROM event_state WHERE id=1"
        ).fetchone()["v"]
        last = c.execute(
            "SELECT seq, event_digest FROM platform_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = (last["seq"] + 1) if last else 1
        prev_digest = last["event_digest"] if last else "GENESIS"
        body_text = canonical_json(body)
        body_digest = sha256_hex(body_text)
        event_id = uuid.uuid4().hex
        ts = now()
        event_digest = sha256_hex(canonical_json({
            "seq": seq, "event_id": event_id, "kind": kind,
            "center_code": center_code, "actor_role": actor_role,
            "body_digest": body_digest, "prev_digest": prev_digest,
            "sub_version": sub_version, "created_at": ts,
        }))
        header = {
            "algorithm": EVENT_ALG,
            "event_id": event_id, "seq": seq, "kind": kind,
            "center_code": center_code, "actor_role": actor_role,
            "body_digest": body_digest, "prev_digest": prev_digest,
            "event_digest": event_digest, "sub_version": sub_version,
            "created_at": ts,
        }
        key_id, signature = self._sign(c, header)
        cur = c.execute(
            """INSERT INTO platform_events
               (event_id,seq,kind,center_code,actor_role,body,body_digest,
                prev_digest,event_digest,sub_version,sign_key_id,signature,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (event_id, seq, kind, center_code, actor_role, body_text, body_digest,
             prev_digest, event_digest, sub_version, key_id, signature, ts),
        )
        self._fanout(c, cur.lastrowid, seq, kind, center_code, actor_role)
        return c.execute("SELECT * FROM platform_events WHERE id=?", (cur.lastrowid,)).fetchone()

    def _fanout(self, c: sqlite3.Connection, event_pk: int, seq: int,
                kind: str, center_code: Optional[str], actor_role: str) -> int:
        """为每个匹配且 active 的订阅建一条 queued 投递。
        UNIQUE(subscription_id,event_id) 兜底：绝不重复投递同一事件。"""
        ts = now()
        subs = c.execute(
            "SELECT * FROM event_subscriptions WHERE status='active'"
        ).fetchall()
        n = 0
        for s in subs:
            if not subscription_matches(s, kind, center_code, actor_role):
                continue
            c.execute(
                """INSERT OR IGNORE INTO event_deliveries
                   (subscription_id,event_id,event_seq,status,next_attempt_at,created_at)
                   VALUES(?, ?,?,'queued', ?,?)""",
                (s["id"], event_pk, seq, ts, ts),
            )
            n += 1
        return n

    # ------------------------------------------------------------ 查询
    def envelope(self, row: sqlite3.Row) -> dict[str, Any]:
        """签名事件包：投递与库外核对的同一形态（自描述、可独立验证）。"""
        return {
            "header": {
                "algorithm": EVENT_ALG,
                "event_id": row["event_id"], "seq": row["seq"],
                "kind": row["kind"], "center_code": row["center_code"],
                "actor_role": row["actor_role"],
                "body_digest": row["body_digest"],
                "prev_digest": row["prev_digest"],
                "event_digest": row["event_digest"],
                "sub_version": row["sub_version"],
                "created_at": row["created_at"],
                "sign_key_id": row["sign_key_id"],
            },
            "body": json.loads(row["body"]),
            "signature": row["signature"],
        }

    def get_by_seq(self, seq: int) -> Optional[dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM platform_events WHERE seq=?", (seq,)
        ).fetchone()
        return self.envelope(row) if row else None

    def get_by_event_id(self, event_id: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM platform_events WHERE event_id=?", (event_id,)
        ).fetchone()
        return self.envelope(row) if row else None

    def list_events(self, limit: int = 100,
                    kinds: Optional[list[str]] = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM platform_events"
        params: list[Any] = []
        if kinds:
            q += " WHERE kind IN (%s)" % ",".join("?" * len(kinds))
            params.extend(kinds)
        q += " ORDER BY seq DESC LIMIT ?"
        params.append(min(limit, 1000))
        return [self.envelope(r) for r in self.conn.execute(q, params).fetchall()]

    # -------------------------------------------------------- 完整性巡检
    def check_integrity(self) -> dict[str, Any]:
        """重算链：序号连续、prev_digest 链接、正文摘要、事件摘要、签名。
        任何对历史事件的回写/删改都会在此暴露。"""
        from cryptography.exceptions import InvalidSignature

        problems: list[str] = []
        key_cache: dict[str, Any] = {}
        prev = "GENESIS"
        expected_seq = 1
        rows = self.conn.execute("SELECT * FROM platform_events ORDER BY seq").fetchall()
        for r in rows:
            if r["seq"] != expected_seq:
                problems.append(f"序号不连续：期望 {expected_seq}，实际 {r['seq']}")
            if r["prev_digest"] != prev:
                problems.append(f"事件 {r['seq']} 哈希链断裂（prev_digest 不符）")
            if sha256_hex(r["body"]) != r["body_digest"]:
                problems.append(f"事件 {r['seq']} 正文摘要不符（正文被改动）")
            recomputed = sha256_hex(canonical_json({
                "seq": r["seq"], "event_id": r["event_id"], "kind": r["kind"],
                "center_code": r["center_code"], "actor_role": r["actor_role"],
                "body_digest": r["body_digest"], "prev_digest": r["prev_digest"],
                "sub_version": r["sub_version"], "created_at": r["created_at"],
            }))
            if recomputed != r["event_digest"]:
                problems.append(f"事件 {r['seq']} 事件摘要不符（头部被改动）")
            if r["sign_key_id"] not in key_cache:
                krow = self.conn.execute(
                    "SELECT public_pem FROM event_signing_keys WHERE id=?",
                    (r["sign_key_id"],),
                ).fetchone()
                if not krow:
                    problems.append(f"事件 {r['seq']} 的签发公钥 {r['sign_key_id']} 缺失")
                    key_cache[r["sign_key_id"]] = None
                else:
                    key_cache[r["sign_key_id"]] = KeyStore.load_public_key(krow["public_pem"])
            pub = key_cache.get(r["sign_key_id"])
            if pub is not None:
                header = {
                    "algorithm": EVENT_ALG,
                    "event_id": r["event_id"], "seq": r["seq"], "kind": r["kind"],
                    "center_code": r["center_code"], "actor_role": r["actor_role"],
                    "body_digest": r["body_digest"], "prev_digest": r["prev_digest"],
                    "event_digest": r["event_digest"], "sub_version": r["sub_version"],
                    "created_at": r["created_at"],
                }
                try:
                    pub.verify(base64.b64decode(r["signature"]),
                               canonical_json(header).encode())
                except InvalidSignature:
                    problems.append(f"事件 {r['seq']} 签名验证失败（非本平台签发或被篡改）")
            prev = r["event_digest"]
            expected_seq += 1
        orphans = self.conn.execute(
            """SELECT d.id FROM event_deliveries d
               LEFT JOIN platform_events e ON e.id=d.event_id
               WHERE e.id IS NULL"""
        ).fetchall()
        if orphans:
            problems.append(f"{len(orphans)} 条投递指向不存在的事件")
        return {"ok": not problems, "problems": problems, "events": len(rows)}


# ================================================================== 订阅过滤

def _load_filter(value: str) -> list[str]:
    try:
        v = json.loads(value)
        return v if isinstance(v, list) else []
    except (TypeError, ValueError):
        return []


def subscription_matches(sub: sqlite3.Row, kind: str,
                         center_code: Optional[str], actor_role: str) -> bool:
    """按 事件种类 × 中心 × 发起人角色 三维过滤；空清单 = 不过滤（全收）。

    全平台事件（center_code 为空，如正常揭盲）不受中心维度限制：
    只按种类/角色匹配——它对所有订阅方都属于平台级事实。"""
    kinds = _load_filter(sub["kind_filter"])
    centers = _load_filter(sub["center_filter"])
    roles = _load_filter(sub["role_filter"])
    if kinds and kind not in kinds:
        return False
    if centers and center_code is not None and center_code not in centers:
        return False
    if roles and actor_role not in roles:
        return False
    return True


# ================================================================== 订阅服务

class SubscriptionService:
    """安全管理员：登记/查看/暂停/恢复订阅、验证材料与换钥。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.keys = KeyStore(conn)
        self.bus = EventBus(conn, self.keys)

    @staticmethod
    def _audit(c: sqlite3.Connection, actor: str, action: str,
               detail: dict[str, Any]) -> None:
        """安全审计留痕。detail 只放标识/版本/计数，绝不放订阅密钥或盲态字段。"""
        c.execute(
            "INSERT INTO audit_log(actor,action,detail,created_at) VALUES(?,?,?,?)",
            (actor, action, canonical_json(detail), now()),
        )

    @staticmethod
    def _secret_hash(secret: str) -> str:
        return hashlib.sha256(secret.encode()).hexdigest()

    def _normalize_filters(self, kinds: Any, centers: Any, roles: Any
                           ) -> tuple[list[str], list[str], list[str]]:
        kinds, centers, roles = kinds or [], centers or [], roles or []
        if not all(isinstance(x, str) for x in (kinds + centers + roles)):
            raise EventError("BAD_FILTER", "过滤项必须是字符串数组", 422)
        bad_kinds = [k for k in kinds if k not in EVENT_KINDS]
        if bad_kinds:
            raise EventError("BAD_FILTER", f"未知事件种类: {','.join(bad_kinds)}", 422)
        bad_roles = [r for r in roles if r not in ("investigator", "pharmacy", "safety")]
        if bad_roles:
            raise EventError("BAD_FILTER", f"未知角色: {','.join(bad_roles)}", 422)
        known_centers = {r["code"] for r in self.conn.execute("SELECT code FROM centers")}
        bad_centers = [c for c in centers if c not in known_centers]
        if bad_centers:
            raise EventError("BAD_FILTER", f"未知中心: {','.join(bad_centers)}", 422)
        return (list(dict.fromkeys(kinds)), list(dict.fromkeys(centers)),
                list(dict.fromkeys(roles)))

    def register(self, actor: str, name: str, endpoint_url: str,
                 kinds: Optional[list[str]] = None,
                 centers: Optional[list[str]] = None,
                 roles: Optional[list[str]] = None) -> dict[str, Any]:
        """登记订阅端点。重复订阅（同 URL）稳定返回既有配置，不重复建、不换密钥。"""
        if not name or not name.strip():
            raise EventError("BAD_NAME", "订阅名称必填", 422)
        if not endpoint_url or not endpoint_url.strip().lower().startswith(
                ("http://", "https://")):
            raise EventError("BAD_ENDPOINT", "端点必须是 http(s) URL", 422)
        kf, cf, rf = self._normalize_filters(kinds, centers, roles)
        with transaction(self.conn) as c:
            url = endpoint_url.strip()
            existing = c.execute(
                "SELECT * FROM event_subscriptions WHERE endpoint_url=?", (url,)
            ).fetchone()
            if existing:
                view = self._view(c, existing)
                view["duplicate"] = True  # 稳定结果：重复订阅不报错也不重发密钥
                return view
            secret = "rtsevt_" + secrets.token_urlsafe(32)
            cur = c.execute(
                """INSERT INTO event_subscriptions
                   (name,endpoint_url,secret_hash,secret_store,kind_filter,center_filter,
                    role_filter,status,version,created_by,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,'active',1,?,?,?)""",
                (name.strip(), url, self._secret_hash(secret), obfuscate_secret(secret),
                 canonical_json(kf), canonical_json(cf), canonical_json(rf),
                 actor, now(), now()),
            )
            sub_id = cur.lastrowid
            sub_version = bump_subscription_version(c)
            self._audit(c, actor, "event_subscription_register", {
                "subscription_id": sub_id, "endpoint_url": url,
                "kinds": kf, "centers": cf, "roles": rf})
            row = c.execute("SELECT * FROM event_subscriptions WHERE id=?", (sub_id,)).fetchone()
            view = self._view(c, row)
            view["secret"] = secret                 # 仅本次响应回显（带外交付）
            view["subscription_version"] = sub_version
            return view

    def _view(self, c: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        """任何视图都不含 secret/secret_hash/secret_store。"""
        stats = c.execute(
            """SELECT
                 SUM(status='queued') queued, SUM(status='leased') leased,
                 SUM(status='sent') sent, SUM(status='dead') dead, COUNT(*) total
               FROM event_deliveries WHERE subscription_id=?""",
            (row["id"],),
        ).fetchone()
        return {
            "id": row["id"], "name": row["name"], "endpoint_url": row["endpoint_url"],
            "kind_filter": _load_filter(row["kind_filter"]),
            "center_filter": _load_filter(row["center_filter"]),
            "role_filter": _load_filter(row["role_filter"]),
            "status": row["status"], "version": row["version"],
            "created_by": row["created_by"], "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "deliveries": {
                "queued": stats["queued"] or 0, "leased": stats["leased"] or 0,
                "sent": stats["sent"] or 0, "dead": stats["dead"] or 0,
                "total": stats["total"] or 0,
            },
        }

    def list_subscriptions(self) -> list[dict[str, Any]]:
        return [self._view(self.conn, r) for r in self.conn.execute(
            "SELECT * FROM event_subscriptions ORDER BY id").fetchall()]

    def get_subscription(self, subscription_id: int) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM event_subscriptions WHERE id=?", (subscription_id,)
        ).fetchone()
        if not row:
            raise EventError("SUBSCRIPTION_NOT_FOUND", "订阅不存在", 404)
        return self._view(self.conn, row)

    def _set_status(self, actor: str, subscription_id: int, status: str) -> dict[str, Any]:
        with transaction(self.conn) as c:
            row = c.execute(
                "SELECT * FROM event_subscriptions WHERE id=?", (subscription_id,)
            ).fetchone()
            if not row:
                raise EventError("SUBSCRIPTION_NOT_FOUND", "订阅不存在", 404)
            if row["status"] != status:
                c.execute(
                    """UPDATE event_subscriptions
                       SET status=?, version=version+1, updated_at=? WHERE id=?""",
                    (status, now(), subscription_id),
                )
                bump_subscription_version(c)
                self._audit(c, actor,
                            "event_subscription_pause" if status == "paused"
                            else "event_subscription_resume",
                            {"subscription_id": subscription_id,
                             "endpoint_url": row["endpoint_url"]})
            row = c.execute("SELECT * FROM event_subscriptions WHERE id=?",
                            (subscription_id,)).fetchone()
            return self._view(c, row)

    def pause(self, actor: str, subscription_id: int) -> dict[str, Any]:
        # 端点停用（暂停）：重复暂停稳定返回当前状态；queued 保留但不被领取
        return self._set_status(actor, subscription_id, "paused")

    def resume(self, actor: str, subscription_id: int) -> dict[str, Any]:
        return self._set_status(actor, subscription_id, "active")

    def rotate_key(self, actor: str) -> dict[str, Any]:
        result = self.keys.rotate(actor=actor)
        with transaction(self.conn) as c:
            self._audit(c, actor, "event_signing_key_rotate",
                        {"key_id": result["key_id"], "version": result["version"]})
        return result

    def materials(self) -> dict[str, Any]:
        return self.keys.public_materials()


# ================================================================== 投递信封 HMAC

def delivery_headers(secret: str, envelope: dict[str, Any],
                     subscription_version: int) -> dict[str, str]:
    """构造投递请求头：事件标识/序号/订阅版本供订阅方去重与代际判断；
    X-RTS-Signature 为整包 HMAC（secret 只在此处使用，绝不写日志/响应）。"""
    h = envelope["header"]
    message = "\n".join([
        DELIVERY_ALG, h["event_id"], str(h["seq"]),
        str(subscription_version), canonical_json(envelope),
    ])
    mac = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-RTS-Event-Id": h["event_id"],
        "X-RTS-Event-Seq": str(h["seq"]),
        "X-RTS-Subscription-Version": str(subscription_version),
        "X-RTS-Delivery-Alg": DELIVERY_ALG,
        "X-RTS-Signature": f"hmac-sha256={mac}",
    }


def verify_delivery_hmac(secret: str, envelope: dict[str, Any],
                         subscription_version: int, signature: str) -> bool:
    """订阅方在库外用持有的共享密钥独立复核投递 HMAC。"""
    prefix = "hmac-sha256="
    if not signature.startswith(prefix):
        return False
    h = envelope["header"]
    message = "\n".join([
        DELIVERY_ALG, h["event_id"], str(h["seq"]),
        str(subscription_version), canonical_json(envelope),
    ])
    mac = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, signature[len(prefix):])


Transport = Callable[[str, dict[str, str], dict[str, Any]], int]


def httpx_transport(endpoint_url: str, headers: dict[str, str],
                    envelope: dict[str, Any], timeout: float = 10.0) -> int:
    import httpx
    r = httpx.post(endpoint_url, headers=headers, json=envelope, timeout=timeout)
    return r.status_code


# 进程级传输覆盖点：测试/特殊部署可注入假传输（如把出站包落到本地接收器）。
# None = 使用真实 httpx。后台线程与 API 内重放都经此解析。
_TRANSPORT_OVERRIDE: Optional[Transport] = None


def set_transport_override(fn: Optional[Transport]) -> None:
    global _TRANSPORT_OVERRIDE
    _TRANSPORT_OVERRIDE = fn


def resolve_transport() -> Transport:
    return _TRANSPORT_OVERRIDE or httpx_transport


def classify_transport_error(exc: BaseException) -> str:
    """传输异常 → 稳定错误码：原始异常文本绝不入日志/响应（可能含 URL/密钥痕迹）。"""
    table = {
        "ConnectError": "ENDPOINT_CONNECT_FAILED",
        "ConnectTimeout": "ENDPOINT_TIMEOUT",
        "ReadTimeout": "ENDPOINT_TIMEOUT",
        "WriteTimeout": "ENDPOINT_TIMEOUT",
        "TimeoutException": "ENDPOINT_TIMEOUT",
        "PoolTimeout": "ENDPOINT_TIMEOUT",
        "RemoteProtocolError": "ENDPOINT_PROTOCOL_ERROR",
        "ReadError": "ENDPOINT_UNREACHABLE",
        "WriteError": "ENDPOINT_UNREACHABLE",
        "NetworkError": "ENDPOINT_UNREACHABLE",
        "TransportError": "ENDPOINT_UNREACHABLE",
        "RequestError": "ENDPOINT_REQUEST_FAILED",
    }
    return table.get(type(exc).__name__, "ENDPOINT_REQUEST_FAILED")


# ================================================================== 投递 worker

class DeliveryWorker:
    """后台投递队列。

    领取（claim_one）：BEGIN IMMEDIATE 串行事务内只挑"到期 + 同订阅前序已终结"
    的最早一条并写租约。两 worker 并发只有一个拿到行；租约过期后任何 worker
    可凭过期条件接管，旧 owner 提交结果时条件 UPDATE rowcount=0 即放弃。
    """

    def __init__(self, conn: sqlite3.Connection, worker_id: Optional[str] = None,
                 transport: Optional[Transport] = None,
                 backoff: tuple[int, ...] = DEFAULT_BACKOFF,
                 max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 lease_seconds: int = DEFAULT_LEASE_SECONDS):
        self.conn = conn
        self.worker_id = worker_id or f"w-{os.getpid()}-{secrets.token_hex(3)}"
        self.transport = transport or resolve_transport()
        self.backoff = backoff
        self.max_attempts = max_attempts
        self.lease_seconds = lease_seconds
        self.bus = EventBus(conn)

    # ------------------------------------------------------------ 领取
    def claim_one(self) -> Optional[int]:
        """领取一条可投递记录，返回 delivery_id；无则 None。

        顺序护栏：同订阅存在更小 seq 且未终结（queued，或 leased 租约仍有效）的
        记录时跳过——绝不越过前序投递后序（事件顺序冲突在领取侧消解为稳定跳过）。"""
        ts = now()
        with transaction(self.conn) as c:
            row = c.execute(
                """SELECT d.id FROM event_deliveries d
                   JOIN event_subscriptions s ON s.id=d.subscription_id
                   WHERE s.status='active' AND d.next_attempt_at <= ?
                     AND (d.status='queued'
                          OR (d.status='leased' AND d.lease_expires_at <= ?))
                     AND NOT EXISTS (
                       SELECT 1 FROM event_deliveries p
                       WHERE p.subscription_id=d.subscription_id
                         AND p.event_seq < d.event_seq
                         AND (p.status='queued'
                              OR (p.status='leased' AND p.lease_expires_at > ?)))
                   ORDER BY d.event_seq, d.id LIMIT 1""",
                (ts, ts, ts),
            ).fetchone()
            if not row:
                return None
            expires = (parse_ts(ts) + timedelta(seconds=self.lease_seconds)
                       ).isoformat(timespec="seconds")
            cur = c.execute(
                """UPDATE event_deliveries
                   SET status='leased', lease_owner=?, leased_at=?, lease_expires_at=?
                   WHERE id=? AND (status='queued'
                        OR (status='leased' AND lease_expires_at <= ?))""",
                (self.worker_id, ts, expires, row["id"], ts),
            )
            return row["id"] if cur.rowcount == 1 else None

    # ------------------------------------------------------------ 单次投递
    def deliver(self, delivery_id: int) -> dict[str, Any]:
        """对本 worker 持有效租约的记录执行一次投递并落结果。

        - 成功且仍持租约 → sent；条件 UPDATE 失配（租约已被接管/进程崩溃后
          他人重投）→ 返回当前状态的稳定视图，不覆盖接管者的结论。
        - 失败 → attempts+1；未达上限按退避排期回 queued，达上限转 dead。
        网络调用在事务外，避免长 IO 持写锁。"""
        with transaction(self.conn) as c:
            d = c.execute("SELECT * FROM event_deliveries WHERE id=?", (delivery_id,)).fetchone()
            if not d:
                raise EventError("DELIVERY_NOT_FOUND", "投递记录不存在", 404)
            if d["status"] != "leased":
                # 已被他者发送/置死信：稳定返回现状，不重复投递
                return delivery_row_view(c, d, note="LEASE_LOST")
            if d["lease_owner"] != self.worker_id:
                # 租约已过期并被另一 worker 接管：旧 owner 不得再发请求（避免重复外呼）
                return delivery_row_view(c, d, note="LEASE_LOST")
            sub = c.execute("SELECT * FROM event_subscriptions WHERE id=?",
                            (d["subscription_id"],)).fetchone()
            ev = c.execute("SELECT * FROM platform_events WHERE id=?", (d["event_id"],)).fetchone()
            envelope = self.bus.envelope(ev)
            secret = deobfuscate_secret(sub["secret_store"])
            url = sub["endpoint_url"]
            sub_version = sub["version"]

        headers = delivery_headers(secret, envelope, sub_version)
        try:
            http_status = self.transport(url, headers, envelope)
            ok = 200 <= http_status < 300
            error_code = None
        except Exception as exc:  # 网络层失败：归类为稳定码，丢弃原始文本
            ok, http_status, error_code = False, None, classify_transport_error(exc)

        return self._complete(delivery_id, envelope, ok, http_status, error_code)

    def _complete(self, delivery_id: int, envelope: dict[str, Any], ok: bool,
                  http_status: Optional[int], error_code: Optional[str]) -> dict[str, Any]:
        ts = now()
        with transaction(self.conn) as c:
            d = c.execute("SELECT * FROM event_deliveries WHERE id=?", (delivery_id,)).fetchone()
            if not d:
                raise EventError("DELIVERY_NOT_FOUND", "投递记录不存在", 404)
            # 租约已失效（被接管）：不覆盖接管者结论，返回稳定现状
            if d["status"] != "leased" or d["lease_owner"] != self.worker_id:
                return self._delivery_view(
                    c, d, note="LEASE_LOST", event_id=envelope["header"]["event_id"])
            attempt_no = d["attempts"] + 1
            if ok:
                c.execute(
                    """UPDATE event_deliveries
                       SET status='sent', attempts=?, sent_at=?,
                           lease_owner=NULL, lease_expires_at=NULL
                       WHERE id=? AND status='leased' AND lease_owner=?""",
                    (attempt_no, ts, delivery_id, self.worker_id),
                )
                self._log(c, delivery_id, attempt_no, "sent", http_status, None)
                d = c.execute("SELECT * FROM event_deliveries WHERE id=?", (delivery_id,)).fetchone()
                return self._delivery_view(c, d)

            # 失败
            if attempt_no >= min(self.max_attempts, d["max_attempts"]):
                c.execute(
                    """UPDATE event_deliveries
                       SET status='dead', attempts=?, dead_at=?,
                           lease_owner=NULL, lease_expires_at=NULL
                       WHERE id=? AND status='leased' AND lease_owner=?""",
                    (attempt_no, ts, delivery_id, self.worker_id),
                )
                self._log(c, delivery_id, attempt_no, "dead", http_status, error_code)
                d = c.execute("SELECT * FROM event_deliveries WHERE id=?", (delivery_id,)).fetchone()
                return self._delivery_view(c, d)

            backoff_s = self.backoff[min(attempt_no - 1, len(self.backoff) - 1)]
            nxt = (parse_ts(ts) + timedelta(seconds=backoff_s)).isoformat(timespec="seconds")
            c.execute(
                """UPDATE event_deliveries
                   SET status='queued', attempts=?, next_attempt_at=?,
                       lease_owner=NULL, leased_at=NULL, lease_expires_at=NULL
                   WHERE id=? AND status='leased' AND lease_owner=?""",
                (attempt_no, nxt, delivery_id, self.worker_id),
            )
            self._log(c, delivery_id, attempt_no, "retried", http_status, error_code)
            d = c.execute("SELECT * FROM event_deliveries WHERE id=?", (delivery_id,)).fetchone()
            return self._delivery_view(c, d)

    def _log(self, c: sqlite3.Connection, delivery_id: int, attempt_no: int,
             result: str, http_status: Optional[int], error_code: Optional[str]) -> None:
        c.execute(
            """INSERT INTO delivery_attempts
               (delivery_id,attempt_no,worker,result,http_status,error_code,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (delivery_id, attempt_no, self.worker_id, result, http_status,
             error_code, now()),
        )

    def _delivery_view(self, c: sqlite3.Connection, d: sqlite3.Row,
                       note: Optional[str] = None, event_id: Optional[str] = None
                       ) -> dict[str, Any]:
        view = delivery_row_view(c, d)
        if note:
            view["note"] = note
        return view

    # ------------------------------------------------------------ 主循环
    def run_batch(self, max_items: int = 16) -> list[dict[str, Any]]:
        """领取并投递至多 max_items 条（测试与后台线程共用）。"""
        results = []
        for _ in range(max_items):
            did = self.claim_one()
            if did is None:
                break
            results.append(self.deliver(did))
        return results

    # ------------------------------------------------------------ 死信重放
    def replay_dead(self, actor: str, delivery_id: int) -> dict[str, Any]:
        """安全管理员逐条重放死信。

        - 只对 status='dead' 的记录生效：已发送 → DELIVERY_ALREADY_SENT；
          排队/租约中 → DELIVERY_NOT_DEAD，都给稳定结果（重复重放幂等）。
        - 重放**复用原事件包**（同一 event_id/seq/正文/签名），绝不修改正文，
          也不产生任何新的业务事件或新的 platform_events 行；
          仅把投递重置 attempts=0、replay_count+1 后立即再投一次。
        """
        ts = now()
        with transaction(self.conn) as c:
            d = c.execute("SELECT * FROM event_deliveries WHERE id=?", (delivery_id,)).fetchone()
            if not d:
                raise EventError("DELIVERY_NOT_FOUND", "投递记录不存在", 404)
            if d["status"] == "sent":
                view = delivery_row_view(c, d)
                view["duplicate"] = True
                return view  # 稳定：重复重放已发送记录 → 当前结果
            if d["status"] != "dead":
                raise EventError("DELIVERY_NOT_DEAD", "只有死信记录可以重放", 409)
            sub = c.execute("SELECT * FROM event_subscriptions WHERE id=?",
                            (d["subscription_id"],)).fetchone()
            if sub["status"] != "active":
                raise EventError("ENDPOINT_PAUSED", "端点已停用，恢复后才能重放", 409)
            # 顺序冲突：同订阅还有更早（seq 更小）的记录未终结（queued/leased/dead），
            # 必须按序先处理前序，重放后序会造成乱序 → 稳定冲突结果
            blocker = c.execute(
                """SELECT id FROM event_deliveries
                   WHERE subscription_id=? AND event_seq < ?
                     AND status IN ('queued','leased','dead')
                   ORDER BY event_seq LIMIT 1""",
                (d["subscription_id"], d["event_seq"]),
            ).fetchone()
            if blocker:
                raise EventError(
                    "DELIVERY_ORDER_CONFLICT",
                    f"前序投递 #{blocker['id']} 尚未终结，须按序号顺序处理", 409)
            c.execute(
                """UPDATE event_deliveries
                   SET status='queued', attempts=0, next_attempt_at=?,
                       replay_count=replay_count+1, dead_at=NULL,
                       lease_owner=NULL, leased_at=NULL, lease_expires_at=NULL
                   WHERE id=? AND status='dead'""",
                (ts, delivery_id),
            )
            c.execute(
                """INSERT INTO delivery_attempts
                   (delivery_id,attempt_no,worker,result,created_at)
                   VALUES(?, 0, ?, 'replayed', ?)""",
                (delivery_id, actor, ts),
            )
            # 安全审计：只记投递/事件标识与代际，不记正文与订阅密钥
            ev = c.execute("SELECT event_id,seq FROM platform_events WHERE id=?",
                           (d["event_id"],)).fetchone()
            c.execute(
                "INSERT INTO audit_log(actor,action,detail,created_at) VALUES(?,?,?,?)",
                (actor, "event_delivery_replay", canonical_json({
                    "delivery_id": delivery_id, "subscription_id": d["subscription_id"],
                    "event_id": ev["event_id"], "event_seq": ev["seq"]}), ts),
            )
            ev = c.execute("SELECT * FROM platform_events WHERE id=?", (d["event_id"],)).fetchone()
            envelope = self.bus.envelope(ev)
            secret = deobfuscate_secret(sub["secret_store"])
            url = sub["endpoint_url"]
            sub_version = sub["version"]
        headers = delivery_headers(secret, envelope, sub_version)
        try:
            http_status = self.transport(url, headers, envelope)
            ok = 200 <= http_status < 300
            error_code = None
        except Exception as exc:
            ok, http_status, error_code = False, None, classify_transport_error(exc)

        with transaction(self.conn) as c:
            d2 = c.execute("SELECT * FROM event_deliveries WHERE id=?", (delivery_id,)).fetchone()
            if ok:
                c.execute(
                    "UPDATE event_deliveries SET status='sent', attempts=1, sent_at=? WHERE id=?",
                    (now(), delivery_id),
                )
                self._log(c, delivery_id, 1, "sent", http_status, None)
            else:
                # 重放仍失败：回到退避队列重新计数（不立即再判死信，给满退避轮次）
                nxt = (datetime.now(timezone.utc) + timedelta(
                    seconds=self.backoff[0])).isoformat(timespec="seconds")
                c.execute(
                    """UPDATE event_deliveries
                       SET status='queued', attempts=1, next_attempt_at=? WHERE id=?""",
                    (nxt, delivery_id),
                )
                self._log(c, delivery_id, 1, "retried", http_status, error_code)
            d2 = c.execute("SELECT * FROM event_deliveries WHERE id=?", (delivery_id,)).fetchone()
            return delivery_row_view(c, d2)


# ================================================================== 投递视图 / 审计

def delivery_row_view(c: sqlite3.Connection, d: sqlite3.Row,
                      note: Optional[str] = None, event_id: Optional[str] = None
                      ) -> dict[str, Any]:
    """投递记录视图：只含队列状态，绝无订阅密钥与事件盲态正文。
    事件侧只回传 event_id/seq/kind/中心（摘要级），不回传 body。"""
    ev = c.execute(
        "SELECT event_id,seq,kind,center_code,sub_version,sign_key_id FROM platform_events WHERE id=?",
        (d["event_id"],),
    ).fetchone()
    sub = c.execute("SELECT name,endpoint_url,status,version FROM event_subscriptions WHERE id=?",
                    (d["subscription_id"],)).fetchone()
    view = {
        "id": d["id"],
        "subscription_id": d["subscription_id"],
        "subscription_name": sub["name"] if sub else None,
        "endpoint_url": sub["endpoint_url"] if sub else None,
        "event_id": ev["event_id"], "event_seq": ev["seq"], "kind": ev["kind"],
        "center_code": ev["center_code"], "event_sub_version": ev["sub_version"],
        "sign_key_id": ev["sign_key_id"],
        "status": d["status"], "attempts": d["attempts"],
        "max_attempts": d["max_attempts"], "replay_count": d["replay_count"],
        "lease_owner": d["lease_owner"], "leased_at": d["leased_at"],
        "lease_expires_at": d["lease_expires_at"],
        "next_attempt_at": d["next_attempt_at"],
        "dead_at": d["dead_at"], "sent_at": d["sent_at"],
        "created_at": d["created_at"],
    }
    if note:
        view["note"] = note
    return view

class DeliveryAudit:
    """安全端投递审计与死信清单。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def list_deliveries(self, status: Optional[str] = None,
                        subscription_id: Optional[int] = None,
                        limit: int = 200) -> list[dict[str, Any]]:
        q = "SELECT * FROM event_deliveries WHERE 1=1"
        params: list[Any] = []
        if status:
            q += " AND status=?"
            params.append(status)
        if subscription_id is not None:
            q += " AND subscription_id=?"
            params.append(subscription_id)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(min(limit, 1000))
        return [delivery_row_view(self.conn, r)
                for r in self.conn.execute(q, params).fetchall()]

    def get_delivery(self, delivery_id: int) -> dict[str, Any]:
        d = self.conn.execute("SELECT * FROM event_deliveries WHERE id=?",
                             (delivery_id,)).fetchone()
        if not d:
            raise EventError("DELIVERY_NOT_FOUND", "投递记录不存在", 404)
        view = delivery_row_view(self.conn, d)
        attempts = self.conn.execute(
            """SELECT attempt_no,worker,result,http_status,error_code,created_at
               FROM delivery_attempts WHERE delivery_id=? ORDER BY id""",
            (delivery_id,),
        ).fetchall()
        view["attempts_log"] = [dict(a) for a in attempts]
        return view

    def list_dead(self) -> list[dict[str, Any]]:
        return self.list_deliveries(status="dead")


# ================================================================== 研究端事件摘要

class ResearchEventView:
    """研究端只能看自己被授权的事件摘要：本中心事件 + 平台级（center 为空）事件。
    只给头部摘要，不返回签名包/端点/投递状态，更不含任何盲态字段。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def summaries_for_center(self, center_code: str, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT seq,event_id,kind,center_code,actor_role,sub_version,
                      sign_key_id,created_at
               FROM platform_events
               WHERE center_code=? OR center_code IS NULL
               ORDER BY seq DESC LIMIT ?""",
            (center_code, min(limit, 1000)),
        ).fetchall()
        return [{
            "seq": r["seq"], "event_id": r["event_id"], "kind": r["kind"],
            "center_code": r["center_code"], "actor_role": r["actor_role"],
            "sub_version": r["sub_version"], "sign_key_id": r["sign_key_id"],
            "created_at": r["created_at"],
        } for r in rows]

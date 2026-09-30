"""数据库连接、WAL 持久化与 schema 初始化。

所有状态都落 SQLite；写连接开启立即刷盘（synchronous=FULL）+ WAL，
保证：进程崩溃/被 kill 后重启，已提交事务不丢、未提交事务不留半成品。
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager

SCHEMA_VERSION = 3

SCHEMA = """
-- 用户与会话（角色：investigator 研究者 / pharmacy 药房 / safety 安全管理员）
CREATE TABLE IF NOT EXISTS users(
  id          INTEGER PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  display     TEXT NOT NULL,
  role        TEXT NOT NULL CHECK(role IN ('investigator','pharmacy','safety')),
  center_code TEXT,                       -- 研究者/药房绑定的中心
  salt        TEXT NOT NULL,
  pwhash      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions(
  token       TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id),
  created_at  TEXT NOT NULL
);

-- 试验方案版本：版本号、区组大小、各组名称与比例（如 A:B = 1:1）
CREATE TABLE IF NOT EXISTS protocol_versions(
  id           INTEGER PRIMARY KEY,
  code         TEXT NOT NULL UNIQUE,      -- 如 V1.0 / V2.0
  block_size   INTEGER NOT NULL,          -- 区组大小（必须 = 比例和的整数倍）
  arm_names    TEXT NOT NULL,             -- JSON ["A","B"]
  arm_ratios   TEXT NOT NULL,             -- JSON [1,1]
  active       INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS centers(
  code        TEXT PRIMARY KEY,           -- 中心编码，如 01
  name        TEXT NOT NULL
);

-- 分层化随机序列游标：(方案版本, 中心) 一条，独立消费，互不影响
CREATE TABLE IF NOT EXISTS strata(
  id              INTEGER PRIMARY KEY,
  pv_code         TEXT NOT NULL,
  center_code     TEXT NOT NULL,
  next_assignment INTEGER NOT NULL DEFAULT 0,  -- 已发出的分配数（含未使用的号）
  UNIQUE(pv_code, center_code)
);

-- 受试者。随机号全局唯一；arm 在入组成功时即刻固化，但普通接口永不返回
CREATE TABLE IF NOT EXISTS subjects(
  id             INTEGER PRIMARY KEY,
  subject_code   TEXT NOT NULL UNIQUE,    -- 筛选号/受试者唯一编码
  center_code    TEXT NOT NULL,
  pv_code        TEXT NOT NULL,           -- 入组时锁定的方案版本
  random_no      TEXT UNIQUE,             -- 随机号，如 V10-01-0007
  arm            TEXT,                    -- 治疗组：盲态字段，写入后默认不可见
  enrolled_at    TEXT,                   -- 随机化时间（入排通过前为 NULL）
  withdrawn      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS eligibility_events(
  id            INTEGER PRIMARY KEY,
  subject_code  TEXT NOT NULL,
  center_code   TEXT NOT NULL,
  pv_code       TEXT,
  passed        INTEGER NOT NULL,
  detail        TEXT NOT NULL,            -- JSON 入排问答/失败原因
  created_at    TEXT NOT NULL
);

-- 药盒批号：compat_arms 为该批号可服务的治疗组集合（盲态，只在分配内部使用）
CREATE TABLE IF NOT EXISTS lots(
  id           INTEGER PRIMARY KEY,
  lot_no       TEXT NOT NULL UNIQUE,
  center_code  TEXT NOT NULL,
  compat_arms  TEXT NOT NULL,             -- JSON ["A","B"]
  priority     INTEGER NOT NULL,          -- 同兼容集内使用顺序，小者优先
  created_at   TEXT NOT NULL
);

-- 药盒：arm 盲态字段拆出语义——kit_no 表面中性，分组只存这里
-- status: in_stock / dispensed / returned
-- frozen=1 表示被召回冻结，任何发放/再入库都不得触碰；只能由安全管理员显式解冻
CREATE TABLE IF NOT EXISTS kits(
  id          INTEGER PRIMARY KEY,
  kit_no      TEXT NOT NULL UNIQUE,       -- 中性药盒号，不含分组信息
  lot_no      TEXT NOT NULL,
  center_code TEXT NOT NULL,
  arm         TEXT NOT NULL,              -- 盲态：对应治疗组
  status      TEXT NOT NULL DEFAULT 'in_stock'
              CHECK(status IN ('in_stock','dispensed','returned')),
  holder_subject_id INTEGER REFERENCES subjects(id),  -- 当前持有人
  frozen      INTEGER NOT NULL DEFAULT 0
);

-- 药盒去向流水：只增不改，药盒守恒靠它审计
CREATE TABLE IF NOT EXISTS kit_events(
  id          INTEGER PRIMARY KEY,
  kit_no      TEXT NOT NULL,
  event_type  TEXT NOT NULL CHECK(event_type IN ('dispense','return')),
  subject_id  INTEGER REFERENCES subjects(id),
  random_no   TEXT,
  lot_no      TEXT,
  lot_switched INTEGER NOT NULL DEFAULT 0, -- 本次发放是否启用了兼容批号
  actor       TEXT NOT NULL,
  note        TEXT,
  created_at  TEXT NOT NULL
);

-- 应急揭盲：一次只开放单个受试者，不触碰其他人
CREATE TABLE IF NOT EXISTS emergency_unblinds(
  id           INTEGER PRIMARY KEY,
  subject_id   INTEGER NOT NULL UNIQUE REFERENCES subjects(id),
  reason       TEXT NOT NULL,
  actor        TEXT NOT NULL,
  created_at   TEXT NOT NULL
);

-- 正常揭盲申请：必须 data_locked=1，且两名不同安全管理员审批
CREATE TABLE IF NOT EXISTS unblind_requests(
  id           INTEGER PRIMARY KEY,
  scope        TEXT NOT NULL DEFAULT 'all',
  status       TEXT NOT NULL DEFAULT 'pending'
               CHECK(status IN ('pending','approved','rejected')),
  reason       TEXT NOT NULL,
  created_by   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  decided_at   TEXT
);

CREATE TABLE IF NOT EXISTS unblind_approvals(
  id          INTEGER PRIMARY KEY,
  request_id  INTEGER NOT NULL REFERENCES unblind_requests(id),
  approver    TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  UNIQUE(request_id, approver)            -- 同一人不能双算
);

-- 全试验唯一开关
CREATE TABLE IF NOT EXISTS study_state(
  id INTEGER PRIMARY KEY CHECK(id=1),
  data_locked INTEGER NOT NULL DEFAULT 0,
  locked_at TEXT,
  locked_by TEXT
);

-- 审计日志：append-only。盲态动作（揭盲）强制留痕
CREATE TABLE IF NOT EXISTS audit_log(
  id         INTEGER PRIMARY KEY,
  actor      TEXT,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL,               -- JSON，注意禁止写入其他受试者的 arm
  created_at TEXT NOT NULL
);

-- 批次召回单：风险控制（安全管理员）发布，指定受影响批号。
-- status: active 进行中 / closed 已关闭（全部处置完毕）/ revoked 已撤销（未发生任何替换核销）
CREATE TABLE IF NOT EXISTS recalls(
  id            INTEGER PRIMARY KEY,
  recall_no     TEXT NOT NULL UNIQUE,     -- 如 RC-0001
  reason        TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active'
                CHECK(status IN ('active','closed','revoked')),
  created_by    TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  closed_at     TEXT,
  closed_by     TEXT,
  revoked_at    TEXT,
  revoked_by    TEXT,
  revoke_reason TEXT
);

-- 召回单波及的批号（同一批号同一时间只允许出现在一个进行中的召回单）
CREATE TABLE IF NOT EXISTS recall_lots(
  id        INTEGER PRIMARY KEY,
  recall_id INTEGER NOT NULL REFERENCES recalls(id),
  lot_no    TEXT NOT NULL,
  UNIQUE(recall_id, lot_no)
);

-- 召回范围快照：发布瞬间固化，之后补录进该批号的药盒不自动混入本单。
-- state 推进：frozen_stock（未领用库存，冻结）
--   pending 待处理 → recovered 已回收 → replaceable 可替换 → redeemed 已核销
--   pending → exempt_pending 豁免待复核 →（批准）replaceable /（驳回）pending
--   进行中状态在召回撤销时 → void；frozen_stock 不随撤销/关闭自动解冻
CREATE TABLE IF NOT EXISTS recall_items(
  id               INTEGER PRIMARY KEY,
  recall_id        INTEGER NOT NULL REFERENCES recalls(id),
  kit_no           TEXT NOT NULL,
  lot_no           TEXT NOT NULL,
  center_code      TEXT NOT NULL,
  subject_id       INTEGER REFERENCES subjects(id),  -- 发布时的持有人（在库则为空）
  random_no        TEXT,                             -- 冗余随机号，供配药端中性展示
  state            TEXT NOT NULL
                   CHECK(state IN ('frozen_stock','pending','recovered',
                                   'exempt_pending','replaceable','redeemed','void')),
  exemption_reason TEXT,
  exemption_by     TEXT,
  exemption_at     TEXT,
  reviewed_by      TEXT,
  reviewed_at      TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE(recall_id, kit_no)
);

-- 一次性替换凭证：回收扫码确认 / 豁免复核通过后签发。
-- UNIQUE(recall_id, subject_id) 保证同一对象对同一召回单最多完成一次替换；
-- 核销用条件 UPDATE ... WHERE status='issued'，并发下只有一个事务能转成 redeemed。
CREATE TABLE IF NOT EXISTS replacement_vouchers(
  id              INTEGER PRIMARY KEY,
  voucher_no      TEXT NOT NULL UNIQUE,   -- 如 RV-0001
  recall_id       INTEGER NOT NULL REFERENCES recalls(id),
  item_id         INTEGER NOT NULL UNIQUE REFERENCES recall_items(id),
  subject_id      INTEGER NOT NULL,
  random_no       TEXT NOT NULL,
  center_code     TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'issued'
                  CHECK(status IN ('issued','redeemed','void')),
  issued_by       TEXT NOT NULL,
  issued_at       TEXT NOT NULL,
  redeemed_at     TEXT,
  redeemed_by     TEXT,
  redeemed_kit_no TEXT,
  UNIQUE(recall_id, subject_id)
);

-- ============================================================ 平台事件出站队列
-- 不可变平台事件：入组/发药/退药/召回/揭盲等已提交事务的唯一事实来源。
-- 只追加（append-only）：历史事件一经提交永不 UPDATE/DELETE（见巡检与库外校验）。
-- seq 全平台单调递增；prev_digest 把事件串成哈希链，任何历史篡改都会断链；
-- body 为规范 JSON，body_digest 独立可验；sub_version 是签发瞬间的订阅配置版本；
-- sign_key_id 指向签发所用的 Ed25519 公钥指纹（轮换后旧事件仍可按旧公钥核对）。
CREATE TABLE IF NOT EXISTS platform_events(
  id          INTEGER PRIMARY KEY,
  event_id    TEXT NOT NULL UNIQUE,      -- UUID，订阅方据此幂等去重
  seq         INTEGER NOT NULL UNIQUE,   -- 单调序号（全平台一条线）
  kind        TEXT NOT NULL,
  center_code TEXT,                      -- NULL = 全平台事件（如正常揭盲）
  actor_role  TEXT NOT NULL,
  body        TEXT NOT NULL,             -- 规范 JSON 正文（不含 arm/批号兼容/密钥）
  body_digest TEXT NOT NULL,             -- sha256(canonical(body))
  prev_digest TEXT NOT NULL,             -- 前一事件的 event_digest
  event_digest TEXT NOT NULL,            -- 本事件链摘要（含头与正文摘要）
  sub_version INTEGER NOT NULL,          -- 签发版本：当时的订阅配置单调版本
  sign_key_id TEXT NOT NULL,
  signature   TEXT NOT NULL,             -- 事件头 Ed25519 签名（base64）
  created_at  TEXT NOT NULL
);

-- 签发密钥对：Ed25519。active=1 为当前版本；轮换后旧版本保留以供库外核对历史。
-- 私钥仅安全端换钥/签名时内部读取，任何接口永不输出；公钥通过 /api/verify-materials 公布。
CREATE TABLE IF NOT EXISTS event_signing_keys(
  id           TEXT PRIMARY KEY,         -- 公钥指纹（DER 哈希前 16 字节 hex）
  version      INTEGER NOT NULL UNIQUE,
  public_pem   TEXT NOT NULL,
  private_pem  TEXT NOT NULL,            -- 内部持有，不外泄；演示系统落盘
  active       INTEGER NOT NULL DEFAULT 0,
  rotated_at   TEXT,
  created_at   TEXT NOT NULL
);

-- 订阅：安全管理员登记；按 事件种类 × 中心 × 角色 过滤。
-- 同一 URL 只能登记一条（重复订阅稳定返回原配置，不重复 fan-out）。
-- secret 是投递信封的 HMAC 共享密钥：仅登记响应返回一次，之后任何页面/接口不再回显，
-- 审计/错误/重试日志也不得包含它（见 delivery_attempts 与错误脱敏）。
-- secret_hash 仅为登记一致性比对；secret_store 为服务端 pepper 异或混淆后的密文
-- （worker 需要还原密钥来计算投递 HMAC；它不是机密保护层，真正的机密边界在
--   "任何 API/页面/日志永不回显"）。
-- version: 该订阅自身的配置版本；每次暂停/恢复/改筛选自增，事件包携带当时版本。
CREATE TABLE IF NOT EXISTS event_subscriptions(
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL,
  endpoint_url TEXT NOT NULL UNIQUE,
  secret_hash  TEXT NOT NULL,            -- 仅保存 HMAC 密钥的服务端摘要（比对用）
  secret_store TEXT NOT NULL,            -- pepper 异或混淆后的投递密钥（worker 还原签名用）
  kind_filter  TEXT NOT NULL,            -- JSON 事件种类清单；[] = 全部
  center_filter TEXT NOT NULL,           -- JSON 中心清单；[] = 全部
  role_filter  TEXT NOT NULL,            -- JSON 发起人角色清单；[] = 全部
  status       TEXT NOT NULL DEFAULT 'active'
               CHECK(status IN ('active','paused')),
  version      INTEGER NOT NULL DEFAULT 1,
  created_by   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

-- 出站投递：(订阅, 事件) 唯一，fan-out 时每匹配订阅一条。
-- status: queued 待投递 / leased 已被某 worker 租走 / sent 成功 / dead 死信
-- 事件顺序冲突：同一订阅必须按事件 seq 投递，前序未终结（queued/leased）时
--   后序不可领取（claim 阶段跳过），不产生乱序投递。
CREATE TABLE IF NOT EXISTS event_deliveries(
  id              INTEGER PRIMARY KEY,
  subscription_id INTEGER NOT NULL REFERENCES event_subscriptions(id),
  event_id        INTEGER NOT NULL REFERENCES platform_events(id),
  event_seq       INTEGER NOT NULL,
  status          TEXT NOT NULL DEFAULT 'queued'
                  CHECK(status IN ('queued','leased','sent','dead')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  max_attempts    INTEGER NOT NULL DEFAULT 6,
  lease_owner     TEXT,                  -- 租约持有者标识（worker 实例）
  leased_at       TEXT,
  lease_expires_at TEXT,
  next_attempt_at TEXT NOT NULL,         -- 退避到期时间；queued 立即可投
  dead_at         TEXT,
  sent_at         TEXT,
  replay_count    INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL,
  UNIQUE(subscription_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due
  ON event_deliveries(status, next_attempt_at);

-- 投递尝试流水：append-only 的重试日志。
-- 严禁写入 arm/治疗组/分配臂/批号兼容/订阅密钥；detail 只放稳定错误码与计数。
CREATE TABLE IF NOT EXISTS delivery_attempts(
  id              INTEGER PRIMARY KEY,
  delivery_id     INTEGER NOT NULL REFERENCES event_deliveries(id),
  attempt_no      INTEGER NOT NULL,
  worker          TEXT NOT NULL,
  result          TEXT NOT NULL CHECK(result IN ('sent','retried','dead','replayed','skipped_order')),
  http_status     INTEGER,
  error_code      TEXT,                  -- 稳定错误码（非原始异常文本）
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_delivery ON delivery_attempts(delivery_id, id);

-- 全局单调的订阅配置版本：任何订阅 登记/暂停/恢复/换钥事件都自增；
-- 事件签发时读取当前值写入 sub_version，订阅方可识别其配置所处的版本代际。
CREATE TABLE IF NOT EXISTS event_state(
  id INTEGER PRIMARY KEY CHECK(id=1),
  subscription_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS schema_meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=5000")


def connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    _apply_pragmas(conn)
    return conn


def init_db(db_path: str) -> None:
    """幂等初始化（首次建库 / 老库升级都安全）。

    注意：sqlite3 的 executescript 会先隐式提交当前事务，
    所以 schema 建表单独执行，再用显式事务写元数据。"""
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        # 老库升级：kits.frozen 列（召回冻结标记）
        cols = {r[1] for r in conn.execute("PRAGMA table_info(kits)").fetchall()}
        if "frozen" not in cols:
            conn.execute(
                "ALTER TABLE kits ADD COLUMN frozen INTEGER NOT NULL DEFAULT 0"
            )
        with transaction(conn):
            conn.execute(
                "INSERT OR IGNORE INTO study_state(id,data_locked) VALUES(1,0)"
            )
            conn.execute(
                "INSERT OR IGNORE INTO event_state(id,subscription_version) VALUES(1,0)"
            )
            conn.execute(
                "INSERT OR IGNORE INTO schema_meta(key,value) VALUES('version',?)",
                (str(SCHEMA_VERSION),),
            )
        # 幂等生成平台事件的初始 Ed25519 签发密钥（首次建库 / 老库升级都安全；
        # 放在 init_db 中，使任何入口（含不经 startup 的脚本/测试）都能签发事件）
        from .events import KeyStore
        KeyStore(conn).ensure_initial_key()
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection):
    """串行化所有写事务：BEGIN IMMEDIATE 一进来就拿写锁，
    并发抢最后一个药盒时只有一个事务能把行更新成功。"""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

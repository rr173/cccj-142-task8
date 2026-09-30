"""FastAPI 持久化接口 + 三类角色页面。

所有数据落盘于 RTS_DB（默认 rts/data/rts.db），重启不丢。
角色：investigator（研究者）/ pharmacy（药房）/ safety（安全管理员）。
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, Query
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .db import connect, init_db
from .service import TrialService, ServiceError
from .events import (
    DeliveryAudit, DeliveryWorker, EventBus, EventError, KeyStore,
    ResearchEventView, SubscriptionService,
)

DB_PATH = os.environ.get("RTS_DB", str(Path(__file__).parent / "data" / "rts.db"))
STATIC_DIR = Path(__file__).parent / "static"

# 后台出站队列：默认开启；测试可置 RTS_QUEUE_ENABLED=0 改为手动驱动（run_batch）
QUEUE_ENABLED = os.environ.get("RTS_QUEUE_ENABLED", "1") != "0"
QUEUE_INTERVAL = float(os.environ.get("RTS_QUEUE_INTERVAL", "1.0"))
QUEUE_LEASE_SECONDS = int(os.environ.get("RTS_QUEUE_LEASE", "30"))

app = FastAPI(title="多中心临床试验 随机分组与盲态药盒分配平台", version="1.0")

# 每个请求独立连接（SQLite 连接轻量；WAL 下读写不互斥太久）
def service() -> TrialService:
    return TrialService(connect(DB_PATH))


_queue_stop = threading.Event()
_queue_thread: Optional[threading.Thread] = None


def _queue_loop() -> None:
    """后台投递线程：每轮新连接领取到期记录（租约未到期的不会被重复领取）。
    全程错误码化，异常不冒泡出线程。"""
    while not _queue_stop.wait(QUEUE_INTERVAL):
        try:
            conn = connect(DB_PATH)
            try:
                worker = DeliveryWorker(conn, lease_seconds=QUEUE_LEASE_SECONDS)
                worker.run_batch(max_items=int(os.environ.get("RTS_QUEUE_BATCH", "16")))
            finally:
                conn.close()
        except Exception:
            # 队列错误绝不能拖垮 API 进程；下一轮继续（投递状态全部在库里）
            pass


def token(x_authorization: Optional[str]) -> Optional[str]:
    # 前端统一发 X-Authorization: Bearer <token>
    if not x_authorization:
        return None
    return x_authorization.removeprefix("Bearer ").strip() or None


@app.on_event("startup")
def _startup() -> None:
    init_db(DB_PATH)
    conn = connect(DB_PATH)
    try:
        # 首次启动/老库升级：生成活动签发密钥（幂等）
        KeyStore(conn).ensure_initial_key()
    finally:
        conn.close()
    if QUEUE_ENABLED:
        global _queue_thread
        _queue_thread = threading.Thread(target=_queue_loop, name="rts-event-queue",
                                         daemon=True)
        _queue_thread.start()


@app.on_event("shutdown")
def _shutdown() -> None:
    _queue_stop.set()


# ----------------------------------------------------------------- 异常
@app.exception_handler(ServiceError)
def _svc_error_handler(request, exc: ServiceError):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=exc.http,
                        content={"error": exc.code, "message": exc.message})


@app.exception_handler(EventError)
def _event_error_handler(request, exc: EventError):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=exc.http,
                        content={"error": exc.code, "message": exc.message})


# ----------------------------------------------------------------- 模型
class LoginIn(BaseModel):
    username: str
    password: str


class EligibilityIn(BaseModel):
    subject_code: str = Field(min_length=1)
    answers: dict[str, bool]


class EnrollIn(BaseModel):
    subject_code: str = Field(min_length=1)
    pv_code: str = Field(min_length=1)
    idem_key: Optional[str] = None


class DispenseIn(BaseModel):
    random_no: str
    kit_no: Optional[str] = None


class ReturnIn(BaseModel):
    kit_no: str
    note: Optional[str] = None


class ReasonIn(BaseModel):
    reason: str = Field(min_length=1)


class KitNoIn(BaseModel):
    kit_no: str


class LotIn(BaseModel):
    lot_no: str
    center_code: str
    compat_arms: list[str]
    priority: int = 0


class KitsIn(BaseModel):
    lot_no: str
    count: int = Field(ge=1, le=10000)
    arm: Optional[str] = None


class RecallIn(BaseModel):
    lot_nos: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1)


class RecoverIn(BaseModel):
    kit_no: str = Field(min_length=1)


class ExemptIn(BaseModel):
    reason: str = Field(min_length=1)


class ReviewIn(BaseModel):
    approve: bool


class RedeemIn(BaseModel):
    voucher_no: str = Field(min_length=1)
    kit_no: Optional[str] = None


# ------------------------------------------------- 平台事件出站队列
class SubscriptionIn(BaseModel):
    name: str = Field(min_length=1)
    endpoint_url: str = Field(min_length=1)
    kinds: list[str] = []        # 事件种类过滤，空=全部
    centers: list[str] = []      # 中心过滤，空=全部
    roles: list[str] = []        # 发起人角色过滤，空=全部


# ----------------------------------------------------------------- 认证
@app.post("/api/login")
def api_login(body: LoginIn):
    return service().login(body.username, body.password)


@app.post("/api/logout")
def api_logout(x_authorization: Optional[str] = Header(None)):
    t = token(x_authorization)
    if t:
        service().logout(t)
    return {"ok": True}


@app.get("/api/me")
def api_me(x_authorization: Optional[str] = Header(None)):
    return service().me(token(x_authorization))


# ----------------------------------------------------------------- 研究者
@app.post("/api/investigator/eligibility")
def api_eligibility(body: EligibilityIn, x_authorization: Optional[str] = Header(None)):
    return service().evaluate_eligibility(token(x_authorization), body.subject_code, body.answers)


@app.post("/api/investigator/enroll")
def api_enroll(body: EnrollIn, x_authorization: Optional[str] = Header(None)):
    return service().enroll(token(x_authorization), body.subject_code, body.pv_code, body.idem_key)


@app.get("/api/investigator/subjects")
def api_subjects(x_authorization: Optional[str] = Header(None)):
    return service().list_subjects(token(x_authorization))


@app.post("/api/investigator/emergency-unblind/{random_no}")
def api_emergency_one(random_no: str, body: ReasonIn,
                      x_authorization: Optional[str] = Header(None)):
    return service().emergency_unblind(token(x_authorization), random_no, body.reason)


# ----------------------------------------------------------------- 药房
@app.get("/api/pharmacy/kits")
def api_available(x_authorization: Optional[str] = Header(None)):
    return service().available_kits(token(x_authorization))


@app.post("/api/pharmacy/dispense")
def api_dispense(body: DispenseIn, x_authorization: Optional[str] = Header(None)):
    return service().dispense(token(x_authorization), body.random_no, body.kit_no)


@app.post("/api/pharmacy/return")
def api_return(body: ReturnIn, x_authorization: Optional[str] = Header(None)):
    return service().return_kit(token(x_authorization), body.kit_no, body.note)


@app.post("/api/pharmacy/restock")
def api_restock(body: KitNoIn, x_authorization: Optional[str] = Header(None)):
    return service().restock_returned(token(x_authorization), body.kit_no)


@app.get("/api/pharmacy/kits/{kit_no}/history")
def api_kit_history(kit_no: str, x_authorization: Optional[str] = Header(None)):
    return service().kit_history(token(x_authorization), kit_no)


# ----------------------------------------------------------------- 药房：召回处置
@app.get("/api/pharmacy/recall-items")
def api_pharm_recall_items(x_authorization: Optional[str] = Header(None)):
    return service().pharmacy_recall_items(token(x_authorization))


@app.post("/api/pharmacy/recall-items/{item_id}/recover")
def api_pharm_recover(item_id: int, body: RecoverIn,
                      x_authorization: Optional[str] = Header(None)):
    return service().recover_item(token(x_authorization), item_id, body.kit_no)


@app.post("/api/pharmacy/recall-items/{item_id}/exempt")
def api_pharm_exempt(item_id: int, body: ExemptIn,
                     x_authorization: Optional[str] = Header(None)):
    return service().register_exemption(token(x_authorization), item_id, body.reason)


@app.post("/api/pharmacy/recall-items/{item_id}/voucher")
def api_pharm_voucher(item_id: int, x_authorization: Optional[str] = Header(None)):
    return service().issue_voucher(token(x_authorization), item_id)


@app.post("/api/pharmacy/recall-vouchers/redeem")
def api_pharm_redeem(body: RedeemIn, x_authorization: Optional[str] = Header(None)):
    return service().redeem_voucher(token(x_authorization), body.voucher_no, body.kit_no)


# ----------------------------------------------------------------- 安全管理员
@app.get("/api/safety/status")
def api_status(x_authorization: Optional[str] = Header(None)):
    return service().study_status(token(x_authorization))


@app.post("/api/safety/data-lock")
def api_lock(x_authorization: Optional[str] = Header(None)):
    return service().lock_data(token(x_authorization))


@app.post("/api/safety/unblind-requests")
def api_request_unblind(body: ReasonIn, x_authorization: Optional[str] = Header(None)):
    return service().request_unblind(token(x_authorization), body.reason)


@app.post("/api/safety/unblind-requests/{request_id}/approve")
def api_approve(request_id: int, x_authorization: Optional[str] = Header(None)):
    return service().approve_unblind(token(x_authorization), request_id)


@app.get("/api/safety/unblind-requests")
def api_list_requests(x_authorization: Optional[str] = Header(None)):
    return service().list_unblind_requests(token(x_authorization))


@app.get("/api/safety/unblind-requests/{request_id}")
def api_get_request(request_id: int, x_authorization: Optional[str] = Header(None)):
    return service().get_unblind_request(token(x_authorization), request_id)


@app.get("/api/safety/emergency-list")
def api_emergency_list(x_authorization: Optional[str] = Header(None)):
    return service().emergency_list(token(x_authorization))


@app.get("/api/safety/invariants")
def api_invariants(x_authorization: Optional[str] = Header(None)):
    svc = service()
    svc._require(svc._user(token(x_authorization)), "safety")
    return svc.check_invariants()


@app.get("/api/safety/audit")
def api_audit(limit: int = 200, x_authorization: Optional[str] = Header(None)):
    return service().audit_log(token(x_authorization), limit)


@app.post("/api/safety/lots")
def api_add_lot(body: LotIn, x_authorization: Optional[str] = Header(None)):
    return service().add_lot(token(x_authorization), body.lot_no, body.center_code,
                             body.compat_arms, body.priority)


@app.post("/api/safety/kits")
def api_add_kits(body: KitsIn, x_authorization: Optional[str] = Header(None)):
    return service().add_kits(token(x_authorization), body.lot_no, body.count, body.arm)


# ----------------------------------------------------------------- 安全管理员：批次召回
@app.post("/api/safety/recalls")
def api_create_recall(body: RecallIn, x_authorization: Optional[str] = Header(None)):
    return service().create_recall(token(x_authorization), body.lot_nos, body.reason)


@app.get("/api/safety/recalls")
def api_list_recalls(x_authorization: Optional[str] = Header(None)):
    return service().list_recalls(token(x_authorization))


@app.get("/api/safety/recalls/{recall_id}")
def api_get_recall(recall_id: int, x_authorization: Optional[str] = Header(None)):
    return service().get_recall(token(x_authorization), recall_id)


@app.post("/api/safety/recalls/{recall_id}/close")
def api_close_recall(recall_id: int, x_authorization: Optional[str] = Header(None)):
    return service().close_recall(token(x_authorization), recall_id)


@app.post("/api/safety/recalls/{recall_id}/revoke")
def api_revoke_recall(recall_id: int, body: ReasonIn,
                      x_authorization: Optional[str] = Header(None)):
    return service().revoke_recall(token(x_authorization), recall_id, body.reason)


@app.post("/api/safety/recall-items/{item_id}/review-exemption")
def api_review_exemption(item_id: int, body: ReviewIn,
                         x_authorization: Optional[str] = Header(None)):
    return service().review_exemption(token(x_authorization), item_id, body.approve)


@app.post("/api/safety/recalls/unfreeze")
def api_unfreeze(body: KitNoIn, x_authorization: Optional[str] = Header(None)):
    return service().unfreeze_kit(token(x_authorization), body.kit_no)


# ----------------------------------------------------------------- 研究者：召回通知
@app.get("/api/investigator/recall-notices")
def api_inv_recall_notices(x_authorization: Optional[str] = Header(None)):
    return service().investigator_recall_notices(token(x_authorization))


# ============================================================ 平台事件：出站队列
#
# 角色边界：
#   安全管理员 safety —— 订阅登记/暂停/恢复、死信重放、投递审计、事件完整性、换钥；
#   研究者 investigator —— 仅本中心（含平台级）被授权事件的**摘要**；
#   药房 pharmacy —— 任何事件管理/审计接口一律 403，且读不到订阅密钥/其他中心事件；
#   未登录访客 —— 只能取公布的验证材料与按 seq/事件标识取签名事件包（供库外核对）。

def _require_role(x_authorization: Optional[str], role: str):
    svc = service()
    user = svc._user(token(x_authorization))
    svc._require(user, role)
    return svc, user


# ---------------- 安全端：订阅管理 ----------------
@app.post("/api/safety/event-subscriptions")
def api_register_subscription(body: SubscriptionIn,
                              x_authorization: Optional[str] = Header(None)):
    _, user = _require_role(x_authorization, "safety")
    return SubscriptionService(connect(DB_PATH)).register(
        user["username"], body.name, body.endpoint_url,
        body.kinds, body.centers, body.roles)


@app.get("/api/safety/event-subscriptions")
def api_list_subscriptions(x_authorization: Optional[str] = Header(None)):
    _require_role(x_authorization, "safety")
    return SubscriptionService(connect(DB_PATH)).list_subscriptions()


@app.get("/api/safety/event-subscriptions/{subscription_id}")
def api_get_subscription(subscription_id: int,
                         x_authorization: Optional[str] = Header(None)):
    _require_role(x_authorization, "safety")
    return SubscriptionService(connect(DB_PATH)).get_subscription(subscription_id)


@app.post("/api/safety/event-subscriptions/{subscription_id}/pause")
def api_pause_subscription(subscription_id: int,
                           x_authorization: Optional[str] = Header(None)):
    _, user = _require_role(x_authorization, "safety")
    return SubscriptionService(connect(DB_PATH)).pause(user["username"], subscription_id)


@app.post("/api/safety/event-subscriptions/{subscription_id}/resume")
def api_resume_subscription(subscription_id: int,
                            x_authorization: Optional[str] = Header(None)):
    _, user = _require_role(x_authorization, "safety")
    return SubscriptionService(connect(DB_PATH)).resume(user["username"], subscription_id)


# ---------------- 安全端：死信重放（逐条，不改原事件） ----------------
@app.post("/api/safety/event-deliveries/{delivery_id}/replay")
def api_replay_dead(delivery_id: int, x_authorization: Optional[str] = Header(None)):
    _, user = _require_role(x_authorization, "safety")
    conn = connect(DB_PATH)
    worker = DeliveryWorker(conn)
    return worker.replay_dead(user["username"], delivery_id)


# ---------------- 安全端：投递审计 ----------------
@app.get("/api/safety/event-deliveries")
def api_list_deliveries(status_filter: Optional[str] = Query(None, alias="status"),
                        subscription_id: Optional[int] = None,
                        x_authorization: Optional[str] = Header(None)):
    _require_role(x_authorization, "safety")
    return DeliveryAudit(connect(DB_PATH)).list_deliveries(
        status=status_filter, subscription_id=subscription_id)


@app.get("/api/safety/event-deliveries/{delivery_id}")
def api_get_delivery(delivery_id: int, x_authorization: Optional[str] = Header(None)):
    _require_role(x_authorization, "safety")
    return DeliveryAudit(connect(DB_PATH)).get_delivery(delivery_id)


# ---------------- 安全端：事件清单与完整性巡检 ----------------
@app.get("/api/safety/events")
def api_safety_events(limit: int = 100, kind: Optional[str] = None,
                      x_authorization: Optional[str] = Header(None)):
    _require_role(x_authorization, "safety")
    kinds = [kind] if kind else None
    return EventBus(connect(DB_PATH)).list_events(limit=limit, kinds=kinds)


@app.get("/api/safety/event-integrity")
def api_event_integrity(x_authorization: Optional[str] = Header(None)):
    _require_role(x_authorization, "safety")
    return EventBus(connect(DB_PATH)).check_integrity()


@app.post("/api/safety/rotate-signing-key")
def api_rotate_signing_key(x_authorization: Optional[str] = Header(None)):
    _, user = _require_role(x_authorization, "safety")
    return SubscriptionService(connect(DB_PATH)).rotate_key(user["username"])


# ---------------- 公开：验证材料 + 签名事件包（库外核对） ----------------
@app.get("/api/verify-materials")
def api_verify_materials():
    """公布的验证材料：全部 Ed25519 公钥（含已轮换）+ 当前链锚点。"""
    return KeyStore(connect(DB_PATH)).public_materials()


@app.get("/api/events/{seq}")
def api_public_event(seq: int):
    """按单调序号取签名事件包（头 + 正文 + 签名）。正文本就无盲态/密钥字段。"""
    env = EventBus(connect(DB_PATH)).get_by_seq(seq)
    if env is None:
        raise EventError("EVENT_NOT_FOUND", "事件不存在", 404)
    return env


@app.get("/api/events/by-id/{event_id}")
def api_public_event_by_id(event_id: str):
    env = EventBus(connect(DB_PATH)).get_by_event_id(event_id)
    if env is None:
        raise EventError("EVENT_NOT_FOUND", "事件不存在", 404)
    return env


# ---------------- 研究端：本中心被授权事件摘要 ----------------
@app.get("/api/investigator/events")
def api_investigator_events(x_authorization: Optional[str] = Header(None)):
    svc, user = _require_role(x_authorization, "investigator")
    return ResearchEventView(connect(DB_PATH)).summaries_for_center(user["center_code"])


@app.get("/api/health")
def health():
    return {"ok": True}


# ----------------------------------------------------------------- 页面
@app.get("/")
def index():
    return RedirectResponse("/static/index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# 多中心临床试验：随机分组与盲态药盒分配平台

> 姊妹模块：`coldchain/`（冷链证据，Node）、`consent/`（电子知情同意，Python）、
> **`siteguard/`（建设现场签署终端可信登记，Node：一次性注册码、终端证书、挑战-响应落款网关）**。

受试者通过入排标准后，按**方案版本 × 中心分层**的置换区组序列取得随机号；药房只见
中性药盒号，系统内部完成治疗组盲态匹配；首选批号短缺时自动/手动转用兼容批号而不动
随机序列；正常揭盲须数据锁定 + 双人审批，应急揭盲只开单个受试者。**批次召回闭环**：
风险控制发布召回单即冻结未领用库存并固化范围快照，配药端登记回收/医疗豁免后签发
一次性替换凭证，核销后从未被召回批次发放可替代包装。**平台事件签名出站队列**：
入组/发药/退药/召回/揭盲等已提交事务先写不可变事件（单调序号、订阅版本、签名摘要、
哈希链），再由后台队列按租约异步投递；失败退避重试、达上限进死信、安全管理员逐条
重放。SQLite(WAL) 持久化，进程崩溃重启后随机号、药盒去向、召回处置进度、登录会话、
未发送/超时/死信事件全部存活。

## 运行

```bash
pip install -r requirements.txt
python -m rts.seed                      # 初始化并播种演示数据（rts/data/rts.db）
python -m uvicorn rts.main:app --port 8000
# 浏览器打开 http://localhost:8000/
```

可环境变量 `RTS_DB=/path/to/study.db` 指定库文件。

### 演示账号（密码均为 demo1234）

| 角色 | 账号 | 中心 |
|---|---|---|
| 研究者 | inv01 / inv02 | 01 北京 / 02 上海 |
| 药房 | ph01 / ph02 | 01 / 02 |
| 安全管理员 | safe1、safe2 | 全局（双人揭盲各一票） |

## 页面

- **研究者** `/static/investigator.html`：入排评估 → 取得随机号 → 查看本中心受试者；
  应急揭盲（随机号 + 必填原因，只返回该一人治疗组）；召回通知（仅"是否需要联系 + 处置阶段"）。
- **药房** `/static/pharmacy.html`：只看本中心可领取药盒（中性药盒号/批号，无分组）；
  发药（留空药盒号=系统盲态自动匹配，首选批号缺货自动转兼容批号）、退药、退回盒再入库、单盒去向流水；
  召回处置（扫码回收、登记医疗豁免、生成并核销一次性替换凭证）。
- **安全管理员** `/static/safety.html`：试验状态、数据锁定、正常揭盲申请/双人审批与揭盲表、
  应急揭盲登记、审计日志、批号/药盒维护、守恒不变量巡检；
  批次召回（发布/明细/豁免复核/关闭/撤销/冻结盒质检解冻，跨中心汇总仅计数）；
  **`/static/events.html`：平台事件出站队列（订阅登记/暂停、死信逐条重放、投递审计、
  验证材料公布与签发密钥轮换、事件链完整性巡检）**。
- **研究者** `/static/investigator.html`：入排评估 → 取得随机号 → 查看本中心受试者；
  应急揭盲（随机号 + 必填原因，只返回该一人治疗组）；召回通知（仅"是否需要联系 + 处置阶段"）；
  平台事件摘要（仅本中心 + 平台级事件的序号/种类/签发版本，不含正文与密钥）。

## 关键规则如何落地

| 要求 | 实现 |
|---|---|
| 分层 + 区组随机 | `(pv_code, center_code)` 分层游标 `strata.next_assignment`；区组序列由 `(版本,中心,区组号)` 派生种子做确定性 Fisher–Yates，不物化、重启可复现；比例按区组放大（1:1/区组4 ⇒ 2A2B） |
| 随机号唯一 | `random_no` 全局 UNIQUE；游标在 `BEGIN IMMEDIATE` 事务内条件自增；重复入组同一受试者**幂等返回原号**，并发注册不同受试者拿到不同号 |
| 盲态边界 | `arm` 字段对研究者/药房的所有接口与审计明细永不输出；药房库存不返回 `arm` 与批号兼容集；指定药盒不兼容时与"不存在/已发"返回同一笼统错误，无法枚举反推 |
| 兼容批号转用 | 批号有 `compat_arms` 与优先级；自动选盒按优先级取**药盒实际 arm 精确匹配**的在库盒，转用标记 `lot_switched=1`；受试者→治疗组的随机序列不变 |
| 并发抢最后一盒 | 条件更新 `UPDATE kits SET status='dispensed' ... WHERE status='in_stock'`，写事务串行化，只有一个请求 rowcount=1 |
| 退药再发 | 三态 `in_stock/dispensed/returned` + append-only `kit_events`；退药解除持有人，质检再入库后可发给新受试者，随机号不复用 |
| 正常揭盲 | 必须 `data_locked=1`；申请即第一票，另一名安全管理员第二票才释放全部分组；同人不可双算；待审批/被拒的任何接口都不带分组 |
| 应急揭盲 | 接口路径只含一个随机号，响应仅该受试者 `arm`（`scope=single_subject`）；每受试者登记一次、原因必填、审计留痕；安全侧列表不含 arm |
| 重启持久化 | SQLite WAL + `synchronous=FULL`；每请求独立连接；序列游标/药盒状态/会话均落盘，SIGKILL 后重启继续且不变量成立 |
| 药盒去向守恒 | 每盒流水满足 `dispense 次数 − return 次数 ∈ {0,1}`，且与当前状态、持有人互相一致；`GET /api/safety/invariants` 巡检 |
| 召回范围快照 | 发布瞬间把受影响批号下的药盒固化为 `recall_items`；之后补录的盒不混入本单（但其批号在召回期间仍被发放/再入库拦截） |
| 未领用库存冻结 | 发布即 `kits.frozen=1`；发放、自动选盒、再入库一律跳过；**撤销/关闭/重启都不自动解冻**，仅安全管理员逐盒质检解冻，杜绝误恢复 |
| 处置状态机 | `pending→recovered→replaceable→redeemed`，豁免支路 `pending→exempt_pending→(批准)replaceable /(驳回)pending`；其余跳转（含逆向）统一 `RECALL_STATE_CONFLICT` |
| 一次性替换凭证 | 回收扫码/豁免批准才签发；`UNIQUE(recall_id, subject_id)` 保证同一对象同一召回单最多一次替换；核销用条件 `UPDATE ... WHERE status='issued'`，并发下只有一笔发放，双方得到同一稳定回执 |
| 替换包装来源 | 核销时仅从**未被召回批次**（排除全部进行中召回批号 + 冻结盒）按盲态兼容规则选盒 |
| 关闭与撤销 | 关闭前必须清空全部未决项（`RECALL_OPEN_ITEMS`）；未发生替换核销的召回可带原因撤销（未决项与凭证作废）；已核销的召回只能关闭不能回退；重复关闭/撤销幂等返回当前状态 |
| 召回盲态边界 | 配药端只见本站中性盒码+随机编码（无批号无分组）；研究端只见是否需联系+阶段；安全端跨中心汇总仅计数；审计明细不写 arm |
| 不可变事件 | 业务事务在同一 `BEGIN IMMEDIATE` 内先写 `platform_events`：全平台单调 `seq`、`prev_digest` 哈希链、规范正文 `body_digest`、签发瞬间 `sub_version`、Ed25519 签名；只追加永不 UPDATE/DELETE，`GET /api/safety/event-integrity` 重算全链证伪篡改 |
| 订阅过滤 | 安全管理员登记按 事件种类 × 中心 × 角色 过滤的端点；空清单=全收；平台级事件（正常揭盲/召回，center 为空）不受中心维度限制；同一 URL 重复订阅稳定返回原配置、不重发密钥 |
| 投递密钥边界 | 投递 HMAC 密钥仅登记成功响应回显一次（带外交付），库内仅存 pepper 混淆密文与摘要；任何列表/审计/错误/重试日志都不回显；请求头 `X-RTS-Signature` 只在投递时现算 |
| 租约与并发 | 领取在写事务内只挑"到期 + 同订阅前序已终结"的最早一条并写 `leased`+owner+过期时刻；两 worker 同时只有一个持有效租约；租约过期后凭过期条件被他人接管，旧 owner 复活提交条件 UPDATE 失配（`LEASE_LOST`）不覆盖结论 |
| 退避/死信/重放 | 失败按指数退避（2/5/15/40/90s）回到 queued，6 次（首发+5）转 dead；安全管理员逐条重放**复用原签名事件包**，不改正文、不产生新业务事件；重复重放已送达记录幂等；端点停用→`ENDPOINT_PAUSED`，前序未终结→`DELIVERY_ORDER_CONFLICT` |
| 事件顺序 | 同订阅严格按 seq：存在更小 seq 未终结（queued 或租约有效）时后序不可领取，乱序在领取侧稳定跳过 |
| 投递去重 | 每包带 `event_id`/`seq`/订阅版本请求头；at-least-once（成功后崩溃接管会重投），订阅方按 `X-RTS-Event-Id` 幂等去重；`(订阅,事件)` 唯一约束兜底 |
| 库外可验证 | `GET /api/verify-materials` 公布全部 Ed25519 公钥（含已轮换）+链锚点；`python -m rts.verify_events e.json --materials m.json --chain` 在库外核对序号连续/正文/签发版本/签名；换钥保留旧公钥，历史事件随时可验 |
| 重启继续 | 队列状态全部落盘；SIGKILL 后重启，后台线程继续领取 queued/退避到期/接管过期租约/处理死信重放，已生成历史事件不回写（见 test_event_restart） |

## 主要 API

```
POST /api/login | POST /api/logout | GET /api/me
POST /api/investigator/eligibility
POST /api/investigator/enroll
GET  /api/investigator/subjects
POST /api/investigator/emergency-unblind/{random_no}      # body: {"reason": "..."}
GET  /api/pharmacy/kits
POST /api/pharmacy/dispense        # {"random_no": "...", "kit_no": 可选}
POST /api/pharmacy/return          # {"kit_no": "...", "note": 可选}
POST /api/pharmacy/restock         # {"kit_no": "..."}
GET  /api/pharmacy/kits/{kit_no}/history
GET  /api/safety/status
POST /api/safety/data-lock
POST /api/safety/unblind-requests
POST /api/safety/unblind-requests/{id}/approve
GET  /api/safety/unblind-requests | /api/safety/unblind-requests/{id}
GET  /api/safety/emergency-list
GET  /api/safety/audit
POST /api/safety/lots | POST /api/safety/kits
GET  /api/safety/invariants
POST /api/safety/recalls                     # {"lot_nos": [...], "reason": "..."}
GET  /api/safety/recalls | /api/safety/recalls/{id}
POST /api/safety/recalls/{id}/close          # 未决项未清空 → 409
POST /api/safety/recalls/{id}/revoke         # {"reason": "..."}；已核销的召回 → 409
POST /api/safety/recall-items/{id}/review-exemption   # {"approve": true|false}
POST /api/safety/recalls/unfreeze            # {"kit_no": "..."} 质检解冻
GET  /api/pharmacy/recall-items              # 本站待处置项（中性盒码+随机号）
POST /api/pharmacy/recall-items/{id}/recover # {"kit_no": "..."} 扫码回收
POST /api/pharmacy/recall-items/{id}/exempt  # {"reason": "..."} 登记医疗豁免
POST /api/pharmacy/recall-items/{id}/voucher # 生成一次性替换凭证
POST /api/pharmacy/recall-vouchers/redeem    # {"voucher_no": "...", "kit_no": 可选}
GET  /api/investigator/recall-notices        # 是否需联系 + 处置阶段

# ---- 平台事件签名出站队列 ----
POST /api/safety/event-subscriptions          # {name,endpoint_url,kinds[],centers[],roles[]}；密钥仅此一次回显
GET  /api/safety/event-subscriptions          # 列表（无密钥）
GET  /api/safety/event-subscriptions/{id}
POST /api/safety/event-subscriptions/{id}/pause
POST /api/safety/event-subscriptions/{id}/resume
GET  /api/safety/event-deliveries?status=&subscription_id=
GET  /api/safety/event-deliveries/{id}        # 含逐条重试流水（稳定错误码，无正文/密钥）
POST /api/safety/event-deliveries/{id}/replay # 死信逐条重放（复用原事件，不造新事件）
GET  /api/safety/events?limit=&kind=          # 安全端事件清单（含签名包）
GET  /api/safety/event-integrity              # 序号/哈希链/正文摘要/签名巡检
POST /api/safety/rotate-signing-key           # 签发密钥轮换（旧公钥保留）
GET  /api/verify-materials                    # 公开：全部公钥 + 链锚点（无需登录）
GET  /api/events/{seq} | /api/events/by-id/{event_id}   # 公开：签名事件包
GET  /api/investigator/events                 # 研究端：本中心+平台级事件摘要（无正文/密钥）
```
所有需认证接口带 `X-Authorization: Bearer <token>`，按服务端会话角色鉴权并做中心隔离。

## 测试

```bash
python -m pytest rts/tests/ -q
```

覆盖：区组平衡/序列确定性、重复入组幂等、同受试者与不同受试者并发、跨中心跨版本分层、
盲态文本零泄露、角色与中心隔离、应急揭盲单受试者、并发抢最后一盒（200/409 各一）、
首选批号缺货转兼容批号、退药→再入库→再发、数据锁定+双人揭盲审批、20 例随机操作流
守恒模糊测试，以及**真实 uvicorn 进程 SIGKILL 后重启**的持久性；
召回闭环：发布冻结与范围快照、回收/豁免/凭证/核销全流程、并发核销同一凭证单一发放、
重复回收/重复核销/重复关闭/重复撤销幂等、撤销后冻结不误恢复、已核销召回不可回退、
非法跳转统一冲突、召回各表面零 arm 泄露、重连后续作（38 项）。
事件出站队列（29 项）：不可变事件链与签名、种类×中心×角色过滤与 fan-out、
重复订阅/暂停幂等、两 worker 租约互斥与过期接管、成功后崩溃重投按 event_id 去重、
退避→死信→逐条重放（不改正文/不造新事件）、顺序冲突与停用冲突稳定结果、
药房 403/研究端中心隔离/审计与错误零密钥零 arm、库外 CLI 验签与篡改检出、换钥后旧事件可验，
以及**真实 uvicorn 进程 SIGKILL 重启后**未发/失败重试记录继续投递、历史事件不回写。

## 目录

```
rts/
  db.py             schema、WAL 连接、串行事务（含事件表/订阅/投递/签发密钥）
  service.py        全部领域规则（随机序列、盲态匹配、守恒、揭盲流程），业务事务内发事件
  events.py         不可变事件链、Ed25519 签发/轮换、订阅过滤、出站队列（租约/退避/死信/重放）
  verify_events.py  库外签名事件包核对 CLI（序号/正文/签发版本/哈希链/签名）
  main.py           FastAPI 持久化接口 + 后台投递线程
  seed.py           演示数据
  static/           角色页面（新增 events.html 事件出站队列页）
  tests/            pytest 场景测试（含真实进程重启）
```

### 后台投递队列与环境变量

- 服务启动即运行一个后台投递线程（间隔 `RTS_QUEUE_INTERVAL`，默认 1s；租约时长
  `RTS_QUEUE_LEASE` 默认 30s）。置 `RTS_QUEUE_ENABLED=0` 可关闭（测试用）。
- 投递为 at-least-once：网络成功但落 `sent` 前崩溃，接管 worker 会重投同一事件包，
  订阅方必须用请求头 `X-RTS-Event-Id` 幂等去重，并用 `X-RTS-Signature`（HMAC-SHA256，
  算法标识 `X-RTS-Delivery-Alg`）核验来源。

### 库外核对示例

```bash
curl -s http://localhost:8000/api/verify-materials -o materials.json
curl -s http://localhost:8000/api/events/1 -o event-1.json
python -m rts.verify_events event-1.json --materials materials.json
# 多事件加 --chain 同时核对序号连续与链锚点；退出码 0 通过 / 2 被改动
```

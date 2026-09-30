# 医疗行为与同意依据事后对账模块

零外部依赖（Python 3.11 标准库 + SQLite WAL）。模块把许可引擎中读取到的历史许可**固化为自己的不可变快照**，
接收采血、影像、用药、留样系统的执行声明，并严格按**实际发生时刻**裁定依据是否存在、是否在范围、是否已经终止。

> 核心原则：后补材料只能进入下一次重算并产生新版本；若许可快照在行为发生后才被观察到，
> 它不能把发生当时无资格的行为追认成“已解释/合规”。

## 运行

```bash
cd reconcile
python3 server.py
# 默认 http://127.0.0.1:8090，首次启动自动建库和演示数据
RECONCILE_DB=/data/recon.db RECONCILE_PORT=9000 python3 server.py
```

演示账号：

| 角色 | 账号 / 密码 | 机构 |
|---|---|---|
| 合规人员 | `comp` / `comp-pass` | 全局 |
| 研究站点 | `sitea` / `site-pass`，`siteb` / `site-pass` | INST-A / INST-B |
| 参与人 | `wang` / `wang-pass`，`zhao` / `zhao-pass` | INST-A / INST-B |

## 验证

```bash
cd reconcile
python3 tests/verify.py
```

脚本启动真实 HTTP 服务，包含线程级双重算竞争，以及“发布后、响应前进程退出”后重启恢复。
当前覆盖 **37 项断言**：正常匹配、终止前后分流、迟到声明、同标识异文、带版本更正、
跨机构批次回滚、双重算、崩溃恢复、旧处置待复核、角色/机构/参与人隔离等。

## 时间点裁定

声明匹配键为：

```text
实际发生时刻 + 对象 + 中性操作码 + 用途 + 依据版本
```

四类源系统映射到中性操作码：

| 来源 | 中性操作码 |
|---|---|
| `blood` | `blood_draw` |
| `imaging` | `imaging` |
| `medication` | `medication` |
| `sample` | `sample_retention`（兼容许可引擎 `sample_reuse` 语义） |

版本发布时，对周期窗口 `[starts_at, cutoff_at)` 内每个声明的**最新已接受修订**生成一条不可变结果：

| 结果 | 含义 |
|---|---|
| `explained` | 发生时刻之前已观察到许可快照；授权已签发、覆盖该操作/用途、依据版本一致且未终止 |
| `missing_basis` | 发生时刻之前没有该对象/版本依据，或许可签发晚于行为 |
| `out_of_scope` | 同一依据版本在当时存在，但不覆盖该操作或用途 |
| `post_termination` | 发生时刻之前可见的依据状态已终止，且终止时刻 ≤ 发生时刻 |
| `awaiting_late_materials` | 声明自身标记 `awaiting_materials`，等待迟到资料补齐 |

许可快照有两个时间：`observed_at` 是对账模块从许可引擎读取/固化的时刻，`granted_at`/`terminated_at`
是依据自身状态时间。只有 `observed_at <= occurred_at` 的快照有资格裁定该行为。

## 不可变与版本链

- `consent_snapshots` / `snapshot_entries` 只追加；同一来源水位线异文冲突会拒绝。
- 执行声明按 `claim_id + revision` 追加：
  - 同 `claim_id` 且规范正文完全相同：返回首个 `receipt`，`replayed=true`。
  - 同 `claim_id` 但时间、对象、用途或正文不同且未引用上一版本：`409 claim_payload_mismatch`。
  - 更正必须 `supersedes_revision=<当前最新 revision>`；旧行保留为 `superseded`，新行成为当前版本。
- 批量导入在一个 `BEGIN IMMEDIATE` 事务中预检并提交；任一 JSON/字段损坏或批次包含非 `inst_scope`
  对象，整批回滚，不留下部分声明。
- 重算版本按输入水位幂等：快照、声明最新修订没有变化时返回同一版本。
- 版本与差异项发布后不可更新；新声明、更正或新快照只能产生新版本。
- 两个重算进程并发时，SQLite 写锁串行化事务，`UNIQUE(cycle_id,input_watermark)`
  保证同一输入只发布一个版本；失败者回滚，临时结果不可见。

## 发布后崩溃恢复

发布流程在同一事务中写入 `reconciliation_versions` 与全部 `reconciliation_items` 后提交。
演示/测试可在请求体传：

```json
{"crash_after_publish": true}
```

服务会在事务提交后、HTTP 响应前调用 `os._exit(7)`。重启后再次重算会读取已发布版本并幂等返回，
不会生成新的版本号，也不会重复生成差异项。

## 处置与复核

合规人员处置差异时必须记录：

- `adopted_snapshot_id`：采用的许可快照版本；
- `decision`：`accepted` / `escalated` / `waived`；
- `reason`：理由。

`dispositions` 为追加表。每次重算时，若同一 `claim_id` 的源声明修订、正文哈希，或当时匹配的
输入快照发生变化，旧处置自动变成 `needs_review`，但 `original_decision/original_reason/original_snapshot_id`
原样保留；复核提交新处置，旧行成为 `superseded` 并链接到新行。

## 页面与 API

- `/`：登录后按角色进入对应工作台。
- 合规：周期版本、重算、五类结果、差异处置、待复核列表。
- 站点：只读取本站版本与差异；不能查看或处置其他机构对象。
- 参与人：只查看与自己相关的历史执行依据及时间点裁定。

主要接口：

```text
POST /api/auth/login
GET  /api/me

POST /api/snapshots                         # 合规：固化许可引擎快照
GET  /api/snapshots                         # 合规：快照水位线/摘要
POST /api/claims                            # 单条声明或更正
POST /api/claims/batch                      # 单机构批量导入
GET  /api/claims                            # 合规/站点声明队列

POST /api/cycles                            # 合规：创建周期
GET  /api/cycles
POST /api/cycles/{cycle}/recompute
GET  /api/cycles/{cycle}/versions
GET  /api/cycles/{cycle}/versions/latest
GET  /api/cycles/{cycle}/site-items         # 站点：只含本站

POST /api/items/{id}/disposition            # 合规：处置
GET  /api/dispositions?status=needs_review
GET  /api/my/executions                     # 参与人：本人
```

## 从现有许可引擎只读导入

也可以直接只读打开 `consent/consent.db`，把其中许可状态固化为对账快照（库内仍生成独立副本，
许可库不会被写入）：

```python
import db, service
db.init_db()
service.import_from_consent_db(
    db.get_conn(),
    "/workspace/consent/consent.db",
    source_watermark="manual-001",
    observed_at="2026-09-10T00:00:00Z",
)
```

生产集成可把该函数替换为许可引擎的只读导出 API；关键约束不变：导入时刻和正文摘要必须落盘，
且对账模块后续不再改写快照。

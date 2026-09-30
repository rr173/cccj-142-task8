# 医疗行为与同意依据事后对账模块

零外部依赖 Python 3.11 + SQLite(WAL) 实现。模块从许可引擎接收**不可改写历史快照**，
并接收采血、影像、用药、留样系统的执行声明，按**行为实际发生时刻、对象、中性操作码、
用途、依据版本**做时间点匹配。后补材料只能进入后续新版本，不能把当时无资格的行为追认成合规。

## 运行

```bash
cd reconcile
python3 server.py                         # 默认 http://127.0.0.1:8090
RECONCILE_DB=/data/reconcile.db python3 server.py
```

演示账号（密码均为 `demo1234`）：

| 角色 | 账号 | 范围 |
|---|---|---|
| 合规人员 | `compliance` | 全局：导入快照、周期重算、处置、复核 |
| 北京站点 | `sitea` | `INST-A`：上报/查看本站声明与差异 |
| 上海站点 | `siteb` | `INST-B`：上报/查看本站声明与差异 |
| 参与人 | `wang` / `zhao` | 仅本人相关许可依据与执行记录 |

## 五类对账结果

| 结果 | 含义 |
|---|---|
| `explained` | 发生时刻存在引用的对象/依据版本，许可未终止，操作码与用途均在范围内 |
| `missing_basis` | 引用版本不存在、未生效，或当时没有覆盖该行为的依据 |
| `out_of_scope` | 依据当时有效且未终止，但中性操作码或用途超出许可范围 |
| `post_termination` | 引用依据在行为发生前已经终止/撤销 |
| `awaiting_late_material` | 许可引擎尚未补送引用依据；等待迟到资料进入下一重算版本 |

若后补快照的生效时刻晚于行为时刻，新版本判定为 `missing_basis`，不会升级为 `explained`。

## 关键不变量

1. **历史只追加**：`permit_snapshots`、`permit_terminations`、`claim_versions`、
   `claim_attempts`、`reconciliation_versions`、`reconciliation_items` 均由 SQLite trigger
   禁止 UPDATE/DELETE。
2. **声明幂等与冲突**：相同声明标识 + 相同规范正文稳定返回同一回执；同标识异文且未显式
   `replaces_version` 返回 `claim_identifier_conflict`。
3. **更正链**：更正必须引用当前 `current_version`；旧版本、正文指纹、回执和差异链全部保留，
   指针只更新到新版本，不覆盖原记录。
4. **批量原子性**：任一声明格式损坏或批次中出现跨机构对象，整批回滚；没有任何半条声明可见。
5. **版本互斥**：重算先计算不可见候选，再在 `BEGIN IMMEDIATE` 中抢活动租约并发布。
   同周期并发时只发布一个版本，竞争进程返回已发布版本或租约冲突；失败临时结果不提交、不可见。
6. **发布后崩溃恢复**：版本与差异项在同一事务提交。提交后、响应前崩溃，重启识别既有版本；
   输入未变化不会再次生成差异项。
7. **处置保留与失效重审**：处置记录保存结论、理由、采用快照版本和决定人。来源声明更正，
   或同意快照/分类结果变化时，旧处置自动标记 `stale_pending_review`；原结论和理由永不覆盖。

## 页面

- `/static/compliance.html`：合规人员的周期重算、版本结果、差异处置、旧处置复核、
  许可快照/终止事件/执行声明导入。
- `/static/site.html`：研究站点仅查看本站差异，不带其他机构对象、用途正文或处置人之外的数据。
- `/static/subject.html`：参与人查看本人许可快照、终止记录、执行声明的对账依据和版本结果。

## 主要 API

```http
POST /api/auth/login
GET  /api/me

POST /api/permit-snapshots       # compliance：{permit_id,subject_id,family,basis_version,
                                 #  scope[],allowed_purposes[],effective_at,snapshot_version,body_hash}
POST /api/permit-terminations    # compliance：{permit_id,terminated_at,reason,snapshot_version}

POST /api/claims                 # compliance/site；更正带 replaces_version
POST /api/claim-batches          # {"claims":[...]}；格式损坏或跨机构整批回滚
GET  /api/claims/{claim_id}      # 全版本、差异链、接收/拒绝回执

POST /api/cycles
GET  /api/cycles
POST /api/cycles/{cycle_id}/recompute
GET  /api/cycles/{cycle_id}/latest
GET  /api/versions/{version_id}

POST /api/items/{item_id}/disposition
                                 # {resolution,reason,adopted_snapshot_version}
GET  /api/dispositions/stale
POST /api/dispositions/{id}/review
                                 # {review_note}

GET  /api/subject/basis          # subject：仅本人
```

中性操作码固定为 `BLOOD_DRAW`、`IMAGING`、`MEDICATION`、`SAMPLE_RETENTION`。
来源系统固定为 `blood_station`、`imaging`、`medication`、`sample_bank`；来源系统专属字段
放在 `payload`，匹配只使用规范后的中性操作码。

## 验证

```bash
# 当前环境没有 pytest 时可运行标准库验证器（覆盖 11 个核心场景）
python3 tests/verify.py

# 真实 HTTP 子进程：发布事务提交后、响应前 os._exit，重启后恢复
python3 tests/test_restart.py
```

覆盖场景：

- 正常匹配与五类结果；终止前/后两笔行为分流；
- 迟到声明进入新版本，旧版本不重写；
- 同标识同正文同一回执、同标识异文拒绝；
- 带版本更正与差异链保留；
- 格式损坏、跨机构和多机构批次原子回滚；
- 两个重算进程同时处理同一周期只发布一个版本；
- 发布后崩溃恢复，不重复生成差异项；
- 快照变化或声明更正后旧处置自动待复核且保留原判断；
- 合规/站点/参与人三角色数据隔离；
- 触发器阻止改写许可快照、声明版本和已发布对账结果。

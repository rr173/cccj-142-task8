# 电子知情同意与医疗操作许可引擎

零外部依赖实现（Python 3.11 标准库 + SQLite WAL），覆盖**规则维护 / 现场办理 / 参与人自助**三套页面、
持久化存储与 HTTP API。所有状态变更走 `BEGIN IMMEDIATE` 单事务并追加单调事件流水，
因此签名、撤销、执行确认、材料停用等并发竞争都按**持久化先后**收敛为唯一且可说明的状态。

## 运行

```bash
python3 server.py                 # 默认 http://127.0.0.1:8088，首次启动自动建库+种子
CONSENT_PORT=9000 python3 server.py
CONSENT_DB=/data/consent.db python3 server.py
```

打开 `http://127.0.0.1:8088/` 登录。演示账号（仅演示，密码为弱口令）：

| 角色 | 账号 / 密码 | 机构 |
|---|---|---|
| 规则维护员 | `admin` / `admin-pass` | 全局 |
| 现场负责人 A 院 | `sitea` / `site-pass` | INST-A |
| 现场负责人 B 院 | `siteb` / `site-pass` | INST-B |
| 参与人 王/李 | `wang` / `wang-pass`，`li` / `li-pass` | INST-A |
| 参与人 赵 | `zhao` / `zhao-pass` | INST-B |

见证者**无需账号**：现场开单/会话详情里生成一次性签名链接（`witness.html?session=…&role=witness&token=…`），
链接用后即失效。

## 可验证的场景

```bash
python3 tests/verify.py
```

脚本会启动临时库上的真实 HTTP 服务（含 SIGKILL 重启与多线程并发），64 项断言覆盖：

1. **首次完整签署** —— 三角色对同一封存指纹落款齐备才生成许可；查询返回材料版本/获准范围/尚缺条件。
2. **缺少见证者** —— 办理进度明确缺项，操作前查询与执行确认拒绝。
3. **双终端重复落款** —— 同一可信设备/同一幂等键并发，双方拿到同一首次结果、只落一笔签名和一条设备证明；异文、换设备或他机构冲突稳定失败。
4. **办理途中停用材料** —— 在途会话立即 `blocked`，不能再签、不能对停用版开新单、不降级旧版；已发许可继续有效。
5. **修订触发再次同意** —— 新版把操作标成需再次同意后，未发生操作立即冻结，已完成操作保留旧依据，新版补签齐备解锁；无关操作不受影响。
6. **不改变许可范围的修订**（无再次同意标记）—— 既有许可不被误伤，正常放行。
7. **异常退出后接续** —— SIGKILL 重启后未结束会话可核对、签名与落款时刻不变、会话仍钉在旧版本不挪给后续版本。
8. **撤销与执行确认竞争** —— 只按事件流水 `seq` 产生一种结果；重复撤销/重复执行均幂等；撤销后无任何越权新操作。
9. **设备可信网关** —— 未注册、跨站、封禁、旧代凭据、挑战过期、换角色/会话/正文指纹均失败；同载荷重试复用首回执。
9. 附加：跨机构列表/审计/报错 PII 隔离、维护员不能落款、未批准译文不出现在办理界面、新增用途唯一登记与撤销前记录保留。

另有两个临时压测（见会话记录）对 12 组撤销/执行并发验证两种先后顺序都能唯一收敛。

## 关键设计

### 封存与版本化
- `materials` 每行是一次**封存**：正文、语种、适用条件、必签角色、允许操作共同参与 SHA-256 指纹 `body_hash`。
- 同 `track_key = hash(family|机构|语种|条件JSON)` 下，正文或覆盖范围（角色/操作/再次同意标记）一旦变化，
  发布即自动 `version+1`；完全无变化返回 `409 unchanged_version`，不制造伪版本。
- 每个 track 对现场只呈现**最新现行版**；界面不允许拼接未批准译文（语种不一致直接不呈现）。

### 会话钉版与三角色签署
- 开单时把会话钉死在某个 `material_id`；后续发布新版本、停用都不会挪动它。
- 签署位按材料的 `roles_json` 创建；参与人/现场负责人需登录且机构/本人匹配，见证者持一次性令牌免登录。
- 每笔签名保存签署时的 `body_hash`；**全部**必签角色对同一份封存内容完成后，在同一事务里把会话置为
  `completed` 并生成许可。`signatures.created_at` 只由数据库事务写入，全代码库没有更新该列的入口，后台无法改落款时刻。
- 幂等：客户端 `idempotency_key`（缺省前端自动生成）+ 服务端槽位内容哈希双保险。
  同一落款人重复提交→回放首次结果；不同落款人抢同一槽位→`409 slot_filled_by_other`，以先提交者为准。

### 许可评估、再次同意与撤销
- 许可裁定者 = **最新一份覆盖该操作的许可**；它若被撤销，不回落到更旧许可复活权限。
- 再次同意冻结：同 track 出现带 `requires_reconsent` 的现行新版且版本更新时，`evaluate` 返回
  `frozen_reconsent`，并指出需要补签的版本与尚缺会话；不追溯此前已 `performed` 的记录。
- 撤销：进行中会话→`withdrawn`；已发许可→`revoked`。撤销前执行记录原样保留（仍引用旧 family/version），
  其后新操作、`sample_reuse` 的新增用途一律拒绝。
- `executions` 对 `(对象,操作,用途)` 有部分唯一索引：同一“新增用途”只能形成一次 performed。

### 设备可信证明网关
- 主体端、站点端和外部见证链接的所有状态变更（开单、轮换见证链接、三类落款、撤销、执行确认）都必须先领取短时挑战，并在 `X-Device-Attestation` 中提交本站已登记 P-256 终端的签名。
- 设备按登录主体或具体见证签署位登记，凭据绑定机构、硬件标识、公钥哈希与代次；未注册浏览器、跨站设备、被停用硬件、旧代凭据、过期授权均在业务状态机前稳定失败。
- 挑战绑定动作、资源、角色、正文摘要、随机数与一次性见证链接；改换会话/机构、角色或正文指纹均不能通过。
- 挑战消费、`device_attestations` 留痕、幂等回执和业务行在同一个 `BEGIN IMMEDIATE` 事务提交；崩溃恢复不会制造第二次变更。同载荷用同一幂等键重试只返回首个回执，异文/换设备稳定冲突。
- 修复前已落盘的业务记录不回填、不删除，继续可查可验；新记录必须能在设备审计中对应到设备、凭据代次与证明。

### 隔离
- 现场接口一律限定本机构；跨机构访问对象/会话统一返回 `404 …_not_found`，报错不暴露他人存在。
- 审计：现场只见本机构事件；维护员全局可见但参与人身份与签名人姓名打码；参与人仅见本人。
- 维护员角色在服务端被拒绝任何签署（`403`），页面也无落款入口。

## 目录

```
consent/
├── server.py        # 标准库 HTTP API + 静态页路由（ThreadingHTTPServer）
├── engine.py        # 领域引擎与设备证明网关（发布/会话/签署/评估/执行/撤销/审计，全部事务化）
├── trust.py         # P-256/SHA-256 规范摘要与签名核验
├── db.py            # SQLite 连接、schema、迁移、封存指纹与 track 键
├── seed.py          # 空库种子（两机构、三套账号、一份封存材料）
├── static/          # index/admin/site/subject/witness 五页 + app.js + styles.css
└── tests/
    ├── verify.py    # 8 大场景 + 隔离附加项的端到端断言
    └── client.py    # HTTP 客户端、并发屏障、SIGKILL 重启工具
```

## 主要 API

所有状态变更接口还必须携带 `X-Device-Attestation`（由浏览器 `/static/trust.js` 自动完成挑战-响应）。

| 方法 路径 | 角色 | 说明 |
|---|---|---|
| `POST /api/auth/login` | 公开 | 登录换令牌 |
| `POST /api/admin/device-enrollments` | admin | 签发主体终端一次性登记授权 |
| `POST /api/devices/register` | 公开（授权码） | 登记/轮换可信浏览器硬件与 P-256 公钥 |
| `POST /api/devices/challenge` | 主体或见证链接 | 领取绑定动作/资源/角色/正文摘要的短时挑战 |
| `POST /api/devices/rotate-code` | admin/site | 签发设备密钥换代授权 |
| `POST /api/devices/revoke` | admin/site | 停用硬件并作废当前凭据 |
| `GET /api/device-audit` | admin/site | 设备、凭据代次与业务证明审计 |
| `POST /api/materials` | admin | 封存发布（变化即新版） |
| `POST /api/materials/{id}/retire` | admin | 停用并冻结在途会话 |
| `GET /api/materials` | admin/site | 版本列表（现场限本机构） |
| `GET /api/subjects` / `GET /api/subjects/{id}/eligibility` | site | 本机构对象与吻合材料（不吻合给原因） |
| `POST /api/subjects/{id}/sessions` | site | 对吻合的现行版开单（钉版） |
| `GET /api/sessions` `GET /api/sessions/{sid}` | site/subject | 办理进度与具体缺项 |
| `POST /api/sessions/{sid}/tokens` | site | 生成见证者一次性链接（旧链接失效） |
| `POST /api/sessions/{sid}/sign` | 三类 | 参与人/现场登录签署，见证者 token 签署 |
| `POST /api/sessions/{sid}/revoke` | subject | 撤销办理意愿或许可（幂等） |
| `GET  /api/subjects/{id}/check?op=&purpose=` | site | 操作前查询：版本依据/获准范围/尚缺条件 |
| `POST /api/subjects/{id}/execute` | site | 执行确认（与撤销竞争时按落盘先后） |
| `GET /api/subjects/{id}/permits` `/executions` | site/subject | 当前许可与历史记录 |
| `GET /api/audit` | 三类 | 事件流水（按角色过滤/打码） |

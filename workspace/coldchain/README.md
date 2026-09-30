# 临床试验用药冷链证据模块

接收运输设备上传的**中性运单号、传感器编号、采样区间与温度片段**，合并实际采样
时间线、识别缺口与连续温度越界，在网页上展示每个运单的完整时间线、缺口、越界
事件与最终处置状态，并导出**可在数据库之外重新校验**的不可变处置凭据。
与 `../rts`（随机分组与盲态药盒分配平台）是同一体系的姊妹模块，全模块不出现
治疗组、分配臂、批号兼容等任何盲态信息。

## 技术栈与持久化

- Node.js（ESM，Node ≥ 20）+ 原生 `http`，零 Web 框架；`better-sqlite3` 同步驱动。
- SQLite：`journal_mode=WAL` + `synchronous=FULL`；所有写操作走 `.transaction().immediate()`，
  同一连接写天然串行，配合条件 `UPDATE … WHERE state=…` 与唯一索引处理并发。
- 凭据签名：Ed25519（`node:crypto`），模块密钥首启生成、随库持久化；
  浏览器端用 WebCrypto（SubtleCrypto）做库外验签与重算。

## 运行

```bash
cd coldchain
npm install
npm run seed                 # 初始化并播种演示数据（data/coldchain.db）
npm start                    # http://localhost:8080/  （COLDCHAIN_PORT 可改端口）
```

环境变量：`COLDCHAIN_DB`（库文件路径）、`COLDCHAIN_PORT`（默认 8080）。

### 演示账号（密码均 demo1234）

| 角色 | 账号 | 说明 |
|---|---|---|
| 运输设备 | dev1 / dev2 | 建运单、上传片段（可乱序补传、重复重传） |
| 质量管理员 | qm1 / qm2 | 两人；撤销复核必须异名 |
| 研究站点 | site1 | 只读，只见中性运单号 + 能否接收 + 简化原因 |

演示运单：`WB-1001` 合规已接收（凭据已签发）、`WB-1002` 连续越界已隔离且撤销待复核、
`WB-1003` 只传了前段（待补传）、`WB-1004` 按新规则版本固化、完整待处置。

## 页面

- **登录** `/static/index.html`；凭据持有方有公开入口 `/static/verify.html`（无需登录、不连库）。
- **设备上传** `/static/device.html`：建运单、贴片段 JSON；运单时间线表（片段/点数、缺口、越界、状态）。
- **质量管理员** `/static/quality.html`：处置台、完整证据（规则快照、原始片段与哈希、
  缺口明细、越界事件、合并时间线 SVG、计算明细、版本链）、确认/撤销、复核队列、
  规则版本发布、凭据导出、审计日志、凭据库外校验面板。
- **研究站点** `/static/site.html`：仅中性运单号、是否可接收、简化原因。

## 关键规则如何落地

| 要求 | 实现 |
|---|---|
| 规则版本固化 | 建单时把 `version/允许区间/连续越界秒/校准偏移` 复制进 `waybills` 快照列；`temp_rules` 改版只影响新运单 |
| 同标识同正文幂等 | `UNIQUE(waybill_id,fragment_no)` + 对**采样正文**的规范化 SHA-256；重传返回原回执（`idempotent:true`、原片段 id、原上传时间） |
| 同标识不同正文拒绝 | 哈希不同 → `409 FRAGMENT_CONTENT_CONFLICT`，原证据不覆盖；审计留痕 |
| 重叠区间逐点合并 | 声明区间并集判缺口；`sample_points` 以时刻为主键，合并预检逐点比对，相同收敛为一个点，不同 → `409 POINT_CONFLICT`，冲突点全量返回、片段整体不落库 |
| 缺口不静默 | 前置/中间/尾部/越界五类缺口逐段列出；缺失区间绝不补点，缺口打断越界连续段 |
| 连续越界 | 用合并后的**实际采样时刻**计时（首末点之差），实测值 + 校准偏移后判定；时长 `> max_breach_sec` 才记 breach |
| 未齐不出结论 | 有缺口/冲突/越界异常时 `state=collecting`、`suggested_disposition=null`；完整才转 `ready`，确认接口在非 ready 时拒绝 |
| 并发双确认 | `UPDATE waybills SET state='decided' WHERE state IN('ready','revoked')` 条件抢状态，写事务串行；落败方幂等返回原决定，`decision_versions` 仅一行 |
| 决定后补传 | 存在任何决定版本即证据封冻，新片段号 → `409 EVIDENCE_SEALED`；原片段同正文重传仍幂等 |
| 撤销双人复核 | `revoking` 待复核；部分唯一索引保证同单只有一个 pending；必须**另一名**质量管理员批准/驳回，重复处理幂等；批准后 `revoked` 可重新决定 |
| 前后版本保留 | `decision_versions` append-only，新决定 `revokes_revision` 指向前版本，旧版本永不删除/覆盖 |
| 重启可用 | WAL+FULL，运单/片段/会话/待复核撤销/规则快照全部落盘；重开进程继续未完成上传与复核（见 `tests/test_restart.js`） |
| 盲态边界 | 输入侧敏感词守门（治疗组/分配臂/批号/批次/arm/lot/batch 等）直接拒绝；站点视图只有 `waybill_no/status/receivable/reason`；审计与错误不写盲态信息 |
| 不可变凭据 | Ed25519 签名的自描述信封：运单中性标识、规则版本与全部参数、全部片段正文、分析明细、决定版本链及各自摘要；每决定版本最多一份（重签幂等） |
| 库外重算校验 | 只用模块公钥：验签 → 重算片段集摘要 → 用凭据内规则重跑时间线 → 重算决定链摘要。CLI：`src/verify.js`；网页：`/static/verify.html`；接口：`POST /api/verify-credential` |

## 主要 API

```
POST /api/login | POST /api/logout | GET /api/me
GET  /api/public-key                         # 模块公钥（公开）
POST /api/verify-credential                  # 不查库的重算校验（公开）

POST /api/quality/rules                      # 发布规则版本（之后新运单默认引用）
GET  /api/quality/rules

POST /api/device/waybills                    # 建运单（同号重试幂等，参数不同冲突）
GET  /api/device/waybills | /api/device/waybills/:no
POST /api/device/waybills/:no/fragments      # 上传片段（幂等/正文冲突/点冲突/封冻）

GET  /api/quality/waybills | /api/quality/waybills/:id
POST /api/quality/waybills/:id/confirm       # {disposition: accept|quarantine, reason}
POST /api/quality/waybills/:id/revoke        # 撤销申请（理由必填）
GET  /api/quality/revocations
POST /api/quality/revocations/:id/review     # {approve, note}；同人 403
POST /api/quality/waybills/:id/credential    # 签发/幂等取回凭据
GET  /api/quality/audit

GET  /api/site/waybills | /api/site/waybills/:no
```
所有业务接口带 `X-Authorization: Bearer <token>`，按会话角色鉴权。

错误码：`FRAGMENT_CONTENT_CONFLICT / POINT_CONFLICT / EVIDENCE_SEALED /
FRAGMENT_OUT_OF_RANGE / SENSOR_MISMATCH / TIMELINE_INCOMPLETE /
REVOCATION_IN_REVIEW / REVIEWER_MUST_DIFFER / NON_NEUTRAL_CONTENT` 等。

## 凭据库外校验

```bash
curl -s localhost:8080/api/public-key > /tmp/pub.jwk            # 带外取得公钥
node src/verify.js CC-0001-WB-1001.json --public-key /tmp/pub.jwk
# 或浏览器打开 /static/verify.html，贴公钥与凭据文件，全程本地计算
```
任一项不过即 `ok:false` 并给出失败检查（签名 / 片段摘要 / 分析重算 / 决定链摘要）。

## 测试

```bash
npm test
```
28 项，覆盖：规范化哈希与表示无关性、片段校验、重叠合并/逐点冲突、
缺口分类与不补点、连续越界被缺口打断、校准偏移、规则版本固化、
同标识幂等/正文冲突、未齐待补传、并发双确认单一决定、决定后封冻、
撤销异名复核与版本保留、角色鉴权、并发撤销部分唯一索引、
凭据五类篡改检测、真实模块重启后的会话/上传/复核持久性。

## 目录

```
coldchain/
  src/
    db.js          schema（WAL/FULL/外键）、Ed25519 模块密钥持久化
    engine.js      纯函数：规范化哈希、逐点合并、缺口、连续越界（浏览器可复用）
    credential.js  凭据信封构造/签名、库外 verifyCredential
    service.js     领域服务：状态机、幂等/冲突、双人复核、盲态守门、审计
    http.js        原生 http 路由、鉴权、静态页
    seed.js        演示数据
    verify.js      库外校验 CLI
  static/
    index.html device.html quality.html site.html verify.html
    shared/        style.css、api.js、detail.js（时间线 SVG）、verify-web.js
  tests/           node:test 用例（含模块级重启）
```

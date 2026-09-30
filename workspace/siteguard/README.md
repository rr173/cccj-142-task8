# 建设现场签署终端可信登记模块

施工现场浏览器首次登记时用 **Web Crypto** 在本机生成终端密钥（ECDSA P-256，私钥不出设备）
并提交公钥；安全管理员签发的**一次性注册码**只能被一个浏览器成功使用，服务端据此签发
绑定**站点、设备标识、可用角色、有效期与代次**的终端证书。每次业务落款前，终端先领取含
**随机数、业务动作、会话标识、角色、正文摘要、短截止时间**的挑战，再用本地私钥签署
完整请求；网关验完证书、挑战与请求摘要后才把动作转给业务接口。轮换后旧密钥只能核对
历史，隔离设备立即失去后续资格；所有状态 fsync 追加落盘，重启不复活已消费的注册码/随机数。

与同体系 `../coldchain`（冷链证据）、`../consent`（电子知情同意）、`../rts`（随机与盲态）
是姊妹模块：零外部依赖（Node ≥ 20 标准库）、中性编号审计、库外可重算验签。

## 运行

```bash
node src/seed.js                 # 可选：播种演示数据（data/siteguard.wal.log）
node src/http.js                 # http://localhost:8090/
SIGUARD_PORT=9000 node src/http.js
SIGUARD_DATA=/var/lib/siteguard SIGUARD_CHALLENGE_TTL=60000 node src/http.js
```

环境变量：`SIGUARD_DATA`（事件日志目录，默认 `data/`）、`SIGUARD_PORT`（默认 8090）、
`SIGUARD_CHALLENGE_TTL`（挑战短截止毫秒，默认 60000）、`SIGUARD_CERT_MINUTES`（证书有效期分钟，默认 5 天）。

### 演示账号（密码均 demo1234）

| 角色 | 账号 | 范围 |
|---|---|---|
| 安全管理员 | `safeA` / `safeB` | 仅 SITE-A / 仅 SITE-B，互不可见 |
| 中性审计员 | `auditor` | 全局，但只见中性分区 P-1/P-2 与 D-/C-/R-/RC- 编号 |

终端登记**不需要账号**：在终端页粘贴安全管理员签发的一次性注册码即可。

## 页面

- **门户/登录** `/`：管理员入口与模块说明。
- **终端登记/自检** `/static/terminal.html`：展示电子知情同意当前版本 → 本机 Web Crypto
  生成密钥 → 提交登记；自检面板（自证签名查询代次/隔离状态）；挑战-落款演示
  （领取挑战、私钥签署、同请求重放返回首次结果、篡改角色被拒）。
- **安全管理** `/static/admin.html`：签发一次性注册码（明文仅此一次回显）、本站设备与
  证书代次、即时隔离、颁发轮换授权码、本站落款记录。
- **中性审计** `/static/audit.html`：仅审计员；分区与编号，不含站点编码、账号、正文摘要。
- **库外验签** `/static/verify.html`：粘贴自描述记录信封，仅用服务端公钥在浏览器重算
  五条核验（无需登录、不查库）。

## 关键规则如何落地

| 要求 | 实现 |
|---|---|
| 一次性注册码抢占 | `registerCodes.get(code).used` 检查与 `deviceRegistered` 的 fsync 追加在同一同步执行段；两个浏览器并发登记，先持久化者拿到证书，后者稳定收到 `409 REGISTER_CODE_CONSUMED`（8 轮并发断言） |
| 电子知情同意 | 登记 CSR 必须钉住 `GET /api/consent` 的当前 `CONSENT.version`，旧版本 `CONSENT_VERSION_STALE` |
| 终端密钥与证书 | 浏览器 `crypto.subtle` 生成 P-256；CSR 用新私钥自证持有公钥（公钥冒充 `CSR_SIG_INVALID`）；服务端 ECDSA 签发证书，绑定站点/设备/角色/`not_before/not_after`/代次；公钥 JWK 携带私钥字段 `d` 一律 `BAD_PUBLIC_KEY` |
| 挑战绑定 | 挑战是服务端签名的短时令牌：随机数（32 hex）+动作+会话+角色+正文摘要+时间窗；提交时六字段逐字比对，替换任一字段 `409 REQUEST_FIELDS_REPLACED`；伪造/过期分别 `CHALLENGE_BAD_SIG` / `CHALLENGE_EXPIRED` |
| 终端签名 | 私钥签的是**完整请求**规范化对象（含挑战签名）；两端 canonicalize 字节级一致（有一致性测试）；签名编码统一 IEEE P1363 裸 r‖s，浏览器签名可直接验 |
| 相同请求返回首次结果 | 幂等落点 `` `${cert_id}|${nonce}` ``；请求指纹只含**被签署内容**（不含 ECDSA 随机因子产生的签名编码），故两个标签页各自独立签名也判同一请求，返回同一回执/同一 `signed_at` |
| 已用随机数不能换第二结果 | 同 nonce 但请求指纹不同 → `409 NONCE_REUSED`；黑盒可达的复用变体先被字段绑定/挑战签名拦截（纵深防御分支保留） |
| 竞争唯一状态 | 单文件 WAL 顺序追加 + 每条 fsync + Node 单线程同步提交段：双标签争用同一挑战（一首发一 replay）、隔离与提交竞争（12 轮强制交错，两种先后都被观察到且各自唯一收敛） |
| 证书轮换 | 管理员颁发一次性短时轮换授权；终端须用**旧私钥与新私钥双签** CSR；旧证书置 `rotated`——再领挑战 `CERT_ROTATED`，但历史记录随时可验；授权用后 `ROTATION_NONCE_USED`；新证书代次 +1 |
| 设备隔离 | `deviceQuarantined` 事件即时把当前证书置 `quarantined`：领挑战、首次落款都拒绝；重复隔离幂等；**此前成功记录的自描述信封仍完整可验** |
| 重启持久化 | 每条事件 `writeFileSync+fsyncSync`，启动整文件重放（单调 seq 校验）：已消费注册码/随机数不复活，隔离、两代证书、历史验签材料、审计全量存活（见 test_restart） |
| 跨站点隔离 | 所有管理查询按 `site_code` 过滤；跨站操作返回 404（不是 403，杜绝枚举存在性）；注册码列表不回显明文码与站点；终端证书站点与挑战站点不符 `SITE_MISMATCH` |
| 中性审计 | 站点只映射为 `P-1/P-2`，实体只有 `D-/C-/R-/RC-` 编号；审计断言不含 `SITE-A`、账号、正文与正文摘要原文 |
| 库外可验 | 记录信封自描述：终端证书链、挑战令牌、终端请求签名、结果摘要、记录服务端签名五项可仅用 `/api/server-key` 重算；任何字段被改即至少两项变红 |

## 主要 API

```
POST /api/login | POST /api/logout | GET /api/me
GET  /api/consent | GET /api/actions | GET /api/server-key
POST /api/verify-record                 # 公开：库外五项重算

POST /api/terminal/register             # {code, device_label, consent_version, public_jwk, csr_sig}
POST /api/terminal/challenge            # {cert, action, session_id, role, body_digest}
POST /api/terminal/submit               # {cert, challenge, challenge_sig, 六字段, terminal_sig}
POST /api/terminal/inspect              # 任意代次证书自证查询状态（隔离设备也能看到已隔离）
POST /api/terminal/rotate               # {rotation_nonce, new_public_jwk, old_sig, new_sig}
POST /api/terminal/record               # 持某代证书私钥取本设备历史记录信封

POST /api/admin/register-codes          # 安全管理员：{roles, minutes}
GET  /api/admin/register-codes          # 使用状态（不回显明文码）
GET  /api/admin/devices                 # 本站设备与全部证书代次
POST /api/admin/devices/quarantine      # {device_id, reason}
POST /api/admin/certificates/rotate     # {cert_id} -> 一次性轮换授权码
GET  /api/admin/records                 # 本站落款记录

GET  /api/audit?type=&limit=            # 仅中性审计员
```

## 测试

```bash
node --test tests/*.js
```

22 项（含浏览器/服务端规范化一致性 3 项），覆盖需求要求的全部 10 个场景：
正常登记并完成落款（含库外验签）、**注册码并发抢占**（8 轮）、相同请求返回原结果
（含双标签独立签名）、请求字段替换拒绝、挑战过期、**双标签页争用同一挑战**、
**设备隔离与提交竞争**（12 轮两种持久化先后）、证书轮换（旧密钥只能核历史/双签/授权一次性）、
**真实关闭后同目录重启**（注册码与随机数不复活、隔离/轮换/审计存活）、跨站点隔离与中性审计；
另有注册码 TTL、公钥冒充、证书篡改、越权角色、JWK 私钥字段等边界。

## 目录

```
siteguard/
  src/
    canonical.js   规范化 JSON 与摘要（终端/服务端字节一致的约定）
    crypto.js      ECDSA P-256：终端证书、挑战令牌、请求签名、请求指纹
    storage.js     fsync 追加事件日志（WAL）+ 启动重放 + 签发根密钥首启生成
    service.js     全部领域规则（登记抢占/挑战网关/轮换/隔离/跨站点/中性审计/库外验签）
    http.js        原生 http 接口与页面（零框架）
    seed.js        演示播种
  static/          门户、终端登记/自检、安全管理、中性审计、库外验签页面
  tests/           node:test 场景测试（内置 Web Crypto 模拟浏览器终端）
```

## 持久化与并发语义

- 事件类型：`serverKeyGenerated / registerCodeIssued / deviceRegistered /
  challengeIssued / actionSigned / rotationPrepared / certificateRotated /
  deviceQuarantined / requestRejected`，每行一个 JSON、单调 `seq`、追加后 fsync。
- 落款成功的唯一结果（含自描述记录信封的服务端签名）随 `actionSigned` 一次性固化，
  之后任何时刻（轮换、隔离、重启）取回的都是同一份；重算只需 `/api/server-key`。
- 登录会话是内存态（重启需重新登录）；安全状态全部在事件日志中，与会话无关。

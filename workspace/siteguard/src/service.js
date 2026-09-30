/**
 * 建设现场签署终端可信登记 / 挑战落款 领域服务。
 *
 * 三条关键防线：
 *  1. 一次性注册码：registerCodes.get(code).used 的检查与 deviceRegistered 落盘
 *     在同一同步执行段内完成（Node 单线程 + fsync 追加），两个浏览器并发登记时
 *     只有先持久化者成功，后者收到稳定的 REGISTER_CODE_CONSUMED。
 *  2. 挑战-落款：挑战是服务端签名的短时令牌（随机数/动作/会话/角色/正文摘要/截止）；
 *     提交时按字节重算终端签名并逐字段比对挑战绑定，任一字段被替换即拒绝；
 *     `${cert_id}|${nonce}` 是已消费随机数的唯一落点，同挑战同请求重放返回首次结果，
 *     换字段或换请求体一律拒绝。
 *  3. 证书代次与隔离：rotated / quarantined 证书不能再领挑战，但其公钥保留，
 *     历史落款记录始终可验；跨站点管理员看不到也操作不了别处设备。
 */
import crypto from 'node:crypto';
import {
  issueTerminalCert, parseTerminalCert, issueChallenge, signObject,
  verifySignedObject, signingRequest, requestFingerprint, TERM_ALG,
} from './crypto.js';
import { digestHexSync } from './canonical.js';

export class ServiceError extends Error {
  constructor(code, message, http = 400, extra = {}) {
    super(message);
    this.code = code; this.http = http; this.extra = extra;
  }
}

// 电子知情同意：登记 CSR 必须钉住当前版本（服务端校验，防止旧同意页蒙混登记）
export const CONSENT = {
  version: 'CONSENT-2026-09-v1',
  title: '建设现场签署终端可信登记电子知情同意书',
  paragraphs: [
    '本终端将在本机硬件加密能力范围内生成一对终端签名密钥，私钥仅保存于本终端、不出设备；',
    '登记成功后服务端签发绑定站点、设备标识、可用角色、有效期与代次的终端证书；',
    '每次业务落款前终端领取含随机数与短截止时间的挑战，并以本地私钥对完整请求签名；',
    '终端被安全隔离或证书轮换后将立即不能继续落款，但此前成功的历史记录仍可核对；',
    '审计页面仅记录中性编号，不含人员姓名与正文内容。',
  ],
};

// 站点 -> 审计中性分区（审计页永不出现站点编码）
export const SITE_PARTITION = { 'SITE-A': 'P-1', 'SITE-B': 'P-2' };

// 业务动作目录：动作 -> 允许的落款角色（证书可用角色必须覆盖）
export const ACTION_CATALOG = {
  'concrete.pour': { title: '混凝土浇筑落款', roles: ['supervisor', 'inspector'] },
  'steel.acceptance': { title: '钢筋隐蔽验收落款', roles: ['inspector', 'supervisor'] },
  'safety.briefing': { title: '班前安全交底落款', roles: ['supervisor', 'recorder'] },
  'shift.handoff': { title: '交接班记录落款', roles: ['supervisor', 'recorder', 'inspector'] },
};

// 演示账号：密码哈希随代码固定（仅演示用途）
function scrypt(pw, salt) {
  return crypto.scryptSync(pw, salt, 32).toString('hex');
}
const DEMO_PW = 'demo1234';
const ACCOUNTS = [
  { username: 'safeA', role: 'admin', site_code: 'SITE-A', display: '安全管理员·甲站' },
  { username: 'safeB', role: 'admin', site_code: 'SITE-B', display: '安全管理员·乙站' },
  { username: 'auditor', role: 'auditor', site_code: null, display: '中性审计员' },
].map((u) => ({ ...u, salt: 'sg-salt-' + u.username, pwhash: scrypt(DEMO_PW, 'sg-salt-' + u.username) }));

export class SiteGuardService {
  constructor(store, opts = {}) {
    this.store = store;
    this.challengeTtlMs = opts.challengeTtlMs ?? 60_000;
    this.certMinutes = opts.certMinutes ?? 5 * 24 * 60;
    this.rotationTtlMs = opts.rotationTtlMs ?? 10 * 60_000;
    this.sessions = new Map(); // token -> 内存会话（不属重启必须恢复的范围）
  }

  get S() { return this.store.state; }

  // ------------------------------------------------------------ 认证会话
  login(username, password) {
    const acc = ACCOUNTS.find((a) => a.username === username);
    if (!acc || !crypto.timingSafeEqual(
      Buffer.from(scrypt(String(password ?? ''), acc.salt)), Buffer.from(acc.pwhash))) {
      throw new ServiceError('BAD_CREDENTIALS', '账号或密码错误', 401);
    }
    const token = crypto.randomBytes(24).toString('hex');
    this.sessions.set(token, { username: acc.username, role: acc.role,
      site_code: acc.site_code, display: acc.display });
    return { token, username: acc.username, role: acc.role,
      site_code: acc.site_code, display: acc.display };
  }

  logout(token) { if (token) this.sessions.delete(token); return { ok: true }; }

  userForToken(token) { return token ? this.sessions.get(token) ?? null : null; }

  requireUser(token, roles) {
    const u = this.userForToken(token);
    if (!u) throw new ServiceError('UNAUTHENTICATED', '未登录或会话已过期', 401);
    if (roles && !roles.includes(u.role)) {
      throw new ServiceError('FORBIDDEN', '该账号无权操作此接口', 403);
    }
    return u;
  }

  /** 站点归属校验：不属于本管理员站点的设备一律按"不存在"处理，杜绝跨站枚举。 */
  ownDevice(user, deviceId) {
    const d = this.S.devices.get(deviceId);
    if (!d || d.site_code !== user.site_code) {
      throw new ServiceError('DEVICE_NOT_FOUND', '设备不存在或不在本站点', 404);
    }
    return d;
  }
  ownCert(user, certId) {
    const row = this.S.certificates.get(certId);
    const d = row && this.S.devices.get(this.S.certDevice.get(certId));
    if (!row || !d || d.site_code !== user.site_code) {
      throw new ServiceError('CERT_NOT_FOUND', '证书不存在或不在本站点', 404);
    }
    return { row, d };
  }

  // ------------------------------------------------------------ 注册码（安全管理员）
  createRegisterCode(user, body) {
    const roles = this.#cleanRoles(body?.roles);
    const minutes = Number.isFinite(body?.minutes) ? Number(body.minutes) : 60;
    if (!(minutes >= 1 && minutes <= 7 * 24 * 60)) {
      throw new ServiceError('BAD_TTL', '注册码有效期需在 1 分钟到 7 天之间', 400);
    }
    const codeRef = this.store.nextCodeRef();
    const code = this.store.randomSecret(12); // 24 位十六进制一次性秘密
    this.store.append('registerCodeIssued', {
      code, code_ref: codeRef, site_code: user.site_code, roles, minutes,
      created_by: user.username,
    }, { type: 'registerCodeIssued',
      partition: SITE_PARTITION[user.site_code], refs: { code: codeRef, roles } });
    return { code, code_ref: codeRef, site_code: user.site_code, roles, minutes,
      used: false, created_at: this.S.registerCodes.get(code).created_at };
  }

  listRegisterCodes(user) {
    return [...this.S.registerCodes.values()]
      .filter((c) => c.site_code === user.site_code)
      .map((c) => ({ code_ref: c.code_ref, roles: c.roles,
        minutes: c.minutes, used: c.used, used_at: c.used_at,
        cert_id: c.used ? this.S.certificates.get(c.cert_id)?.cert_id : null,
        created_at: c.created_at }));
    // 注意：不回显注册码明文（创建响应只展示一次），也不回显站点编码。
  }

  #cleanRoles(roles) {
    const allowed = new Set(['supervisor', 'inspector', 'recorder']);
    if (!Array.isArray(roles) || !roles.length) {
      throw new ServiceError('ROLES_REQUIRED', '必须指定证书可用角色', 400);
    }
    const out = [...new Set(roles.map(String))];
    if (out.some((r) => !allowed.has(r))) {
      throw new ServiceError('BAD_ROLE', '存在不支持的角色', 400);
    }
    return out;
  }

  // ------------------------------------------------------------ 终端首次登记
  /**
   * 无登录接口（施工现场浏览器凭一次性注册码登记）。
   * body: { code, device_label, consent_version, public_jwk, csr_sig }
   * csr_sig 由浏览器新生成的私钥对 CSR 规范对象签名，证明持有对应私钥。
   */
  registerTerminal(body, now = Date.now()) {
    const codeRec = this.S.registerCodes.get(body?.code);
    if (!codeRec) throw new ServiceError('REGISTER_CODE_INVALID', '注册码无效', 404);
    // —— 一次性抢占的唯一关口：检查 used 与落盘 deviceRegistered 之间无任何 await ——
    if (codeRec.used) {
      throw new ServiceError('REGISTER_CODE_CONSUMED',
        '该注册码已成功使用过，不能再次登记', 409, { code_ref: codeRec.code_ref });
    }
    if (Date.parse(codeRec.created_at) + codeRec.minutes * 60_000 < now) {
      throw new ServiceError('REGISTER_CODE_EXPIRED', '注册码已过期', 410);
    }
    if (body?.consent_version !== CONSENT.version) {
      throw new ServiceError('CONSENT_VERSION_STALE',
        '请先阅读并同意当前版本的电子知情同意书', 400, { required: CONSENT.version });
    }
    const label = this.#cleanLabel(body?.device_label);
    const publicJwk = this.#cleanPublicJwk(body?.public_jwk);
    const csr = {
      alg: 'SG-REGISTER-CSR/v1', code: body.code, device_label: label,
      public_jwk: publicJwk, consent_version: CONSENT.version,
    };
    if (!body?.csr_sig || !verifySignedObject(publicJwk, csr, body.csr_sig)) {
      throw new ServiceError('CSR_SIG_INVALID', '终端公钥自证签名不合法', 401);
    }

    const deviceId = this.store.nextDeviceRef();
    const certId = this.store.nextCertRef();
    const atIso = new Date(now).toISOString();
    const cert = {
      alg: TERM_ALG, cert_id: certId, device_id: deviceId, site_code: codeRec.site_code,
      device_label: label, roles: codeRec.roles, gen: 1,
      not_before: atIso,
      not_after: new Date(now + this.certMinutes * 60_000).toISOString(),
      public_jwk: publicJwk,
    };
    const envelope = issueTerminalCert({ serverPrivateJwk: this.S.serverPrivateJwk, cert });

    this.store.append('deviceRegistered', {
      code: body.code, device_id: deviceId, site_code: codeRec.site_code,
      label, cert_id: certId, roles: codeRec.roles,
      not_before: cert.not_before, not_after: cert.not_after, public_jwk: publicJwk,
      cert_envelope: envelope,
    }, { type: 'terminalRegistered', partition: SITE_PARTITION[codeRec.site_code],
      refs: { device: deviceId, cert: certId, code: codeRec.code_ref, roles: codeRec.roles } });

    return { device_id: deviceId, cert: envelope, server_time: new Date().toISOString() };
  }

  #cleanLabel(label) {
    const s = String(label ?? '').trim();
    if (!s || s.length > 40) {
      throw new ServiceError('BAD_LABEL', '设备标识为 1–40 字的中性名称（如：3号拌合站平板）', 400);
    }
    return s;
  }

  #cleanPublicJwk(jwk) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
        typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || jwk.d) {
      throw new ServiceError('BAD_PUBLIC_KEY', '需要 ECDSA P-256 公钥 JWK（不得携带私钥字段 d）', 400);
    }
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }

  // ------------------------------------------------------------ 领取挑战
  /**
   * body: { cert: 证书信封, action, session_id, role, body_digest, nonce? }
   * 只有 active 证书可领：rotated（旧密钥）/ quarantined（隔离设备）一律拒绝。
   */
  issueChallenge(body, now = Date.now()) {
    const payload = this.#parseActiveCert(body?.cert, now);
    const certRow = this.S.certificates.get(payload.cert_id);
    const action = String(body?.action ?? '');
    const catalog = ACTION_CATALOG[action];
    if (!catalog) throw new ServiceError('ACTION_UNKNOWN', '业务动作不在目录内', 400);
    const role = String(body?.role ?? '');
    if (!catalog.roles.includes(role) || !certRow.roles.includes(role)) {
      throw new ServiceError('ROLE_NOT_ALLOWED', '该角色不能对此动作落款或证书未授予此角色', 403);
    }
    const sessionId = this.#cleanSession(body?.session_id);
    const bodyDigest = this.#cleanDigest(body?.body_digest);
    const nonce = crypto.randomBytes(16).toString('hex');
    const ch = {
      cert_id: payload.cert_id, nonce, action, session_id: sessionId, role,
      body_digest: bodyDigest, site_code: certRow.site_code,
      not_before: new Date(now).toISOString(),
      not_after: new Date(now + this.challengeTtlMs).toISOString(),
    };
    const token = issueChallenge({ serverPrivateJwk: this.S.serverPrivateJwk, challenge: ch });
    this.store.append('challengeIssued', ch,
      { type: 'challengeIssued', partition: SITE_PARTITION[certRow.site_code],
        refs: { device: certRow.device_id, cert: payload.cert_id, action } });
    return { ...token, ttl_ms: this.challengeTtlMs };
  }

  // ------------------------------------------------------------ 签名落款（网关）
  submitSignedAction(body, now = Date.now()) {
    const reject = (code, msg, http, certId = null, action = null) => {
      this.#logRejection(code, certId, action);
      throw new ServiceError(code, msg, http);
    };

    // 1) 证书签名 + 有效期
    const payload = parseTerminalCert(body?.cert, this.S.serverPublicJwk, now);
    if (!payload) return reject('CERT_INVALID', '终端证书签名非法或已过有效期', 400);
    const certRow = this.S.certificates.get(payload.cert_id);
    if (!certRow) return reject('CERT_UNKNOWN', '证书未登记', 400, payload.cert_id);

    // 2) 挑战签名与截止时间
    const ch = body?.challenge;
    if (!ch || !body?.challenge_sig ||
        !verifySignedObject(this.S.serverPublicJwk, ch, body.challenge_sig)) {
      return reject('CHALLENGE_BAD_SIG', '挑战签名不合法', 401, payload.cert_id, ch?.action);
    }
    if (Date.parse(ch.not_after) <= now || Date.parse(ch.not_before) > now) {
      return reject('CHALLENGE_EXPIRED', '挑战已过期，请重新领取', 410,
        payload.cert_id, ch.action);
    }

    // 3) 挑战绑定字段逐字比对：替换角色/会话/正文/动作/证书任一即拒绝
    const fields = ['cert_id', 'nonce', 'action', 'session_id', 'role', 'body_digest'];
    for (const f of fields) {
      if (String(body?.[f] ?? '') !== String(ch[f] ?? '')) {
        return reject('REQUEST_FIELDS_REPLACED',
          `请求与挑战绑定不一致（${f}），拒绝落款`, 409, payload.cert_id, ch.action);
      }
    }
    if (ch.site_code !== certRow.site_code) {
      return reject('SITE_MISMATCH', '挑战站点与证书站点不一致', 409, payload.cert_id, ch.action);
    }
    const catalog = ACTION_CATALOG[ch.action];
    if (!catalog || !catalog.roles.includes(ch.role) || !certRow.roles.includes(ch.role)) {
      return reject('ROLE_NOT_ALLOWED', '角色不允许此动作', 403, payload.cert_id, ch.action);
    }

    // 4) 终端私钥对"完整请求"的签名（先于状态/去重校验：只持有合法私钥的终端
    //    才谈得上"相同请求"；被隔离设备重放自己此前合法签名仍能取回首次结果）
    const sr = signingRequest({
      cert_id: ch.cert_id, nonce: ch.nonce, action: ch.action, session_id: ch.session_id,
      role: ch.role, body_digest: ch.body_digest, challenge_sig: body.challenge_sig,
    });
    if (!body?.terminal_sig ||
        !verifySignedObject(payload.public_jwk, sr, body.terminal_sig)) {
      return reject('TERMINAL_SIG_INVALID', '终端签名核验失败', 401, payload.cert_id, ch.action);
    }

    const fp = requestFingerprint(sr);
    const key = `${payload.cert_id}|${ch.nonce}`;

    // 5) 已消费随机数：同一挑战+相同请求返回首次结果；换了任何字段 → 拒绝。
    //    此检查先于隔离/轮换判定："此前成功的记录保持可取回"，且隔离/轮换之后
    //    根本领不到新挑战，新随机数不可能到达这里。
    const existingId = this.S.consumedNonces.get(key);
    if (existingId) {
      const first = this.S.records.get(existingId);
      if (first.request_fp === fp) {
        return { replay: true, record_id: first.record_id, result: first.result,
          result_digest: first.result_digest, signed_at: first.at };
      }
      return reject('NONCE_REUSED',
        '该挑战随机数已使用，不能用它换取第二个结果', 409, payload.cert_id, ch.action);
    }

    // 6) 首次落款：按持久化在 WAL 中的最新状态判定代次/隔离。
    //    证书停用（隔离/轮换）与请求提交并发时，二者先后顺序即此处观察到的状态。
    const device = this.S.devices.get(certRow.device_id);
    if (certRow.status === 'quarantined' || device.quarantined) {
      return reject('DEVICE_QUARANTINED', '设备已被隔离，失去后续操作资格', 403,
        payload.cert_id, ch.action);
    }
    if (certRow.status === 'rotated') {
      return reject('CERT_ROTATED', '该证书代次已轮换，旧密钥只能核对历史记录', 403,
        payload.cert_id, ch.action);
    }
    const recordId = this.store.nextRecordRef();
    const atIso = new Date(now).toISOString();
    const result = this.#runBusiness(ch.action, { session_id: ch.session_id,
      role: ch.role, body_digest: ch.body_digest, record_id: recordId });
    const resultDigest = digestHexSync({
      record_id: recordId, action: ch.action, session_id: ch.session_id,
      body_digest: ch.body_digest, result,
    });

    // 自描述记录信封在落盘前一次性签好并随事件固化；重启后仍可库外重算验签
    const recordPayload = {
      alg: 'SG-RECORD/v1', record_id: recordId, cert_id: certRow.cert_id,
      device_id: device.device_id, site_code: certRow.site_code, action: ch.action,
      session_id: ch.session_id, role: ch.role, body_digest: ch.body_digest,
      nonce: ch.nonce, terminal_sig: body.terminal_sig,
      challenge_sig: body.challenge_sig,
      challenge_not_before: ch.not_before, challenge_not_after: ch.not_after,
      cert_envelope: certRow.envelope, result, result_digest: resultDigest,
      signed_at: atIso,
    };
    const serverSig = signObject(this.S.serverPrivateJwk,
      this.#recordEnvelopePayload(recordPayload));

    this.store.append('actionSigned', {
      record_id: recordId, cert_id: certRow.cert_id, device_id: device.device_id,
      site_code: certRow.site_code, partition: SITE_PARTITION[certRow.site_code],
      action: ch.action, session_id: ch.session_id, role: ch.role,
      body_digest: ch.body_digest, nonce: ch.nonce, request_fp: fp,
      terminal_sig: body.terminal_sig, challenge_sig: body.challenge_sig,
      challenge_not_before: ch.not_before, challenge_not_after: ch.not_after,
      result_digest: resultDigest, result, server_sig: serverSig,
      signed_at: atIso,
    }, { type: 'actionSigned', partition: SITE_PARTITION[certRow.site_code],
      refs: { device: device.device_id, cert: certRow.cert_id, record: recordId,
        action: ch.action } }, atIso);

    return { replay: false, record_id: recordId,
      record: { payload: recordPayload, server_sig: serverSig },
      result, result_digest: resultDigest, signed_at: atIso };
  }

  #runBusiness(action, ctx) {
    // 业务接口桩：网关验签通过后才"转给业务接口"，业务结果对相同落款稳定可复算
    const receipt = 'RCV-' + ctx.record_id.slice(2) + '-' +
      crypto.createHash('sha256').update(ctx.body_digest).digest('hex').slice(0, 8);
    return { accepted: true, action, title: ACTION_CATALOG[action].title,
      receipt, note: '网关已验证证书/挑战/摘要，动作已转交业务接口处理' };
  }

  #logRejection(reason, certId, action) {
    let deviceId = null; let partition = null;
    if (certId) {
      const row = this.S.certificates.get(certId);
      if (row) {
        deviceId = this.S.certDevice.get(certId);
        const d = this.S.devices.get(deviceId);
        partition = d ? SITE_PARTITION[d.site_code] : null;
      }
    }
    this.store.append('requestRejected', { reason },
      { type: 'requestRejected', partition,
        refs: { ...(deviceId ? { device: deviceId } : {}),
          ...(certId && this.S.certificates.has(certId) ? { cert: certId } : {}),
          ...(action ? { action } : {}), reason } });
  }

  // ------------------------------------------------------------ 证书轮换
  /** 安全管理员为本站点某在用证书生成一次性轮换授权码（短有效期）。 */
  prepareRotation(user, body, now = Date.now()) {
    const { row, d } = this.ownCert(user, String(body?.cert_id ?? ''));
    if (d.quarantined || row.status === 'quarantined') {
      throw new ServiceError('DEVICE_QUARANTINED', '设备已隔离，不能轮换证书', 403);
    }
    if (row.status !== 'active') {
      throw new ServiceError('CERT_NOT_ACTIVE', '只有当前在用证书可以轮换', 409);
    }
    const nonce = this.store.randomSecret(12);
    const exp = new Date(now + this.rotationTtlMs).toISOString();
    this.store.append('rotationPrepared', {
      rotation_nonce: nonce, cert_id: row.cert_id, device_id: d.device_id,
      gen: row.gen, exp, prepared_by: user.username,
    }, { type: 'rotationPrepared', partition: SITE_PARTITION[user.site_code],
      refs: { device: d.device_id, cert: row.cert_id, gen: row.gen } });
    return { rotation_nonce: nonce, cert_id: row.cert_id, device_id: d.device_id,
      gen: row.gen, expires_at: exp };
  }

  /**
   * 终端持轮换授权码 + 新公钥完成轮换。
   * 要求同时证明：持有旧私钥（old_sig）与新私钥（new_sig）。
   * 旧证书置 rotated：永久只能核对历史记录，不能再领新挑战。
   */
  rotateTerminal(body, now = Date.now()) {
    const pend = this.S.pendingRotations.get(body?.rotation_nonce);
    if (!pend) throw new ServiceError('ROTATION_NONCE_INVALID', '轮换授权码无效', 404);
    if (pend.used) {
      throw new ServiceError('ROTATION_NONCE_USED', '轮换授权码只能使用一次', 409);
    }
    if (Date.parse(pend.exp) < now) {
      throw new ServiceError('ROTATION_NONCE_EXPIRED', '轮换授权码已过期', 410);
    }
    const old = this.S.certificates.get(pend.cert_id);
    const device = this.S.devices.get(pend.device_id);
    if (device.quarantined || old.status !== 'active') {
      throw new ServiceError('CERT_NOT_ACTIVE', '证书当前不可轮换', 409);
    }
    const newJwk = this.#cleanPublicJwk(body?.new_public_jwk);
    const csr = {
      alg: 'SG-ROTATION-CSR/v1', rotation_nonce: pend.rotation_nonce,
      old_cert_id: old.cert_id, device_id: device.device_id, new_public_jwk: newJwk,
    };
    if (!body?.new_sig || !verifySignedObject(newJwk, csr, body.new_sig) ||
        !body?.old_sig || !verifySignedObject(old.public_jwk, csr, body.old_sig)) {
      throw new ServiceError('ROTATION_SIG_INVALID',
        '必须同时用旧私钥与新私钥对轮换请求签名', 401);
    }

    const newCertId = this.store.nextCertRef();
    const atIso = new Date(now).toISOString();
    const newGen = old.gen + 1;
    const cert = {
      alg: TERM_ALG, cert_id: newCertId, device_id: device.device_id,
      site_code: old.site_code, device_label: old.device_label, roles: old.roles,
      gen: newGen,
      not_before: atIso,
      not_after: new Date(now + this.certMinutes * 60_000).toISOString(),
      public_jwk: newJwk,
    };
    const envelope = issueTerminalCert({ serverPrivateJwk: this.S.serverPrivateJwk, cert });

    this.store.append('certificateRotated', {
      rotation_nonce: pend.rotation_nonce, device_id: device.device_id,
      old_cert_id: old.cert_id, new_cert_id: newCertId, cert,
      cert_envelope: envelope,
    }, { type: 'certificateRotated', partition: SITE_PARTITION[old.site_code],
      refs: { device: device.device_id, old_cert: old.cert_id, cert: newCertId,
        gen: old.gen + 1 } });

    return { device_id: device.device_id, cert: envelope,
      old_cert_id: old.cert_id, gen: old.gen + 1 };
  }

  // ------------------------------------------------------------ 设备隔离
  quarantineDevice(user, body) {
    const d = this.ownDevice(user, String(body?.device_id ?? ''));
    if (d.quarantined) {
      return { idempotent: true, device_id: d.device_id, quarantined: true,
        reason: d.quarantined_reason, quarantined_at: d.quarantined_at,
        current_cert_id: d.current_cert_id };
    }
    const reason = String(body?.reason ?? '').trim();
    if (!reason || reason.length > 100) {
      throw new ServiceError('REASON_REQUIRED', '隔离原因必填且不超过 100 字', 400);
    }
    this.store.append('deviceQuarantined',
      { device_id: d.device_id, reason },
      { type: 'deviceQuarantined', partition: SITE_PARTITION[user.site_code],
        refs: { device: d.device_id, cert: d.current_cert_id } });
    return { idempotent: false, device_id: d.device_id, quarantined: true,
      reason, quarantined_at: d.quarantined_at, current_cert_id: d.current_cert_id };
  }

  // ------------------------------------------------------------ 管理/自检只读
  listDevices(user) {
    return [...this.S.devices.values()].filter((d) => d.site_code === user.site_code).map((d) => {
      const certs = [...this.S.certificates.values()].filter((c) => c.device_id === d.device_id);
      return { device_id: d.device_id, label: d.label, created_at: d.created_at,
        quarantined: d.quarantined, quarantined_reason: d.quarantined_reason,
        quarantined_at: d.quarantined_at, current_cert_id: d.current_cert_id,
        certificates: certs.map((c) => ({ cert_id: c.cert_id, gen: c.gen,
          status: c.status, roles: c.roles, not_after: c.not_after,
          issued_at: c.issued_at, rotated_at: c.rotated_at ?? null })) };
    });
  }

  listRecords(user, query = {}) {
    let rows = [...this.S.records.values()].filter((r) => r.site_code === user.site_code);
    if (query.device_id) {
      const d = this.ownDevice(user, String(query.device_id));
      rows = rows.filter((r) => r.device_id === d.device_id);
    }
    return rows.map((r) => ({ record_id: r.record_id, device_id: r.device_id,
      cert_id: r.cert_id, action: r.action, session_id: r.session_id, role: r.role,
      body_digest: r.body_digest, result_digest: r.result_digest, at: r.at }));
  }

  /**
   * 终端持证书私钥做一次自证，查询自身登记/代次/隔离状态（自检页用）。
   * 任何代次/状态的证书都可自证（隔离设备也要能在自检页看到"已隔离"）。
   */
  inspectTerminal(body, now = Date.now()) {
    const env = body?.cert;
    const any = this.#parseCertAnyTime(env);
    const csr = { alg: 'SG-INSPECT/v1', cert_id: any.cert_id, nonce: String(body?.nonce ?? '') };
    if (!body?.proof_sig || !verifySignedObject(any.public_jwk, csr, body.proof_sig)) {
      throw new ServiceError('PROOF_SIG_INVALID', '终端自证签名不合法', 401);
    }
    const certRow = this.S.certificates.get(any.cert_id);
    if (!certRow) throw new ServiceError('CERT_UNKNOWN', '证书未登记', 404);
    const d = this.S.devices.get(certRow.device_id);
    return { device_id: d.device_id, cert_id: certRow.cert_id, gen: certRow.gen,
      status: certRow.status, quarantined: d.quarantined,
      quarantined_reason: d.quarantined_reason, current_cert_id: d.current_cert_id,
      roles: certRow.roles, not_after: certRow.not_after,
      within_validity: Date.parse(certRow.not_after) > now, server_time: new Date(now).toISOString() };
  }

  /**
   * 持某代证书私钥核对本设备的历史记录（轮换后的旧密钥、被隔离设备的密钥都可用，
   * 但只能读自己证书签署的那条记录，跨站点/跨设备证书一律 404）。
   * body: { record_id, cert, proof_sig }
   */
  collectRecord(body) {
    const any = this.#parseCertAnyTime(body?.cert);
    const csr = { alg: 'SG-RECORD-READ/v1', cert_id: any.cert_id,
      record_id: String(body?.record_id ?? '') };
    if (!body?.proof_sig || !verifySignedObject(any.public_jwk, csr, body.proof_sig)) {
      throw new ServiceError('PROOF_SIG_INVALID', '终端自证签名不合法', 401);
    }
    const rec = this.S.records.get(String(body?.record_id ?? ''));
    if (!rec || rec.cert_id !== any.cert_id) {
      // 不区分"不存在"与"别人的"，避免跨设备/跨站点枚举
      throw new ServiceError('RECORD_NOT_FOUND', '记录不存在或不属于该证书', 404);
    }
    const envelope = this.#buildRecordEnvelope(rec);
    return { envelope, verification: this.verifyRecordEnvelope(envelope) };
  }

  /** 纯库外重算：不查任何归属，只验签名链与摘要绑定（公开接口）。 */
  verifyRecordEnvelope(envelope) {
    const p = envelope?.payload ?? envelope;
    const serverSig = envelope?.server_sig ?? p.server_sig;
    const certPayload = p.cert_envelope?.payload;
    const checks = [];
    // 1) 终端证书的服务端签发签名（历史证书即使已过期/轮换/隔离，签发链仍须成立）
    checks.push(['cert_chain',
      !!certPayload &&
      verifySignedObject(this.S.serverPublicJwk, certPayload, p.cert_envelope.signature)]);
    // 2) 挑战令牌的服务端签名（自描述：时间窗随信封保存）
    const ch = { alg: 'SG-CHALLENGE/v1', cert_id: p.cert_id, nonce: p.nonce,
      action: p.action, session_id: p.session_id, role: p.role,
      body_digest: p.body_digest, site_code: certPayload?.site_code,
      not_before: p.challenge_not_before, not_after: p.challenge_not_after };
    checks.push(['challenge_signature',
      verifySignedObject(this.S.serverPublicJwk, ch, p.challenge_sig)]);
    // 3) 终端私钥对完整请求的签名
    const sr = signingRequest({ cert_id: p.cert_id, nonce: p.nonce, action: p.action,
      session_id: p.session_id, role: p.role, body_digest: p.body_digest,
      challenge_sig: p.challenge_sig });
    checks.push(['terminal_signature',
      !!certPayload && verifySignedObject(certPayload.public_jwk, sr, p.terminal_sig)]);
    // 4) 业务结果摘要绑定
    checks.push(['result_digest',
      digestHexSync({ record_id: p.record_id, action: p.action,
        session_id: p.session_id, body_digest: p.body_digest, result: p.result }) ===
      p.result_digest]);
    // 5) 整个记录信封的服务端签名（签名时覆盖除 server_sig 外的全部 payload 字段）
    checks.push(['record_server_signature',
      verifySignedObject(this.S.serverPublicJwk, this.#recordEnvelopePayload(p),
        serverSig)]);
    const entries = checks.map(([k, v]) => [k, !!v]);
    return { ok: entries.every(([, v]) => v), checks: Object.fromEntries(entries) };
  }

  #buildRecordEnvelope(rec) {
    // 自描述信封：任何持有者都可仅凭服务端公钥在库外重算验签。
    // server_sig 首次落盘时固化（records.server_sig），重建不得重签。
    const payload = {
      alg: 'SG-RECORD/v1', record_id: rec.record_id, cert_id: rec.cert_id,
      device_id: rec.device_id, site_code: rec.site_code, action: rec.action,
      session_id: rec.session_id, role: rec.role, body_digest: rec.body_digest,
      nonce: rec.nonce, terminal_sig: rec.terminal_sig, challenge_sig: rec.challenge_sig,
      challenge_not_before: rec.challenge_not_before,
      challenge_not_after: rec.challenge_not_after,
      cert_envelope: this.S.certificates.get(rec.cert_id).envelope,
      result: rec.result, result_digest: rec.result_digest, signed_at: rec.at,
    };
    return { payload, server_sig: rec.server_sig };
  }

  #recordEnvelopePayload(p) {
    // 服务端签名覆盖除 server_sig 外的全部字段
    const { server_sig, ...rest } = p;
    return { alg: 'SG-RECORD/v1', ...rest };
  }

  /** 审计列表：仅 auditor；只返回中性编号（无站点、无账号、无正文）。 */
  listAudit(user, { limit = 200, type } = {}) {
    if (user.role !== 'auditor') {
      throw new ServiceError('FORBIDDEN', '只有中性审计员可查看审计页面', 403);
    }
    let rows = this.S.audit;
    if (type) rows = rows.filter((a) => a.type === type);
    return rows.slice(-Number(limit)).map((a) => ({ seq: a.seq, at: a.at,
      type: a.type, partition: a.partition, refs: a.refs }));
  }

  // ------------------------------------------------------------ 内部工具
  #parseActiveCert(envelope, now) {
    const p = parseTerminalCert(envelope, this.S.serverPublicJwk, now);
    if (!p) throw new ServiceError('CERT_INVALID', '终端证书签名非法或已过有效期', 400);
    const row = this.S.certificates.get(p.cert_id);
    if (!row) throw new ServiceError('CERT_UNKNOWN', '证书未登记', 404);
    const d = this.S.devices.get(row.device_id);
    if (d.quarantined || row.status === 'quarantined') {
      throw new ServiceError('DEVICE_QUARANTINED', '设备已被隔离，不能领取挑战', 403);
    }
    if (row.status === 'rotated') {
      throw new ServiceError('CERT_ROTATED', '旧证书代次已轮换，不能领取新挑战', 403);
    }
    return p;
  }

  #parseCertAnyTime(envelope) {
    // 与 parseTerminalCert 的区别：不检查有效期（历史核对用），只验服务端签名
    if (!envelope?.payload || !envelope.signature) return null;
    if (!verifySignedObject(this.S.serverPublicJwk, envelope.payload, envelope.signature)) {
      return null;
    }
    return envelope.payload;
  }

  #cleanSession(s) {
    const v = String(s ?? '').trim();
    if (!/^[A-Za-z0-9:_-]{4,64}$/.test(v)) {
      throw new ServiceError('BAD_SESSION', '会话标识需为 4–64 位字母数字及 :_-', 400);
    }
    return v;
  }

  #cleanDigest(h) {
    if (!/^[0-9a-f]{64}$/.test(String(h ?? ''))) {
      throw new ServiceError('BAD_DIGEST', '正文摘要需为 64 位十六进制 SHA-256', 400);
    }
    return String(h);
  }
}

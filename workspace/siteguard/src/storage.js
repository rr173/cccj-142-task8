/**
 * 追加写事件日志（WAL）持久化与重放。
 *
 * 设计要点（对应需求"按持久化先后得到唯一状态"）：
 *   - 所有状态变更（注册码签发/消费、设备、证书、轮换、隔离、落款结果、审计）
 *     都是一条不可变事件，单文件顺序追加；
 *   - 每条事件 writeFileSync 后立即 fsyncSync 落盘，崩溃时只有"已 fsync / 未 fsync"
 *     两种结果，不会出现半截状态；
 *   - Node 单线程 + 同步落盘：两个并发请求进入事务函数的先后就是事件在日志中的先后，
 *     竞争双方据此得到唯一且可解释的状态（先到者成功，后到者收到稳定的冲突结果）；
 *   - 重启时整文件重放还原内存状态：已消费的注册码/挑战随机数不会复活，
 *     隔离、轮换、历史验签信息全部保留。
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const WAL_FILE = 'siteguard.wal.log';

/** 生成服务端 ECDSA P-256 签发密钥（证书与挑战令牌的签名根）。 */
function generateServerKeyJwk() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  // 显式只保留最小 JWK 字段：Node 导出私钥 JWK 时带的 key_ops=['sign'] 会被
  // createPublicKey 误用，导致服务端自验签失败。
  const priv = privateKey.export({ format: 'jwk' });
  const pub = publicKey.export({ format: 'jwk' });
  return {
    public: { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y },
    private: { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y, d: priv.d },
  };
}

function blankState() {
  return {
    // 服务端签发密钥（首启生成并立刻事件化落盘，重启后沿用同一根）
    serverPrivateJwk: null,
    serverPublicJwk: null,
    // 注册码：secret -> { code, site_code, roles, minutes, created_by, created_at,
    //   used:false, used_at, cert_id }
    registerCodes: new Map(),
    // 设备中性编号 -> { device_id, site_code, label, current_cert_id, quarantined,
    //   quarantined_reason, created_at }
    devices: new Map(),
    // 证书号 -> 证书（含公钥 JWK、代次、状态）
    // status: active（可领挑战）/ rotated（仅可验历史）/ quarantined（仅可验历史）
    certificates: new Map(),
    // cert_id -> 设备（快速反查）
    certDevice: new Map(),
    // 待完成轮换：rotation_nonce -> { cert_id, device_id, exp, used }
    pendingRotations: new Map(),
    // 已成功落款记录 R-000001 -> 完整验签材料
    records: new Map(),
    // `${cert_id}|${nonce}` -> record_id：已消费随机数唯一落点
    consumedNonces: new Map(),
    audit: [], // { seq, at, type, partition?, refs? } —— 只含中性编号
    counters: { cert: 0, device: 0, record: 0, code: 0 },
  };
}

const pad6 = (n) => String(n).padStart(6, '0');

/** 事件归约：把单条事件作用到内存状态上（纯顺序，无 IO）。 */
function apply(state, rec) {
  const { type, p, at } = rec;
  switch (type) {
    case 'serverKeyGenerated':
      state.serverPrivateJwk = p.private_jwk;
      state.serverPublicJwk = p.public_jwk;
      return;
    case 'registerCodeIssued': {
      state.counters.code += 1;
      state.registerCodes.set(p.code, {
        code: p.code, code_ref: p.code_ref, site_code: p.site_code, roles: p.roles,
        minutes: p.minutes, created_by: p.created_by, created_at: at,
        used: false, used_at: null, cert_id: null,
      });
      return;
    }
    case 'deviceRegistered': {
      state.counters.device += 1;
      state.counters.cert += 1;
      state.devices.set(p.device_id, {
        device_id: p.device_id, site_code: p.site_code, label: p.label,
        current_cert_id: p.cert_id, quarantined: false, quarantined_reason: null,
        created_at: at,
      });
      state.certificates.set(p.cert_id, {
        envelope: p.cert_envelope, ...p.cert_envelope.payload, status: 'active',
        issued_at: at,
      });
      state.certDevice.set(p.cert_id, p.device_id);
      state.registerCodes.get(p.code).used = true;
      state.registerCodes.get(p.code).used_at = at;
      state.registerCodes.get(p.code).cert_id = p.cert_id;
      return;
    }
    case 'challengeIssued':
      // 挑战本身是短期签名令牌（无需存储即可验证）；审计计数外不占状态。
      return;
    case 'actionSigned': {
      state.counters.record += 1;
      state.records.set(p.record_id, {
        record_id: p.record_id, cert_id: p.cert_id, device_id: p.device_id,
        site_code: p.site_code, partition: p.partition, action: p.action,
        session_id: p.session_id, role: p.role, body_digest: p.body_digest,
        challenge_not_before: p.challenge_not_before,
        challenge_not_after: p.challenge_not_after, nonce: p.nonce,
        request_fp: p.request_fp, terminal_sig: p.terminal_sig,
        challenge_sig: p.challenge_sig, result_digest: p.result_digest,
        result: p.result, server_sig: p.server_sig ?? null,
        at: p.signed_at ?? at,
      });
      state.consumedNonces.set(`${p.cert_id}|${p.nonce}`, p.record_id);
      return;
    }
    case 'rotationPrepared':
      state.pendingRotations.set(p.rotation_nonce, {
        rotation_nonce: p.rotation_nonce, cert_id: p.cert_id,
        device_id: p.device_id, gen: p.gen, exp: p.exp, prepared_by: p.prepared_by,
        prepared_at: at, used: false,
      });
      return;
    case 'certificateRotated': {
      state.counters.cert += 1;
      const old = state.certificates.get(p.old_cert_id);
      old.status = 'rotated';
      old.rotated_at = at;
      state.certificates.set(p.cert.cert_id, {
        envelope: p.cert_envelope, ...p.cert_envelope.payload,
        status: 'active', issued_at: at,
      });
      state.certDevice.set(p.new_cert_id, p.device_id);
      state.devices.get(p.device_id).current_cert_id = p.new_cert_id;
      const pend = state.pendingRotations.get(p.rotation_nonce);
      if (pend) pend.used = true;
      return;
    }
    case 'deviceQuarantined': {
      const d = state.devices.get(p.device_id);
      d.quarantined = true;
      d.quarantined_reason = p.reason;
      d.quarantined_at = at;
      // 当前在用证书立即失去后续操作资格；已轮换旧证书本来也只能验历史
      const cur = state.certificates.get(d.current_cert_id);
      if (cur && cur.status === 'active') cur.status = 'quarantined';
      return;
    }
    case 'requestRejected':
      // 落款被拒不改任何业务状态（随机数/挑战不消费），只在审计行留痕
      return;
    default:
      throw new Error('未知事件类型: ' + type);
  }
}

export class Store {
  constructor(dir) {
    this.dir = dir;
    this.file = path.join(dir, WAL_FILE);
    this.state = blankState();
    this.seq = 0;
    fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(this.file)) this.#replay();
    this.fd = fs.openSync(this.file, 'a');
    if (!this.state.serverPrivateJwk) {
      const kp = generateServerKeyJwk();
      this.append('serverKeyGenerated', { public_jwk: kp.public, private_jwk: kp.private });
    }
  }

  #replay() {
    const text = fs.readFileSync(this.file, 'utf8');
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      const rec = JSON.parse(line);
      if (rec.seq !== this.seq + 1) {
        throw new Error(`WAL 序号不连续：期望 ${this.seq + 1}，实际 ${rec.seq}`);
      }
      this.seq = rec.seq;
      apply(this.state, rec);
      if (rec.audit) this.state.audit.push(rec.audit);
    }
  }

  /**
   * 追加一条事件并同步落盘，然后作用到内存状态。
   * auditView：可选的中性审计视图；不传则该事件不进审计页。
   * 返回落盘后的完整记录（rec.at 即权威事件时间）。
   */
  append(type, p, auditView = null, at = new Date().toISOString()) {
    const rec = { seq: this.seq + 1, at, type, p };
    if (auditView) {
      rec.audit = { seq: rec.seq, at: rec.at, type: auditView.type,
        partition: auditView.partition ?? null, refs: auditView.refs ?? {} };
    }
    const line = JSON.stringify(rec) + '\n';
    fs.writeFileSync(this.fd, line);
    fs.fsyncSync(this.fd);
    this.seq = rec.seq;
    apply(this.state, rec);
    if (auditView) this.state.audit.push(rec.audit);
    return rec;
  }

  close() { try { fs.closeSync(this.fd); } catch { /* 已关闭 */ } }

  // ------------------------------------------------ 中性编号
  nextCertRef() { return 'C-' + pad6(this.state.counters.cert + 1); }
  nextDeviceRef() { return 'D-' + pad6(this.state.counters.device + 1); }
  nextRecordRef() { return 'R-' + pad6(this.state.counters.record + 1); }
  nextCodeRef() { return 'RC-' + pad6(this.state.counters.code + 1); }

  randomSecret(bytes = 16) { return crypto.randomBytes(bytes).toString('hex'); }
}

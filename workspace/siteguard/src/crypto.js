/**
 * 密码学原语：终端密钥 / 服务端签发 / 终端证书 / 挑战令牌 / 请求落款。
 *
 * 算法（终端浏览器与服务端一致，均兼容 Web Crypto SubtleCrypto）：
 *   - 终端密钥对：ECDSA P-256（生成于浏览器 Web Crypto，私钥不出终端）；
 *   - 终端证书：服务端 ECDSA P-256 私钥对"证书规范对象"签名，绑定
 *     站点 / 设备标识 / 可用角色 / 有效期 / 代次；
 *   - 挑战：服务端对挑战内容签名的短期令牌；提交时先验服务端签名再用；
 *   - 落款：终端私钥对"完整请求"（挑战指纹 + 证书号 + 动作 + 会话 + 角色 +
 *     正文摘要 + 随机数）做 ECDSA SHA-256 签名。
 *
 * 所有待签名对象先过 canonicalize，浏览器侧使用 shared/canonical-web.js 的同一实现。
 */
import crypto from 'node:crypto';
import { canonicalBytes, digestHexSync } from './canonical.js';

export const TERM_ALG = 'SG-TERM-ECDSA-P256-SHA256/v1';
export const SIG_ALG = 'SG-CA-ECDSA-P256-SHA256/v1';

/**
 * 签名编码：统一使用 WebCrypto SubtleCrypto 的原生 IEEE P1363（裸 r||s，定长 64 字节），
 * base64url 传输。这样浏览器端 subtle.sign 的输出可直接提交，无需 DER 转换。
 */
const SIG_FORMAT = 'ieee-p1363';

const nodeKey = (jwk, isPrivate) => isPrivate
  ? crypto.createPrivateKey({ key: jwk, format: 'jwk' })
  : crypto.createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk',
    });

export function keyFromJwk(jwk) { return nodeKey(jwk, false); }
export function privateKeyFromJwk(jwk) { return nodeKey(jwk, true); }

export function signBytes(privateJwk, bytes) {
  const sig = crypto.sign(null, Buffer.from(bytes), {
    key: privateKeyFromJwk(privateJwk), dsaEncoding: SIG_FORMAT,
  });
  return sig.toString('base64url');
}

export function verifyBytes(publicJwk, bytes, sigB64url) {
  try {
    return crypto.verify(null, Buffer.from(bytes),
      { key: keyFromJwk(publicJwk), dsaEncoding: SIG_FORMAT },
      Buffer.from(sigB64url, 'base64url'));
  } catch { return false; }
}

export function sha256HexOfBytes(bytes) {
  return crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
}

/** 对任意可规范化对象签名（服务端签发证书/挑战用）。 */
export function signObject(privateJwk, obj) {
  return signBytes(privateJwk, canonicalBytes(obj));
}

export function verifySignedObject(publicJwk, obj, sigB64url) {
  return verifyBytes(publicJwk, canonicalBytes(obj), sigB64url);
}

/**
 * 构造并签发终端证书。cert 字段：
 * { alg, cert_id, device_id, site_code, device_label, roles[], gen, not_before, not_after, public_jwk }
 */
export function issueTerminalCert({ serverPrivateJwk, cert }) {
  const payload = { ...cert, alg: TERM_ALG };
  const signature = signObject(serverPrivateJwk, payload);
  return { payload, signature, sig_alg: SIG_ALG };
}

/**
 * 验证终端证书：服务端签名合法、当前时间在有效期内。
 * 注意：是否 active / 是否被隔离 / 代次是否最新，属于业务状态，由 service 另查。
 * 返回 payload（合法）或 null（签名非法）。
 */
export function parseTerminalCert(envelope, serverPublicJwk, now = Date.now()) {
  if (!envelope || !envelope.payload || !envelope.signature) return null;
  if (!verifySignedObject(serverPublicJwk, envelope.payload, envelope.signature)) return null;
  const p = envelope.payload;
  const t = now;
  if (Date.parse(p.not_before) > t || Date.parse(p.not_after) <= t) return null;
  return p;
}

/** 挑战内容（被签名的规范对象）。 */
export function challengePayload({ cert_id, nonce, action, session_id, role,
                                   body_digest, not_before, not_after, site_code }) {
  return { alg: 'SG-CHALLENGE/v1', cert_id, nonce, action, session_id, role,
    body_digest, site_code, not_before, not_after };
}

export function issueChallenge({ serverPrivateJwk, challenge }) {
  const payload = challengePayload(challenge);
  return { challenge: payload, signature: signObject(serverPrivateJwk, payload) };
}

/**
 * 完整请求（终端签名对象）。终端私钥签署此对象，服务端按字节重算核对，
 * 因此替换角色 / 会话 / 正文 / 随机数 / 动作 / 证书号任一字段都会使签名失配。
 */
export function signingRequest({ cert_id, nonce, action, session_id, role,
                                 body_digest, challenge_sig }) {
  return { alg: 'SG-SIGN-REQUEST/v1', cert_id, nonce, action, session_id, role,
    body_digest, challenge_sig };
}

/**
 * 请求指纹（幂等与"相同请求返回首次结果"的唯一落点）。
 * 注意：故意不包含 terminal_sig —— ECDSA 签名含随机因子，两个标签页对同一份
 * 完整请求独立签名会得到不同但各自合法的签名编码；"相同请求"的语义是被签署内容
 * （随机数 + 动作 + 会话 + 角色 + 正文摘要 + 挑战令牌）相同，二者都应拿到首次结果。
 */
export function requestFingerprint(signingRequestObj) {
  return digestHexSync(signingRequestObj);
}

/** 服务端自己生成一对终端密钥（仅测试/自检模拟浏览器时使用）。 */
export function generateTerminalKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    publicJwk: publicKey.export({ format: 'jwk' }),
    privateJwk: privateKey.export({ format: 'jwk' }),
  };
}

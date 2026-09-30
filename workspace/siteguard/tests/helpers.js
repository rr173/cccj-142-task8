/**
 * 测试公共夹具：临时数据目录 + 真实 HTTP 服务（随机端口）；
 * 内置"模拟浏览器"的 Web Crypto 终端（生成密钥、规范化摘要、CSR/请求/轮换签名）。
 */
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { webcrypto } from 'node:crypto';
import { createApp } from '../src/http.js';
import { canonicalize } from '../src/canonical.js';

const { subtle } = webcrypto;

let counter = 0;

export function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sg-test-'));
}

export async function startApp({ challengeTtlMs = 400, certMinutes = 60 * 24 * 5,
                                dataDir } = {}) {
  const dir = dataDir ?? fs.mkdtempSync(path.join(os.tmpdir(), `sg-run-${++counter}-`));
  const app = createApp({ dataDir: dir, challengeTtlMs, certMinutes });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const port = app.server.address().port;
  const url = `http://127.0.0.1:${port}`;
  return {
    url, dir, app,
    close: () => new Promise((res) => {
      app.server.close(() => { app.store.close(); res(); });
    }),
  };
}

export async function httpJson(base, method, urlPath, { body, token } = {}) {
  const res = await fetch(base + urlPath, {
    method,
    headers: { 'content-type': 'application/json',
      ...(token ? { 'X-Authorization': 'Bearer ' + token } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

export async function login(base, username) {
  const r = await httpJson(base, 'POST', '/api/login',
    { body: { username, password: 'demo1234' } });
  if (r.status !== 200) throw new Error('登录失败: ' + JSON.stringify(r.json));
  return r.json.token;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ */
/* 模拟浏览器终端（Web Crypto）                                          */
/* ------------------------------------------------------------------ */

const enc = new TextEncoder();

/** 浏览器侧 canonicalize 的等价物（与 static/shared/canonical-web.js 一致）。 */
export function webCanonicalBytes(obj) {
  return enc.encode(canonicalize(obj));
}

export async function sha256Hex(objOrString) {
  const bytes = typeof objOrString === 'string'
    ? enc.encode(objOrString) : webCanonicalBytes(objOrString);
  const buf = await subtle.digest('SHA-256', bytes);
  return Buffer.from(buf).toString('hex');
}

export async function genTerminalKeys() {
  return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true,
    ['sign', 'verify']);
}
/** 归一为公钥 JWK 的最小四字段（登记/轮换签名必须基于此，避免 ext/key_ops 干扰）。 */
export async function publicJwkOf(keyOrPair) {
  const k = keyOrPair.publicKey ?? keyOrPair;
  const jwk = await subtle.exportKey('jwk', k);
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
const jwkPub = publicJwkOf;

async function webSign(privateKey, obj) {
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' },
    privateKey, webCanonicalBytes(obj));
  return Buffer.from(sig).toString('base64url');
}

/** 一个"浏览器终端"：持有私钥与证书，封装登记/挑战/落款/轮换/自检/取记录。 */
export class BrowserTerminal {
  constructor(base, opts = {}) {
    this.base = base;
    this.keys = null;
    this.cert = null;
    this.deviceId = null;
    this.label = opts.label ?? '3号拌合站平板';
  }

  async ensureKeys() {
    if (!this.keys) this.keys = await genTerminalKeys();
    return this.keys;
  }

  async register(code, { consentVersion, label } = {}) {
    await this.ensureKeys();
    const cv = consentVersion ??
      (await httpJson(this.base, 'GET', '/api/consent')).json.version;
    const publicJwk = await jwkPub(this.keys);
    const csr = { alg: 'SG-REGISTER-CSR/v1', code,
      device_label: label ?? this.label, public_jwk: publicJwk,
      consent_version: cv };
    const csrSig = await webSign(this.keys.privateKey, csr);
    return httpJson(this.base, 'POST', '/api/terminal/register', { body: {
      code, device_label: label ?? this.label, consent_version: cv,
      public_jwk: publicJwk, csr_sig: csrSig,
    } });
  }

  /** 完成正常登记并保存证书；返回响应。 */
  async registerOk(code, opts) {
    const r = await this.register(code, opts);
    if (r.status === 200) {
      this.cert = r.json.cert;
      this.deviceId = r.json.device_id;
    }
    return r;
  }

  async challenge({ action, sessionId, role, bodyDigest }) {
    return httpJson(this.base, 'POST', '/api/terminal/challenge', { body: {
      cert: this.cert, action, session_id: sessionId, role,
      body_digest: bodyDigest,
    } });
  }

  /**
   * 用挑战构造并发送落款。overrides 可替换请求中的任一字段（测试字段替换攻击），
   * 以及 terminalSigTamper（破坏终端签名）。
   */
  /** 两个标签页竞争同一挑战时，各自独立签名得到的完整请求体。 */
  async buildSubmitBody(tok) {
    const ch = tok.challenge;
    const sr = { alg: 'SG-SIGN-REQUEST/v1', cert_id: ch.cert_id, nonce: ch.nonce,
      action: ch.action, session_id: ch.session_id, role: ch.role,
      body_digest: ch.body_digest, challenge_sig: tok.signature };
    const terminal_sig = await webSign(this.keys.privateKey, sr);
    return { cert: this.cert, challenge: ch, challenge_sig: tok.signature,
      cert_id: ch.cert_id, nonce: ch.nonce, action: ch.action,
      session_id: ch.session_id, role: ch.role, body_digest: ch.body_digest,
      terminal_sig };
  }

  async signSubmit(tok, overrides = {}) {
    const ch = tok.challenge;
    const fields = {
      cert: this.cert, challenge: ch, challenge_sig: tok.signature,
      cert_id: overrides.cert_id ?? ch.cert_id,
      nonce: overrides.nonce ?? ch.nonce,
      action: overrides.action ?? ch.action,
      session_id: overrides.session_id ?? ch.session_id,
      role: overrides.role ?? ch.role,
      body_digest: overrides.body_digest ?? ch.body_digest,
    };
    const sr = { alg: 'SG-SIGN-REQUEST/v1', cert_id: fields.cert_id, nonce: fields.nonce,
      action: fields.action, session_id: fields.session_id, role: fields.role,
      body_digest: fields.body_digest, challenge_sig: fields.challenge_sig };
    fields.terminal_sig = overrides.terminal_sig ??
      await webSign(this.keys.privateKey, sr);
    return httpJson(this.base, 'POST', '/api/terminal/submit', { body: fields });
  }

  /** 用指定私钥对某对象签名（轮换/自证/取记录用）。 */
  async signWith(keyPair, obj) { return webSign(keyPair.privateKey, obj); }

  async inspect() {
    const nonce = 'N' + Date.now() + Math.floor(Math.random() * 1e6);
    const proof = await webSign(this.keys.privateKey,
      { alg: 'SG-INSPECT/v1', cert_id: this.cert.payload.cert_id, nonce });
    return httpJson(this.base, 'POST', '/api/terminal/inspect',
      { body: { cert: this.cert, nonce, proof_sig: proof } });
  }

  async rotate(rotationNonce, newKeys) {
    const csr = { alg: 'SG-ROTATION-CSR/v1', rotation_nonce: rotationNonce,
      old_cert_id: this.cert.payload.cert_id, device_id: this.deviceId,
      new_public_jwk: await jwkPub(newKeys) };
    const oldSig = await webSign(this.keys.privateKey, csr);
    const newSig = await webSign(newKeys.privateKey, csr);
    const r = await httpJson(this.base, 'POST', '/api/terminal/rotate', { body: {
      rotation_nonce: rotationNonce, new_public_jwk: await jwkPub(newKeys),
      old_sig: oldSig, new_sig: newSig,
    } });
    if (r.status === 200) {
      this.oldCert = this.cert;
      this.cert = r.json.cert;
      this.keys = newKeys;
    }
    return r;
  }

  async fetchRecord(recordId, keyPair = this.keys, cert = this.cert) {
    const csr = { alg: 'SG-RECORD-READ/v1', cert_id: cert.payload.cert_id,
      record_id: recordId };
    const proof = await webSign(keyPair.privateKey, csr);
    return httpJson(this.base, 'POST', '/api/terminal/record',
      { body: { record_id: recordId, cert, proof_sig: proof } });
  }
}

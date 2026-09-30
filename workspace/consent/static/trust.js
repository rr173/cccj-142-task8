// 可信设备网关：在浏览器中生成 P-256 密钥，所有状态变更必须带一次性挑战证明。
const TRUST = {
  keyPrefix: "consent.trust.key.",
  devicePrefix: "consent.trust.device.",

  b64url(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    bytes.forEach(b => s += String.fromCharCode(b));
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  },
  fromB64url(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(s + "=".repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
  },
  canonical(obj) {
    return new TextEncoder().encode(this._canonical(obj));
  },
  _canonical(value) {
    if (Array.isArray(value)) return "[" + value.map(v => this._canonical(v)).join(",") + "]";
    if (value && typeof value === "object") {
      return "{" + Object.keys(value).sort().map(k =>
        JSON.stringify(k) + ":" + this._canonical(value[k])).join(",") + "}";
    }
    return JSON.stringify(value);
  },
  async digest(obj) {
    const raw = new TextEncoder().encode(this._canonical(obj));
    const digest = await crypto.subtle.digest("SHA-256", raw);
    return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
  },
  async key(userId) {
    const k = this.keyPrefix + userId;
    let raw = localStorage.getItem(k);
    if (!raw) {
      const pair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      raw = this.b64url(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
      localStorage.setItem(k, raw);
    }
    const bin = this.fromB64url(raw);
    return crypto.subtle.importKey("pkcs8", bin, { name: "ECDSA", namedCurve: "P-256" },
      false, ["sign"]);
  },
  async publicJwk(userId) {
    const priv = await this.key(userId);
    const spki = await crypto.subtle.exportKey("spki", priv);
    const pub = await crypto.subtle.importKey("spki", spki,
      { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pub);
    delete jwk.key_ops; delete jwk.ext;
    return jwk;
  },
  hardwareId(userId) {
    const k = "consent.trust.hardware." + userId;
    let id = localStorage.getItem(k);
    if (!id) {
      id = "HW-" + crypto.randomUUID().replaceAll("-", "");
      localStorage.setItem(k, id);
    }
    return id;
  },
  saved(userId) {
    const raw = localStorage.getItem(this.devicePrefix + userId);
    return raw ? JSON.parse(raw) : null;
  },
  save(userId, info) { localStorage.setItem(this.devicePrefix + userId, JSON.stringify(info)); },
  async sign(priv, requestHash) {
    return this.b64url(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, priv,
      new TextEncoder().encode(this._canonical({
        alg: "CONSENT-ATTESTATION/v1", request_hash: requestHash,
      }))));
  },
  async csrSign(priv, csr) {
    return this.b64url(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, priv,
      new TextEncoder().encode(this._canonical(csr))));
  },
  requestHash({ action, resource, role, bodyHash, challengeId, nonce }) {
    return this.digest({
      alg: "CONSENT-ATTESTATION/v1", action, resource, role,
      body_hash: bodyHash, challenge_id: challengeId, nonce,
    });
  },
  bodyHash(body) {
    const payload = { ...body };
    delete payload.idempotency_key;
    return this.digest(payload);
  },
  async register(userId, enrollmentCode, label) {
    const priv = await this.key(userId);
    const publicJwk = await this.publicJwk(userId);
    const hardwareId = this.hardwareId(userId);
    const csr = {
      alg: "CONSENT-REGISTER-CSR/v1", enrollment_code: enrollmentCode,
      hardware_id: hardwareId, device_label: label || "浏览器可信终端",
      public_jwk: publicJwk,
    };
    const data = await apiRaw("POST", "/api/devices/register", {
      enrollment_code: enrollmentCode, hardware_id: hardwareId,
      device_label: csr.device_label, public_jwk: publicJwk,
      csr_sig: await this.csrSign(priv, csr),
    });
    this.save(userId, { device_id: data.device_id, credential_id: data.credential_id });
    return data;
  },
  async registerExternal(storageKey, enrollmentCode, label) {
    const priv = await this.key(storageKey);
    const publicJwk = await this.publicJwk(storageKey);
    const hardwareId = this.hardwareId(storageKey);
    const csr = {
      alg: "CONSENT-REGISTER-CSR/v1", enrollment_code: enrollmentCode,
      hardware_id: hardwareId, device_label: label || "外部见证浏览器",
      public_jwk: publicJwk,
    };
    return apiRaw("POST", "/api/devices/register", {
      enrollment_code: enrollmentCode, hardware_id: hardwareId,
      device_label: csr.device_label, public_jwk: publicJwk,
      csr_sig: await this.csrSign(priv, csr),
    });
  },
  async ensureExternal(ctx) {
    const storageKey = "witness:" + ctx.sessionId + ":" + ctx.witnessToken;
    let info = this.saved(storageKey);
    if (!info) {
      if (!ctx.enrollmentCode) {
        const e = new Error("见证链接缺少本浏览器一次性设备登记授权。");
        e.code = "device_register_required"; throw e;
      }
      info = await this.registerExternal(storageKey, ctx.enrollmentCode, "外部见证浏览器");
      this.save(storageKey, { device_id: info.device_id, credential_id: info.credential_id });
    }
    return { info, storageKey };
  },
  async ensure(user, enrollmentCode) {
    let info = this.saved(user.id);
    if (!info) {
      enrollmentCode = enrollmentCode || window.prompt(
        "这台浏览器尚未登记。请输入安全管理员签发的一次性终端登记授权：");
      if (!enrollmentCode) {
        const e = new Error("未输入终端登记授权");
        e.code = "device_register_required"; throw e;
      }
      info = await this.register(user.id, enrollmentCode.trim(), user.name + " 的浏览器");
    }
    return info;
  },
  async sendExternal(method, path, body, ctx) {
    const { info, storageKey } = await this.ensureExternal(ctx);
    return this._sendWithCredential(method, path, body, ctx, info, storageKey);
  },
  async send(method, path, body, ctx) {
    const user = getUser();
    if (!user) throw new Error("未登录");
    const info = await this.ensure(user, ctx.enrollmentCode);
    return this._sendWithCredential(method, path, body, ctx, info, user.id);
  },
  async _sendWithCredential(method, path, body, ctx, info, keyId) {
    const payload = { ...body };
    const idem = payload.idempotency_key || (method + ":" + path + ":" + crypto.randomUUID());
    payload.idempotency_key = idem;
    const bodyHash = await this.bodyHash(payload);
    const challenge = await apiRaw("POST", "/api/devices/challenge", {
      credential_id: info.credential_id, action: ctx.action, resource: ctx.resource,
      role: ctx.role || null, body_hash: bodyHash,
      witness_token: ctx.witnessToken || null,
    });
    const requestHash = await this.requestHash({
      action: ctx.action, resource: ctx.resource, role: ctx.role || null,
      bodyHash, challengeId: challenge.challenge_id, nonce: challenge.nonce,
    });
    const priv = await this.key(keyId);
    const attestation = {
      challenge_id: challenge.challenge_id, nonce: challenge.nonce,
      credential_id: info.credential_id, role: ctx.role || null,
      request_hash: requestHash, terminal_signature: await this.sign(priv, requestHash),
    };
    return apiRaw(method, path, payload, {
      "X-Device-Attestation": this.b64url(new TextEncoder().encode(JSON.stringify(attestation))),
    });
  },
};

async function apiRaw(method, path, body, headers = {}) {
  const h = { "Content-Type": "application/json", ...headers };
  const tok = getToken();
  if (tok) h.Authorization = "Bearer " + tok;
  const resp = await fetch(path, { method, headers,
    body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await resp.json();
  if (!resp.ok) {
    const e = new Error(data.message || ("HTTP " + resp.status));
    e.code = data.error; e.body = data; throw e;
  }
  return data;
}

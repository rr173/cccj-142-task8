/**
 * 浏览器端规范化 JSON —— 必须与服务端 src/canonical.js 字节级一致。
 * 加载 /vendor/canonical.js（同一份源）或本文件均可；本文件保留给纯静态部署。
 */
(function (global) {
  function canonicalize(value) {
    if (value === null || typeof value === 'boolean') return String(value);
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
        throw new TypeError('仅支持安全整数');
      }
      return String(value);
    }
    if (typeof value === 'string') return JSON.stringify(value);
    if (Array.isArray(value)) {
      return '[' + value.map(function (v) {
        if (v === undefined) throw new TypeError('数组内不允许 undefined');
        return canonicalize(v);
      }).join(',') + ']';
    }
    if (typeof value === 'object') {
      const keys = Object.keys(value)
        .filter((k) => value[k] !== undefined)
        .sort();
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
    }
    throw new TypeError('不支持的类型');
  }

  function canonicalBytes(value) {
    return new TextEncoder().encode(canonicalize(value));
  }

  async function sha256Hex(value) {
    const bytes = typeof value === 'string'
      ? new TextEncoder().encode(value) : canonicalBytes(value);
    const buf = await crypto.subtle.digest('SHA-256', bytes);
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  global.SG = global.SG || {};
  global.SG.canonicalize = canonicalize;
  global.SG.canonicalBytes = canonicalBytes;
  global.SG.sha256Hex = sha256Hex;

  global.SG.signObject = async function (privateKey, obj) {
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, privateKey, canonicalBytes(obj));
    const bytes = new Uint8Array(sig);
    let bin = '';
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  global.SG.publicJwk = async function (keyPair) {
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    // 只保留最小四字段，避免 ext/key_ops 造成终端/服务端签名对象不一致
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  };

  global.SG.generateKeys = function () {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true,
      ['sign', 'verify']);
  };
})(window);

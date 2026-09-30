/**
 * 浏览器端 static/shared/sg-web.js 的规范化/摘要实现，必须与服务端
 * src/canonical.js 在同一组对象上产出字节级一致的结果——否则页面上
 * Web Crypto 的签名在服务端永远验不过。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { canonicalize as serverCanonical, digestHexSync } from '../src/canonical.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const browserSrc = fs.readFileSync(
  path.join(__dirname, '..', 'static', 'shared', 'sg-web.js'), 'utf8');

// 垫片浏览器环境后执行浏览器脚本
const win = {};
new Function('window', 'btoa', 'TextEncoder', 'crypto', browserSrc)(
  win,
  (b) => Buffer.from(b, 'binary').toString('base64'),
  TextEncoder,
  webcrypto,
);

test('浏览器端与服务端 canonicalize 字节级一致', () => {
  const cases = [
    { a: 1, b: 'x' },
    { z: [1, 2, 3], a: { y: true, n: null } },
    '中文字符串',
    { alg: 'SG-REGISTER-CSR/v1', code: 'abc',
      public_jwk: { kty: 'EC', crv: 'P-256', x: 'xx', y: 'yy' } },
    [{ b: 2, a: 1 }],
    { 数字: 123, 'k-v': [true, false, null] },
    [], {},
  ];
  for (const c of cases) {
    assert.equal(win.SG.canonicalize(c), serverCanonical(c));
  }
});

test('浏览器端 sha256Hex 与服务端摘要一致（对象与字符串）', async () => {
  const obj = { pour: 'C30', axis: 'A-12', crew: 7 };
  assert.equal(await win.SG.sha256Hex(obj), digestHexSync(obj));
  assert.equal(await win.SG.sha256Hex('raw body'), digestHexSync('raw body'));
});

test('浏览器端签名可被服务端验证（完整互操作：generateKey→sign→server verify）', async () => {
  const kp = await win.SG.generateKeys();
  const pub = await win.SG.publicJwk(kp);
  const obj = { alg: 'SG-REGISTER-CSR/v1', code: 'c', device_label: 'd',
    public_jwk: pub, consent_version: 'v' };
  const sig = await win.SG.signObject(kp.privateKey, obj);
  const { verifySignedObject } = await import('../src/crypto.js');
  assert.equal(verifySignedObject(pub, obj, sig), true);
});

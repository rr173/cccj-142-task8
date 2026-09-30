/**
 * 演示播种：在默认 data 目录预置
 *   - 甲站一个已登记设备（已完成一笔落款）；
 *   - 甲站一张未使用的一次性注册码（打印到控制台）；
 *   - 乙站一个被隔离的设备。
 * 用法：node src/seed.js   （仅在空库目录上执行；已有事件则直接退出）
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from './storage.js';
import { SiteGuardService } from './service.js';
import { generateTerminalKeyPair, signObject } from './crypto.js';
import { digestHexSync } from './canonical.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dir = process.env.SIGUARD_DATA || path.join(__dirname, '..', 'data');

if (fs.existsSync(path.join(dir, 'siteguard.wal.log')) &&
    fs.statSync(path.join(dir, 'siteguard.wal.log')).size > 0) {
  console.log('数据目录已有事件日志，跳过播种（如需重置请删除该文件）。');
  process.exit(0);
}

const store = new Store(dir);
const svc = new SiteGuardService(store);

const safeA = { username: 'safeA', role: 'admin', site_code: 'SITE-A' };
const safeB = { username: 'safeB', role: 'admin', site_code: 'SITE-B' };

// 甲站：未用注册码
const openCode = svc.createRegisterCode(safeA, { roles: ['supervisor', 'inspector'], minutes: 480 });

// 甲站：已登记设备 + 一笔历史落款（服务端代生成终端密钥仅为播种可信材料）
const seeded = svc.createRegisterCode(safeA, { roles: ['supervisor', 'inspector'], minutes: 480 });
const kp1 = generateTerminalKeyPair();
const csr1 = {
  alg: 'SG-REGISTER-CSR/v1', code: seeded.code, device_label: '甲站主体结构平板',
  public_jwk: kp1.publicJwk, consent_version: 'CONSENT-2026-09-v1',
};
const reg = svc.registerTerminal({
  code: seeded.code, device_label: '甲站主体结构平板',
  consent_version: 'CONSENT-2026-09-v1',
  public_jwk: kp1.publicJwk, csr_sig: signObject(kp1.privateJwk, csr1),
});
const bodyDigest = digestHexSync({ demo: 'seed', pour: 'C25', axis: 'A-12' });
const tok = svc.issueChallenge({
  cert: reg.cert, action: 'concrete.pour', session_id: 'SESS-SEED-0001',
  role: 'supervisor', body_digest: bodyDigest,
});
const sr = { alg: 'SG-SIGN-REQUEST/v1', ...pick(tok.challenge),
  challenge_sig: tok.signature };
const terminalSig = signObject(kp1.privateJwk, sr);
svc.submitSignedAction({
  cert: reg.cert, challenge: tok.challenge, challenge_sig: tok.signature,
  ...pick(tok.challenge), terminal_sig: terminalSig,
});

// 乙站：设备登记后隔离
const codeB = svc.createRegisterCode(safeB, { roles: ['supervisor'], minutes: 480 });
const kp2 = generateTerminalKeyPair();
const csr2 = {
  alg: 'SG-REGISTER-CSR/v1', code: codeB.code, device_label: '乙站桥梁段平板',
  public_jwk: kp2.publicJwk, consent_version: 'CONSENT-2026-09-v1',
};
const regB = svc.registerTerminal({
  code: codeB.code, device_label: '乙站桥梁段平板',
  consent_version: 'CONSENT-2026-09-v1',
  public_jwk: kp2.publicJwk, csr_sig: signObject(kp2.privateJwk, csr2),
});
svc.quarantineDevice(safeB, { device_id: regB.device_id, reason: '演示：设备送修隔离' });

store.close();

console.log('播种完成。');
console.log('  甲站未用一次性注册码：', openCode.code, `（${openCode.code_ref}，8 小时内有效）`);
console.log('  甲站已登记设备：', reg.device_id, reg.cert.payload.cert_id, '（含一笔历史落款）');
console.log('  乙站设备：', regB.device_id, '（已隔离）');

function pick(ch) {
  return { cert_id: ch.cert_id, nonce: ch.nonce, action: ch.action,
    session_id: ch.session_id, role: ch.role, body_digest: ch.body_digest };
}

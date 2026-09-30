/* 终端页逻辑：本地 WebCrypto 密钥、登记、自检、挑战-落款、同请求重放/篡改演示。 */
const STORE = {
  keys: 'sg.terminal.keys', cert: 'sg.terminal.cert', device: 'sg.terminal.device',
};

let keyPair = null;
let certificate = null;
let consentVersion = null;
let lastChallenge = null;
let actions = {};

const $ = (id) => document.getElementById(id);

/* ------------------------------------------------------------ 本地密钥 */
async function saveKeys(kp) {
  // 仅演示用途把私钥 JWK 放入 localStorage（模拟终端内安全存储）
  const jwkPriv = await crypto.subtle.exportKey('jwk', kp.privateKey);
  localStorage.setItem(STORE.keys, JSON.stringify(jwkPriv));
}
async function loadKeys() {
  const raw = localStorage.getItem(STORE.keys);
  if (!raw) return null;
  const jwk = JSON.parse(raw);
  const privateKey = await crypto.subtle.importKey('jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const pub = await SG.publicJwk({ privateKey });
  const publicKey = await crypto.subtle.importKey('jwk',
    { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y },
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  return { privateKey, publicKey };
}

async function refreshKeyState() {
  keyPair = await loadKeys();
  $('keyState').textContent = keyPair ? '本机密钥已就位' : '尚未生成';
  $('registerBtn').disabled = !(keyPair && $('agree').checked);
}

$('genKeys').onclick = async () => {
  keyPair = await SG.generateKeys();
  await saveKeys(keyPair);
  localStorage.removeItem(STORE.cert);
  certificate = null;
  await refreshKeyState();
  SG.flash($('keyMsg'), 'ok', '已在本机生成新的 ECDSA P-256 密钥对（旧证书若有已失效，需重新登记）。');
};

$('agree').onchange = refreshKeyState;

/* ------------------------------------------------------------ 知情同意 */
(async function initConsent() {
  const c = await SG.api('GET', '/api/consent');
  consentVersion = c.version;
  $('consentText').textContent =
    `${c.title}\n版本：${c.version}\n\n` + c.paragraphs.map((p, i) => `${i + 1}. ${p}`).join('\n');
  const acts = await SG.api('GET', '/api/actions');
  actions = acts.actions;
  for (const [code, meta] of Object.entries(actions)) {
    $('action').add(new Option(`${meta.title}（${code}）`, code));
  }
  $('action').onchange = fillRoles;
  fillRoles();
})();

function fillRoles() {
  const roles = actions[$('action').value]?.roles ?? [];
  $('role').innerHTML = '';
  roles.forEach((r) => $('role').add(new Option(r, r)));
}

/* ------------------------------------------------------------ 登记 */
$('registerBtn').onclick = async () => {
  const msg = $('regMsg');
  try {
    await refreshKeyState();
    if (!keyPair) throw new Error('请先生成本机密钥');
    const publicJwk = await SG.publicJwk(keyPair);
    const csr = {
      alg: 'SG-REGISTER-CSR/v1',
      code: $('regCode').value.trim(),
      device_label: $('devLabel').value.trim(),
      public_jwk: publicJwk,
      consent_version: consentVersion,
    };
    const csrSig = await SG.signObject(keyPair.privateKey, csr);
    const resp = await SG.api('POST', '/api/terminal/register', {
      code: $('regCode').value.trim(),
      device_label: $('devLabel').value.trim(),
      consent_version: consentVersion,
      public_jwk: publicJwk,
      csr_sig: csrSig,
    });
    certificate = resp.cert;
    localStorage.setItem(STORE.cert, JSON.stringify(certificate));
    localStorage.setItem(STORE.device, resp.device_id);
    SG.flash(msg, 'ok',
      `登记成功：设备 ${resp.device_id}，证书 ${certificate.payload.cert_id}（代次 ${certificate.payload.gen}）`);
  } catch (e) {
    SG.flash(msg, 'err', `[${e.code || 'ERROR'}] ${e.message}`);
  }
};

$('loadCertBtn').onclick = async () => {
  const raw = localStorage.getItem(STORE.cert);
  if (!raw) { SG.flash($('inspMsg'), 'err', '本地没有已登记证书'); return; }
  certificate = JSON.parse(raw);
  await refreshKeyState();
  SG.flash($('inspMsg'), 'ok', '已载入本地证书 ' + certificate.payload.cert_id);
};

/* ------------------------------------------------------------ 自检 */
$('inspectBtn').onclick = async () => {
  try {
    if (!certificate || !keyPair) throw new Error('请先登记或载入本机证书');
    const nonce = 'N' + Date.now() + Math.floor(Math.random() * 1e6);
    const proof = await SG.signObject(keyPair.privateKey,
      { alg: 'SG-INSPECT/v1', cert_id: certificate.payload.cert_id, nonce });
    const r = await SG.api('POST', '/api/terminal/inspect',
      { cert: certificate, nonce, proof_sig: proof });
    $('inspMsg').className = 'flash ' + (r.quarantined ? 'err' : 'ok');
    $('inspMsg').textContent = r.quarantined
      ? `设备已被隔离（${r.quarantined_reason ?? ''}），失去后续操作资格；历史记录仍可核对。`
      : `状态正常：${r.status}，第 ${r.gen} 代，有效期至 ${r.not_after}`;
    $('inspOut').textContent = JSON.stringify(r, null, 2);
  } catch (e) {
    SG.flash($('inspMsg'), 'err', `[${e.code || 'ERROR'}] ${e.message}`);
  }
};

/* ------------------------------------------------------------ 挑战/落款 */
async function buildBodyDigest() {
  const raw = $('bodyText').value;
  // 正文若是合法 JSON 则按规范化对象取摘要，否则按原文取摘要
  let parsed = null;
  try { parsed = JSON.parse(raw); } catch { /* 按原文 */ }
  return parsed ? SG.sha256Hex(parsed) : SG.sha256Hex(raw);
}

async function signingRequest(ch, challengeSig) {
  return {
    alg: 'SG-SIGN-REQUEST/v1',
    cert_id: ch.cert_id, nonce: ch.nonce, action: ch.action,
    session_id: ch.session_id, role: ch.role, body_digest: ch.body_digest,
    challenge_sig: challengeSig,
  };
}

$('challengeBtn').onclick = async () => {
  try {
    if (!certificate || !keyPair) throw new Error('请先完成登记');
    const bodyDigest = await buildBodyDigest();
    const tok = await SG.api('POST', '/api/terminal/challenge', {
      cert: certificate,
      action: $('action').value,
      session_id: $('sessionId').value.trim(),
      role: $('role').value,
      body_digest: bodyDigest,
    });
    lastChallenge = tok;
    $('submitBtn').disabled = false;
    $('replayBtn').disabled = false;
    $('tamperBtn').disabled = false;
    $('opOut').textContent =
      `已领取挑战（截止 ${tok.challenge.not_after}）：\n` +
      JSON.stringify(tok.challenge, null, 2);
    SG.flash($('opMsg'), 'info', `挑战已领取，${tok.ttl_ms / 1000} 秒内有效`);
  } catch (e) {
    SG.flash($('opMsg'), 'err', `[${e.code || 'ERROR'}] ${e.message}`);
  }
};

async function submitVariant(overrides = {}) {
  const ch = { ...lastChallenge.challenge, ...overrides };
  const challengeSig = lastChallenge.signature;
  const sr = await signingRequest(ch, challengeSig);
  const terminalSig = await SG.signObject(keyPair.privateKey, sr);
  return SG.api('POST', '/api/terminal/submit', {
    cert: certificate, challenge: ch, challenge_sig: challengeSig,
    cert_id: ch.cert_id, nonce: ch.nonce, action: ch.action,
    session_id: ch.session_id, role: ch.role, body_digest: ch.body_digest,
    terminal_sig: terminalSig,
  });
}

function showResult(r) {
  $('opOut').textContent = JSON.stringify(r, null, 2);
  const kind = r.replay ? 'info' : 'ok';
  SG.flash($('opMsg'), kind,
    r.replay ? `幂等返回首次结果：${r.record_id}` : `落款成功：${r.record_id}`);
}

$('submitBtn').onclick = async () => {
  try { showResult(await submitVariant()); }
  catch (e) {
    SG.flash($('opMsg'), 'err', `[${e.code || 'ERROR'}] ${e.message}`);
    $('opOut').textContent = JSON.stringify(e.body, null, 2);
  }
};
$('replayBtn').onclick = async () => {
  try { showResult(await submitVariant()); }
  catch (e) { SG.flash($('opMsg'), 'err', `[${e.code}] ${e.message}`); }
};
$('tamperBtn').onclick = async () => {
  try {
    const otherRole = $('role').options[$('role').selectedIndex ? 0 : 1]?.value
      ?? 'recorder';
    await submitVariant({ role: otherRole });
    SG.flash($('opMsg'), 'err', '意外：篡改角色后竟然通过了');
  } catch (e) {
    SG.flash($('opMsg'), 'err',
      `已按预期拒绝 [${e.code}]：${e.message}`);
    $('opOut').textContent = JSON.stringify(e.body, null, 2);
  }
};

refreshKeyState();
const savedCert = localStorage.getItem(STORE.cert);
if (savedCert) certificate = JSON.parse(savedCert);

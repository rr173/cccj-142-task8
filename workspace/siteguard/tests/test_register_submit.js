/**
 * 场景 1-4：正常登记并完成落款 / 注册码并发抢占 / 相同请求返回首次结果 /
 *           请求字段被替换时拒绝。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  startApp, httpJson, login, sha256Hex, BrowserTerminal,
} from './helpers.js';

async function registerCode(base, token, roles = ['supervisor', 'inspector']) {
  const r = await httpJson(base, 'POST', '/api/admin/register-codes',
    { token, body: { roles, minutes: 60 } });
  assert.equal(r.status, 200);
  return r.json;
}

test('场景1：浏览器首次登记（WebCrypto 密钥）→ 领挑战 → 私钥落款 → 库外验签通过', async () => {
  const app = await startApp();
  try {
    const safe = await login(app.url, 'safeA');
    const { code } = await registerCode(app.url, safe);
    const term = new BrowserTerminal(app.url, { label: '3号拌合站平板' });

    // 未同意当前版本电子知情同意 → 拒绝
    const stale = await term.register(code, { consentVersion: 'CONSENT-OLD' });
    assert.equal(stale.status, 400);
    assert.equal(stale.json.error, 'CONSENT_VERSION_STALE');

    const reg = await term.registerOk(code);
    assert.equal(reg.status, 200);
    assert.match(reg.json.device_id, /^D-\d{6}$/);
    const cp = reg.json.cert.payload;
    assert.equal(cp.site_code, 'SITE-A');
    assert.equal(cp.device_label, '3号拌合站平板');
    assert.deepEqual(cp.roles, ['supervisor', 'inspector']);
    assert.equal(cp.gen, 1);
    assert.ok(cp.not_after > cp.not_before);
    // 私钥字段绝不出现在证书
    assert.equal(cp.public_jwk.d, undefined);

    const bodyDigest = await sha256Hex({ order: 'POUR-2026-0929-01', level: '3F', m3: 128 });
    const ch = await term.challenge({ action: 'concrete.pour',
      sessionId: 'SESS-2026-0929-0001', role: 'supervisor', bodyDigest });
    assert.equal(ch.status, 200);
    assert.equal(ch.json.challenge.body_digest, bodyDigest);
    assert.equal(ch.json.ttl_ms, 400);
    assert.match(ch.json.challenge.nonce, /^[0-9a-f]{32}$/);

    const submit = await term.signSubmit(ch.json);
    assert.equal(submit.status, 200);
    assert.equal(submit.json.replay, false);
    assert.match(submit.json.record_id, /^R-\d{6}$/);
    assert.equal(submit.json.result.accepted, true);

    // 终端取回自描述记录信封并库外重算
    const rec = await term.fetchRecord(submit.json.record_id);
    assert.equal(rec.status, 200);
    assert.equal(rec.json.verification.ok, true);
    assert.deepEqual(Object.values(rec.json.verification.checks).every(Boolean), true);

    // 公开接口（无需登录、不查库）同样通过
    const pub = await httpJson(app.url, 'POST', '/api/verify-record',
      { body: rec.json.envelope });
    assert.equal(pub.json.ok, true);

    // 管理端记录列表只见本站中性编号
    const recs = await httpJson(app.url, 'GET', '/api/admin/records', { token: safe });
    assert.equal(recs.json.length, 1);
    assert.equal(recs.json[0].body_digest, bodyDigest);
  } finally { await app.close(); }
});

test('场景2：两个浏览器同时用同一注册码登记，只有一个取得证书', async () => {
  const app = await startApp();
  try {
    const safe = await login(app.url, 'safeA');

    // 多轮并发提高交错概率；Node 同步落盘段内每轮必有且仅有一个赢家
    for (let i = 0; i < 8; i++) {
      const one = await registerCode(app.url, safe);
      const ta = new BrowserTerminal(app.url, { label: `甲-${i}` });
      const tb = new BrowserTerminal(app.url, { label: `乙-${i}` });
      const [ra, rb] = await Promise.all([ta.registerOk(one.code), tb.registerOk(one.code)]);
      const wins = [ra, rb].filter((r) => r.status === 200);
      const loses = [ra, rb].filter((r) => r.status !== 200);
      assert.equal(wins.length, 1, `第${i}轮应有且仅有一个登记成功`);
      assert.equal(loses[0].status, 409);
      assert.equal(loses[0].json.error, 'REGISTER_CODE_CONSUMED');

      // 输掉的浏览器稍后再试同一个码：稳定的同一冲突，码不会复活
      const winner = ra.status === 200 ? ta : tb;
      const loser = ra.status === 200 ? tb : ta;
      const retry = await loser.register(one.code);
      assert.equal(retry.status, 409);
      assert.equal(retry.json.error, 'REGISTER_CODE_CONSUMED');
      // 赢家持有的设备只有一台
      assert.match(winner.deviceId, /^D-\d{6}$/);
      assert.equal(loser.deviceId, null);
    }

    // 管理端：8 个码全部已用且各绑定一个证书
    const list = await httpJson(app.url, 'GET', '/api/admin/register-codes', { token: safe });
    const used = list.json.filter((c) => c.used);
    assert.equal(used.length, 8);
    assert.ok(used.every((c) => c.cert_id));
  } finally { await app.close(); }
});

test('场景3：同一挑战+相同请求重发（含双标签各自独立签名）都返回首次结果', async () => {
  const app = await startApp();
  try {
    const safe = await login(app.url, 'safeA');
    const { code } = await registerCode(app.url, safe);
    const term = new BrowserTerminal(app.url);
    await term.registerOk(code);
    const bodyDigest = await sha256Hex({ doc: '交底-高处作业', crew: '三班' });
    const tok = (await term.challenge({ action: 'safety.briefing',
      sessionId: 'SESS-REPLAY-01', role: 'supervisor', bodyDigest })).json;

    const first = await term.signSubmit(tok);
    assert.equal(first.status, 200);
    assert.equal(first.json.replay, false);

    // 同一字节序列再发（同一标签页刷新/重试）
    const second = await term.signSubmit(tok);
    assert.equal(second.status, 200);
    assert.equal(second.json.replay, true);
    assert.equal(second.json.record_id, first.json.record_id);
    assert.equal(second.json.result.receipt, first.json.result.receipt);
    assert.equal(second.json.signed_at, first.json.signed_at);

    // 第二个标签页：重新对同一完整请求独立签名（ECDSA 随机因子使编码不同），
    // 被签署内容相同 → 仍是同一请求，返回首次结果
    const third = await term.signSubmit(tok);
    assert.equal(third.json.replay, true);
    assert.equal(third.json.record_id, first.json.record_id);

    // 只落了一笔记录
    const recs = await httpJson(app.url, 'GET', '/api/admin/records', { token: safe });
    assert.equal(recs.json.length, 1);
  } finally { await app.close(); }
});

test('场景4：替换角色/会话/动作/正文/随机数任一字段一律拒绝，且不产生第二笔结果', async () => {
  const app = await startApp();
  try {
    const safe = await login(app.url, 'safeA');
    const { code } = await registerCode(app.url, safe,
      ['supervisor', 'inspector', 'recorder']);
    const term = new BrowserTerminal(app.url);
    await term.registerOk(code);
    const bodyDigest = await sha256Hex({ doc: '交接-夜班', items: 7 });
    const otherDigest = await sha256Hex({ doc: '交接-夜班', items: 8 });
    const tok = (await term.challenge({ action: 'shift.handoff',
      sessionId: 'SESS-TAMPER-01', role: 'supervisor', bodyDigest })).json;

    const cases = [
      ['角色', { role: 'inspector' }],
      ['会话', { session_id: 'SESS-TAMPER-02' }],
      ['正文摘要', { body_digest: otherDigest }],
      ['动作', { action: 'safety.briefing' }],
      ['随机数', { nonce: '0'.repeat(32) }],
      ['证书号', { cert_id: 'C-999999' }],
    ];
    for (const [name, over] of cases) {
      const r = await term.signSubmit(tok, over);
      assert.equal(r.status, 409, `${name}被替换应拒绝`);
      assert.equal(r.json.error, 'REQUEST_FIELDS_REPLACED', `${name}替换错误码`);
    }

    // 伪造终端签名
    const forged = await term.signSubmit(tok, { terminal_sig: 'A'.repeat(43) });
    assert.equal(forged.status, 401);
    assert.equal(forged.json.error, 'TERMINAL_SIG_INVALID');

    // 原始请求仍然成功（攻击尝试未消费随机数）
    const ok = await term.signSubmit(tok);
    assert.equal(ok.status, 200);
    assert.equal(ok.json.replay, false);

    // 成功后再发任何变体：要么字段绑定失败，要么（同挑战同字段）只是幂等返回首次结果，
    // 绝不会产生第二笔业务结果
    const after = await term.signSubmit(tok, { session_id: 'SESS-TAMPER-03' });
    assert.equal(after.status, 409);
    assert.equal(after.json.error, 'REQUEST_FIELDS_REPLACED');
    const recs = await httpJson(app.url, 'GET', '/api/admin/records', { token: safe });
    assert.equal(recs.json.length, 1);
  } finally { await app.close(); }
});

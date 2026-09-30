/**
 * 场景 5-7：挑战过期 / 两个标签页竞争同一挑战 / 设备隔离与请求提交竞争。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  startApp, httpJson, login, sha256Hex, BrowserTerminal, sleep,
} from './helpers.js';

async function readyTerminal(base, token, roles = ['supervisor', 'inspector']) {
  const issued = await httpJson(base, 'POST', '/api/admin/register-codes',
    { token, body: { roles, minutes: 60 } });
  const term = new BrowserTerminal(base);
  const reg = await term.registerOk(issued.json.code);
  assert.equal(reg.status, 200);
  return term;
}

const SESSION = 'SESS-CONTENT-01';

test('场景5：过期挑战不能落款；过期后重新领取新挑战可正常完成', async () => {
  const app = await startApp({ challengeTtlMs: 250 });
  try {
    const safe = await login(app.url, 'safeA');
    const term = await readyTerminal(app.url, safe);
    const bodyDigest = await sha256Hex({ task: '浇筑', zone: 'A' });

    const tok = (await term.challenge({ action: 'concrete.pour',
      sessionId: SESSION, role: 'supervisor', bodyDigest })).json;

    // 在截止前用掉 -> 成功；截止后重放同一请求 -> 过期拒绝（幂等返回也不允许越过时效）
    const before = await term.signSubmit(tok);
    assert.equal(before.status, 200);
    await sleep(280);
    const stale = await term.signSubmit(tok);
    assert.equal(stale.status, 410);
    assert.equal(stale.json.error, 'CHALLENGE_EXPIRED');

    // 另一张挑战：先等它过期再首发 -> 拒绝，且不产生记录
    const tok2 = (await term.challenge({ action: 'concrete.pour',
      sessionId: 'SESS-CONTENT-02', role: 'supervisor', bodyDigest })).json;
    await sleep(280);
    const late = await term.signSubmit(tok2);
    assert.equal(late.status, 410);
    assert.equal(late.json.error, 'CHALLENGE_EXPIRED');

    // 重新领取（新随机数、新截止）-> 正常落款
    const tok3 = (await term.challenge({ action: 'concrete.pour',
      sessionId: 'SESS-CONTENT-03', role: 'supervisor', bodyDigest })).json;
    const fresh = await term.signSubmit(tok3);
    assert.equal(fresh.status, 200);

    // 恰好只成功 2 笔（过期首发未消费随机数、未落业务结果）
    const recs = await httpJson(app.url, 'GET', '/api/admin/records', { token: safe });
    assert.equal(recs.json.length, 2);
  } finally { await app.close(); }
});

test('场景6：两个标签页竞争同一挑战，按持久化先后只有一个首发、另一个拿到同一首次结果', async () => {
  const app = await startApp();
  try {
    const safe = await login(app.url, 'safeA');
    const term = await readyTerminal(app.url, safe);
    const bodyDigest = await sha256Hex({ task: '隐蔽验收', axis: '1-3' });
    const tok = (await term.challenge({ action: 'steel.acceptance',
      sessionId: 'SESS-TABS-01', role: 'inspector', bodyDigest })).json;

    // 两个标签页各自独立签名（ECDSA 随机因子 -> 两个不同但都合法的签名），
    // 几乎同时 POST 同一完整请求
    const bodyA = await term.buildSubmitBody(tok);
    const bodyB = await term.buildSubmitBody(tok);
    assert.notEqual(bodyA.terminal_sig, bodyB.terminal_sig, '两个签名应相互独立');

    const [ra, rb] = await Promise.all([
      httpJson(app.url, 'POST', '/api/terminal/submit', { body: bodyA }),
      httpJson(app.url, 'POST', '/api/terminal/submit', { body: bodyB }),
    ]);

    const firsts = [ra, rb].filter((r) => r.json.replay === false);
    const replays = [ra, rb].filter((r) => r.json.replay === true);
    assert.equal(firsts.length, 1);
    assert.equal(replays.length, 1);
    assert.equal(ra.json.record_id, rb.json.record_id);
    assert.equal(ra.json.result.receipt, rb.json.result.receipt);
    assert.equal(ra.json.signed_at, rb.json.signed_at);

    // 再来第三、第四个并发重放：全部稳定返回同一首次结果
    const [rc, rd] = await Promise.all([
      httpJson(app.url, 'POST', '/api/terminal/submit', { body: await term.buildSubmitBody(tok) }),
      httpJson(app.url, 'POST', '/api/terminal/submit', { body: await term.buildSubmitBody(tok) }),
    ]);
    assert.ok(rc.json.replay && rd.json.replay);
    assert.equal(rc.json.record_id, ra.json.record_id);

    const recs = await httpJson(app.url, 'GET', '/api/admin/records', { token: safe });
    assert.equal(recs.json.length, 1);
  } finally { await app.close(); }
});

test('场景7：隔离与提交竞争——谁先持久化谁生效，两种先后都唯一收敛，隔离后历史可验',
  { timeout: 60000 }, async () => {
  // 多轮并发，两种先后顺序（先提交落盘 / 先隔离落盘）都可能出现；
  // 每轮的结果必须自洽，且整轮中"成功落款数"与"先提交"次数一致。
  let sawSubmitFirst = 0;
  let sawQuarantineFirst = 0;
  for (let i = 0; i < 12; i++) {
    const app = await startApp({ challengeTtlMs: 60_000 });
    try {
      const safe = await login(app.url, 'safeA');
      const term = await readyTerminal(app.url, safe, ['supervisor']);
      const bodyDigest = await sha256Hex({ round: i, task: '交接班' });
      const tok = (await term.challenge({ action: 'shift.handoff',
        sessionId: `SESS-RACE-${String(i).padStart(2, '0')}`,
        role: 'supervisor', bodyDigest })).json;
      const submitBody = await term.buildSubmitBody(tok);

      // 随机让其中一个请求晚 0~6ms 出发，两种持久化先后顺序都会被覆盖；
      // 生产上两个请求来自不同连接，先后本就不确定。
      const submitDelay = i % 2 === 0 ? 6 : 0;
      const quarantineDelay = i % 2 === 0 ? 0 : 6;
      const [sr, qr] = await Promise.all([
        sleep(submitDelay).then(() =>
          httpJson(app.url, 'POST', '/api/terminal/submit', { body: submitBody })),
        sleep(quarantineDelay).then(() =>
          httpJson(app.url, 'POST', '/api/admin/devices/quarantine',
            { token: safe, body: { device_id: term.deviceId, reason: '竞赛隔离' } })),
      ]);
      assert.equal(qr.status, 200);

      if (sr.status === 200) {
        // 提交先持久化：落款成功；设备随后隔离，该记录仍可验
        sawSubmitFirst++;
        const rec = await term.fetchRecord(sr.json.record_id);
        assert.equal(rec.json.verification.ok, true, '此前成功的记录隔离后仍可验');
        // 再用新挑战 -> 已隔离
        const ch = await term.challenge({ action: 'shift.handoff',
          sessionId: `SESS-AFTER-${i}`, role: 'supervisor', bodyDigest });
        assert.equal(ch.status, 403);
        assert.equal(ch.json.error, 'DEVICE_QUARANTINED');
      } else {
        // 隔离先持久化：本次落款被拒，设备无任何成功记录
        sawQuarantineFirst++;
        assert.equal(sr.status, 403);
        assert.equal(sr.json.error, 'DEVICE_QUARANTINED');
      }
    } finally {
      await app.close();
    }
  }
  assert.equal(sawSubmitFirst + sawQuarantineFirst, 12);
  assert.ok(sawSubmitFirst >= 1, `应观察到先提交成功（实际 ${sawSubmitFirst}）`);
  assert.ok(sawQuarantineFirst >= 1, `应观察到先隔离拒绝（实际 ${sawQuarantineFirst}）`);
});

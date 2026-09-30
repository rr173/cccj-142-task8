/**
 * 测试公共夹具：每用例独立临时 DB + 临时 HTTP 服务（随机端口）。
 */
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { after, before, beforeEach } from 'node:test';
import { initDb } from '../src/db.js';
import { ColdChainService } from '../src/service.js';

let counter = 0;
export function makeContext() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cc-test-'));
  const dbPath = path.join(dir, `test-${++counter}.db`);
  const db = initDb(dbPath);
  const svc = new ColdChainService(db);

  // 账号
  const addUser = (username, role, display = username) => {
    const salt = 's' + username;
    const hash = require_pbkdf2('demo1234', salt);
    db.prepare('INSERT INTO users(username,display,role,salt,pwhash) VALUES(?,?,?,?,?)')
      .run(username, display, role, salt, hash);
  };
  addUser('dev1', 'device');
  addUser('qm1', 'quality');
  addUser('qm2', 'quality');
  addUser('site1', 'site');
  addUser('dev2', 'device');

  const S = Date.parse('2026-09-27T08:00:00Z');
  const iso = (ms) => new Date(ms).toISOString();
  const MIN = 60_000;
  /** 等间隔点序列；overrides 为 {相对分钟: 温度}。 */
  const series = (start, end, base = 5, overrides = {}) => {
    const pts = [];
    for (let t = start, m = 0; t <= end; t += MIN, m++) pts.push([t, overrides[m] ?? base]);
    return pts;
  };
  const rule = (over = {}) => ({
    version: 'RV-1', temp_min_c: 2, temp_max_c: 8,
    max_breach_sec: 300, calib_offset_c: 0, active: true, ...over,
  });

  return { db, dbPath, svc, S, iso, MIN, series,
    dev: { username: 'dev1', role: 'device' },
    dev2: { username: 'dev2', role: 'device' },
    qm1: { username: 'qm1', role: 'quality' },
    qm2: { username: 'qm2', role: 'quality' },
    site: { username: 'site1', role: 'site' },
    createRule(over = {}) {
      return svc.createRule({ username: 'qm1' }, rule(over));
    },
    createWaybill(no, actor, opts = {}) {
      const start = opts.start ?? S;
      const end = opts.end ?? S + 60 * MIN;
      return svc.createWaybill(actor, {
        waybill_no: no, sensor_no: opts.sensor ?? 'SN-' + no,
        expected_start: iso(start), expected_end: iso(end),
        ...(opts.rule_id ? { rule_id: opts.rule_id } : {}),
      });
    },
    frag(no, startMin, endMin, points) {
      return { fragment_no: no, interval_start: iso(S + startMin * MIN),
        interval_end: iso(S + endMin * MIN), points };
    },
  };
}

import crypto from 'node:crypto';
function require_pbkdf2(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 200_000, 32, 'sha256').toString('hex');
}

/** 起一个真实 HTTP 服务（重启测试用）。返回 base url + 关闭函数。 */
export async function startServer(dbPath, port = 0) {
  process.env.COLDCHAIN_DB = dbPath;
  const mod = await import('../src/http.js?' + Date.now());
  await new Promise((r) => mod.server.listen(port, r));
  const addr = mod.server.address();
  return { url: `http://127.0.0.1:${addr.port}`, close: () => new Promise((res) => mod.server.close(res)) };
}

export async function httpJson(base, method, urlPath, { body, token } = {}) {
  const res = await fetch(base + urlPath, {
    method,
    headers: { 'content-type': 'application/json',
      ...(token ? { 'X-Authorization': 'Bearer ' + token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

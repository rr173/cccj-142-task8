/**
 * 冷链证据领域服务：全部业务规则。
 *
 * 关键不变量
 * ----------
 * 1. 规则版本在运单创建时固化为快照列；temp_rules 改版只影响新运单。
 * 2. 片段 (waybill_id, fragment_no) 唯一：同标识同正文幂等返回原回执；
 *    同标识不同正文 409 拒绝；重叠区间重合时刻温度不同 409 且片段不落库。
 * 3. 缺口/越界全部由 analyzeTimeline 从合并后的实际采样点复算，缺测绝不补温。
 * 4. 状态机 collecting → ready ⇄ decided ⇄ revoking → revoked →(再次确认) decided。
 * 5. 确认用条件 UPDATE 抢状态，better-sqlite3 写串行：并发双确认只有一个生效，
 *    另一个幂等返回原决定。
 * 6. 撤销必须另一名质量管理员复核；决定版本 append-only，前后版本都保留。
 * 7. 一旦存在过最终决定，证据集封冻：新片段（非幂等重传）一律冲突。
 * 8. 盲态边界：所有写入字段经敏感词守门，研究站点接口只给中性三态结论。
 */
import crypto from 'node:crypto';
import {
  analyzeTimeline, fragmentContentHash, mergePoints, normalizeFragment,
} from './engine.js';
import {
  analysisDigest, buildCredential, decisionChainDigest,
  privateKeyFromStored,
} from './credential.js';

export const nowIso = () => new Date().toISOString();

export class ServiceError extends Error {
  constructor(code, message, http = 400, extra = null) {
    super(message);
    this.code = code;
    this.message = message;
    this.http = http;
    if (extra) Object.assign(this, extra);
  }
}

/** 盲态守门：任何外部输入都不得夹带药品/分组/批号兼容信息。 */
const FORBIDDEN = ['治疗组', '分配臂', '批号', '批次', '揭盲', '盲态',
  '对照组', '试验组', 'arm', 'lot_no', 'lot-', 'batch', 'cohort'];
export function assertNeutral(label, text) {
  if (text === undefined || text === null) return;
  const low = String(text).toLowerCase();
  for (const w of FORBIDDEN) {
    if (low.includes(w.toLowerCase())) {
      throw new ServiceError('NON_NEUTRAL_CONTENT',
        `${label} 含禁止信息（模块只允许中性运单/传感器标识）`, 422);
    }
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const dk = crypto.pbkdf2Sync(password, salt, 200_000, 32, 'sha256');
  return { salt, hash: dk.toString('hex') };
}

export class ColdChainService {
  constructor(db) {
    this.db = db;
    this.auditStmt = db.prepare(
      `INSERT INTO audit_log(actor,action,detail,created_at) VALUES(?,?,?,?)`);
  }

  audit(actor, action, detail = {}) {
    this.auditStmt.run(actor ?? null, action, JSON.stringify(detail), nowIso());
  }

  // ----------------------------------------------------------- 认证
  login(username, password) {
    const u = this.db.prepare('SELECT * FROM users WHERE username=?').get(username);
    if (!u || hashPassword(password, u.salt).hash !== u.pwhash) {
      throw new ServiceError('BAD_CREDENTIALS', '账号或密码错误', 401);
    }
    const token = crypto.randomBytes(24).toString('hex');
    this.db.prepare('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)')
      .run(token, u.id, nowIso());
    this.audit(u.username, 'login', { role: u.role });
    return { token, username: u.username, display: u.display, role: u.role };
  }

  logout(token) {
    this.db.prepare('DELETE FROM sessions WHERE token=?').run(token ?? '');
  }

  userForToken(token) {
    if (!token) return null;
    const row = this.db.prepare(
      `SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?`
    ).get(token);
    return row ?? null;
  }

  requireUser(token, roles) {
    const u = this.userForToken(token);
    if (!u) throw new ServiceError('UNAUTHENTICATED', '请先登录', 401);
    if (roles && !roles.includes(u.role)) {
      throw new ServiceError('FORBIDDEN', '当前角色无权操作', 403);
    }
    return u;
  }

  // ----------------------------------------------------------- 温控规则
  createRule(actor, body) {
    const v = this.#validateRule(body);
    const exists = this.db.prepare('SELECT 1 FROM temp_rules WHERE version=?').get(v.version);
    if (exists) throw new ServiceError('RULE_VERSION_EXISTS', '规则版本号已存在', 409);
    return this.db.transaction(() => {
      if (v.active) {
        this.db.prepare('UPDATE temp_rules SET active=0 WHERE active=1').run();
      }
      const r = this.db.prepare(
        `INSERT INTO temp_rules(version,temp_min_c,temp_max_c,max_breach_sec,
           calib_offset_c,active,created_by,created_at)
         VALUES(?,?,?,?,?,?,?,?)`
      ).run(v.version, v.temp_min_c, v.temp_max_c, v.max_breach_sec,
        v.calib_offset_c, v.active ? 1 : 0, actor.username, nowIso());
      this.audit(actor.username, 'rule.create', {
        rule_id: r.lastInsertRowid, version: v.version, active: v.active });
      return this.getRule(r.lastInsertRowid);
    }).immediate();
  }

  #validateRule(body) {
    const b = body ?? {};
    if (typeof b.version !== 'string' || !b.version.trim()) {
      throw new ServiceError('BAD_RULE', 'version 必填');
    }
    const num = (k) => {
      if (typeof b[k] !== 'number' || !Number.isFinite(b[k])) {
        throw new ServiceError('BAD_RULE', `${k} 必须是数值`);
      }
      return b[k];
    };
    const temp_min_c = num('temp_min_c');
    const temp_max_c = num('temp_max_c');
    const calib_offset_c = num('calib_offset_c');
    if (!(temp_min_c < temp_max_c)) {
      throw new ServiceError('BAD_RULE', 'temp_min_c 必须小于 temp_max_c');
    }
    let max_breach_sec = b.max_breach_sec;
    if (!Number.isInteger(max_breach_sec) || max_breach_sec < 0) {
      throw new ServiceError('BAD_RULE', 'max_breach_sec 必须是非负整数秒');
    }
    return {
      version: b.version.trim(), temp_min_c, temp_max_c, max_breach_sec,
      calib_offset_c, active: b.active !== false, // 默认发布即为当前版本
    };
  }

  getRule(id) {
    const r = this.db.prepare('SELECT * FROM temp_rules WHERE id=?').get(id);
    if (!r) throw new ServiceError('RULE_NOT_FOUND', '规则版本不存在', 404);
    return this.#ruleOut(r);
  }

  listRules() {
    return this.db.prepare('SELECT * FROM temp_rules ORDER BY id DESC')
      .all().map((r) => this.#ruleOut(r));
  }

  #ruleOut(r) {
    return {
      id: r.id, version: r.version, temp_min_c: r.temp_min_c,
      temp_max_c: r.temp_max_c, max_breach_sec: r.max_breach_sec,
      calib_offset_c: r.calib_offset_c, active: !!r.active,
      created_by: r.created_by, created_at: r.created_at,
    };
  }

  #activeRuleId() {
    const r = this.db.prepare('SELECT id FROM temp_rules WHERE active=1 ORDER BY id DESC LIMIT 1').get();
    if (!r) throw new ServiceError('NO_ACTIVE_RULE', '尚无温控规则版本，请质量管理员先发布', 409);
    return r.id;
  }

  // ----------------------------------------------------------- 运单
  createWaybill(actor, body) {
    const b = body ?? {};
    if (typeof b.waybill_no !== 'string' || !b.waybill_no.trim()) {
      throw new ServiceError('BAD_WAYBILL', 'waybill_no 必填');
    }
    const waybill_no = b.waybill_no.trim();
    assertNeutral('waybill_no', waybill_no);
    if (typeof b.sensor_no !== 'string' || !b.sensor_no.trim()) {
      throw new ServiceError('BAD_WAYBILL', 'sensor_no 必填');
    }
    assertNeutral('sensor_no', b.sensor_no);
    const expected_start = asIsoOr400(b.expected_start, 'expected_start');
    const expected_end = asIsoOr400(b.expected_end, 'expected_end');
    if (!(Date.parse(expected_start) < Date.parse(expected_end))) {
      throw new ServiceError('BAD_WAYBILL', '采样区间必须满足 start < end');
    }
    // 幂等键：设备重试创建同一运单号时返回原单（中性参数仍需一致）
    const existing = this.db.prepare('SELECT * FROM waybills WHERE waybill_no=?').get(waybill_no);
    if (existing) {
      if (existing.sensor_no !== b.sensor_no.trim() ||
          existing.expected_start !== expected_start ||
          existing.expected_end !== expected_end) {
        throw new ServiceError('WAYBILL_NO_CONFLICT',
          '运单号已存在但运单参数不同，拒绝', 409);
      }
      return this.waybillDetail(existing, actor);
    }
    return this.db.transaction(() => {
      const ruleId = b.rule_id ? Number(b.rule_id) : this.#activeRuleId();
      const rule = this.db.prepare('SELECT * FROM temp_rules WHERE id=?').get(ruleId);
      if (!rule) throw new ServiceError('RULE_NOT_FOUND', '指定的规则版本不存在', 404);
      const r = this.db.prepare(
        `INSERT INTO waybills(waybill_no,sensor_no,expected_start,expected_end,
           rule_id,rule_version,rule_min_c,rule_max_c,rule_breach_sec,rule_offset_c,
           state,created_by,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?, 'collecting', ?, ?)`
      ).run(waybill_no, b.sensor_no.trim(), expected_start, expected_end,
        rule.id, rule.version, rule.temp_min_c, rule.temp_max_c, rule.max_breach_sec,
        rule.calib_offset_c, actor.username, nowIso());
      this.audit(actor.username, 'waybill.create', {
        waybill_no, rule_version: rule.version });
      const w = this.db.prepare('SELECT * FROM waybills WHERE id=?').get(r.lastInsertRowid);
      return this.waybillDetail(w, actor);
    }).immediate();
  }

  #getWaybill(idOrNo, { byNo = false } = {}) {
    const w = this.db
      .prepare(byNo ? 'SELECT * FROM waybills WHERE waybill_no=?' : 'SELECT * FROM waybills WHERE id=?')
      .get(idOrNo);
    if (!w) throw new ServiceError('WAYBILL_NOT_FOUND', '运单不存在', 404);
    return w;
  }

  listWaybills() {
    return this.db.prepare('SELECT * FROM waybills ORDER BY id DESC').all()
      .map((w) => this.waybillDetail(w, null, { lite: true }));
  }

  waybillDetailById(id, actor) {
    return this.waybillDetail(this.#getWaybill(id), actor);
  }

  waybillDetailByNo(no, actor) {
    return this.waybillDetail(this.#getWaybill(no, { byNo: true }), actor);
  }

  /** 组装完整视图：规则快照 + 原始片段 + 合并分析 + 决定版本 + 撤销 + 凭据。 */
  waybillDetail(w, actor, { lite = false } = {}) {
    const frags = this.db.prepare(
      'SELECT * FROM fragments WHERE waybill_id=? ORDER BY seq_no').all(w.id);
    const analysis = this.computeAnalysis(w, frags);
    const base = {
      id: w.id,
      waybill_no: w.waybill_no,
      sensor_no: w.sensor_no,
      expected_start: w.expected_start,
      expected_end: w.expected_end,
      state: w.state,
      created_by: w.created_by,
      created_at: w.created_at,
      rule_snapshot: {
        version: w.rule_version, temp_min_c: w.rule_min_c, temp_max_c: w.rule_max_c,
        max_breach_sec: w.rule_breach_sec, calib_offset_c: w.rule_offset_c,
      },
      n_fragments: frags.length,
      analysis: lite ? this.#liteAnalysis(analysis) : analysis,
    };
    if (lite) return base;
    base.fragments = frags.map((f) => ({
      id: f.id, fragment_no: f.fragment_no,
      interval_start: f.interval_start, interval_end: f.interval_end,
      n_points: f.n_points, content_hash: f.content_hash,
      points: JSON.parse(f.points_json),
      uploaded_by: f.uploaded_by, uploaded_at: f.uploaded_at, seq_no: f.seq_no,
    }));
    base.decision_versions = this.db.prepare(
      'SELECT * FROM decision_versions WHERE waybill_id=? ORDER BY revision').all(w.id)
      .map((d) => ({
        revision: d.revision, disposition: d.disposition, reason: d.reason,
        decided_by: d.decided_by, decided_at: d.decided_at,
        revokes_revision: d.revokes_revision,
        analysis: JSON.parse(d.analysis_json),
      }));
    const pend = this.db.prepare(
      `SELECT * FROM revocation_requests WHERE waybill_id=? AND state='pending'
       ORDER BY id DESC LIMIT 1`).get(w.id);
    if (pend) {
      base.pending_revocation = {
        id: pend.id, revision: pend.revision, reason: pend.reason,
        requested_by: pend.requested_by, requested_at: pend.requested_at,
      };
    }
    const cred = this.db.prepare(
      'SELECT cred_no, revision, issued_by, issued_at FROM credentials WHERE waybill_id=? ORDER BY revision DESC')
      .all(w.id);
    base.credentials = cred;
    return base;
  }

  #liteAnalysis(a) {
    return {
      complete: a.complete, n_points: a.n_points, n_breaches: a.n_breaches,
      n_gaps: a.gaps.length, n_conflicts: a.point_conflicts.length,
      suggested_disposition: a.suggested_disposition,
    };
  }

  /** 从库中片段重算（唯一事实来源；无缓存，因此重启/换进程结果一致）。 */
  computeAnalysis(w, fragRows = null) {
    const frags = fragRows ?? this.db.prepare(
      'SELECT * FROM fragments WHERE waybill_id=?').all(w.id);
    return analyzeTimeline(
      {
        waybill_no: w.waybill_no, sensor_no: w.sensor_no,
        expected_start: w.expected_start, expected_end: w.expected_end,
      },
      {
        temp_min_c: w.rule_min_c, temp_max_c: w.rule_max_c,
        max_breach_sec: w.rule_breach_sec, calib_offset_c: w.rule_offset_c,
      },
      frags.map((f) => ({
        fragment_no: f.fragment_no, interval_start: f.interval_start,
        interval_end: f.interval_end, points: JSON.parse(f.points_json),
      })),
    );
  }

  // ----------------------------------------------------------- 片段上传
  uploadFragment(actor, waybillNo, body) {
    const w = this.#getWaybill(waybillNo, { byNo: true });
    let nf;
    try {
      nf = normalizeFragment(body);
    } catch (e) {
      if (e.code === 'BAD_FRAGMENT') {
        throw new ServiceError('BAD_FRAGMENT', e.message, 400);
      }
      throw e;
    }
    assertNeutral('fragment_no', nf.fragment_no);
    if (body.sensor_no && body.sensor_no !== w.sensor_no) {
      throw new ServiceError('SENSOR_MISMATCH',
        '片段上报的传感器编号与运单固化的传感器不一致', 409);
    }
    const content_hash = fragmentContentHash(nf);

    const result = this.db.transaction(() => {
      const existing = this.db.prepare(
        'SELECT * FROM fragments WHERE waybill_id=? AND fragment_no=?')
        .get(w.id, nf.fragment_no);
      // 1) 同标识：幂等 或 正文冲突（最高优先级，任何状态下一致）
      if (existing) {
        if (existing.content_hash === content_hash) {
          const frags = this.db.prepare(
            'SELECT * FROM fragments WHERE waybill_id=? ORDER BY seq_no').all(w.id);
          return {
            idempotent: true, accepted: true, fragment_id: existing.id,
            fragment_no: existing.fragment_no, uploaded_at: existing.uploaded_at,
            waybill: this.waybillDetail(w, actor),
          };
        }
        this.audit(actor.username, 'fragment.content_conflict', {
          waybill_no: w.waybill_no, fragment_no: nf.fragment_no,
          stored_hash: existing.content_hash, incoming_hash: content_hash });
        throw new ServiceError('FRAGMENT_CONTENT_CONFLICT',
          '片段标识已存在但采样正文不同：拒绝。必须使用新的片段标识，不得覆盖原始证据。', 409);
      }

      // 2) 证据集已封冻（存在过最终决定）：新片段 = 冲突，不静默并入
      const everDecided = this.db.prepare(
        'SELECT 1 FROM decision_versions WHERE waybill_id=? LIMIT 1').get(w.id);
      if (everDecided) {
        this.audit(actor.username, 'fragment.after_decision_conflict', {
          waybill_no: w.waybill_no, fragment_no: nf.fragment_no });
        throw new ServiceError('EVIDENCE_SEALED',
          '运单已有最终处置决定，新片段不能并入证据集（如需变更须走撤销复核流程）。', 409);
      }

      // 3) 声明区间必须落在运单期望采样区间内（越界上传不静默截断）
      const s = Date.parse(nf.interval_start);
      const e = Date.parse(nf.interval_end);
      const expS = Date.parse(w.expected_start);
      const expE = Date.parse(w.expected_end);
      if (s < expS || e > expE) {
        this.audit(actor.username, 'fragment.out_of_range', {
          waybill_no: w.waybill_no, fragment_no: nf.fragment_no });
        throw new ServiceError('FRAGMENT_OUT_OF_RANGE',
          '片段声明区间超出运单采样区间，拒绝（异常不得静默跳过）。', 409);
      }

      // 4) 重叠区间逐点一致性预检（冲突时整个片段不落库）
      const priorPoints = this.db.prepare(
        'SELECT t_ms, temp_c, fragment_id FROM sample_points WHERE waybill_id=? ORDER BY t_ms')
        .all(w.id).map((r) => [r.t_ms, r.temp_c, r.fragment_id]);
      try {
        mergePoints(priorPoints, nf, -1); // ref=-1 仅用于冲突预检
      } catch (err) {
        this.audit(actor.username, 'fragment.point_conflict', {
          waybill_no: w.waybill_no, fragment_no: nf.fragment_no,
          conflicts: err.conflicts.length });
        throw new ServiceError('POINT_CONFLICT',
          '与既有片段在重叠时刻温度不一致，拒绝合并', 409, { conflicts: err.conflicts });
      }

      const seqRow = this.db.prepare(
        'SELECT COALESCE(MAX(seq_no),0)+1 n FROM fragments WHERE waybill_id=?').get(w.id);
      const ins = this.db.prepare(
        `INSERT INTO fragments(waybill_id,fragment_no,interval_start,interval_end,
           n_points,points_json,content_hash,uploaded_by,uploaded_at,seq_no)
         VALUES(?,?,?,?,?,?,?,?,?,?)`).run(
        w.id, nf.fragment_no, nf.interval_start, nf.interval_end,
        nf.points.length, JSON.stringify(nf.points), content_hash,
        actor.username, nowIso(), seqRow.n);
      const fragId = ins.lastInsertRowid;
      const pstmt = this.db.prepare(
        'INSERT OR IGNORE INTO sample_points(waybill_id,t_ms,temp_c,fragment_id) VALUES(?,?,?,?)');
      // 重叠的相同时刻已由预检保证一致，IGNORE 收敛为一个证据点
      for (const [t, v] of nf.points) pstmt.run(w.id, t, v, fragId);

      // 5) 状态推进：时间线完整才允许进入待处置
      const frags = this.db.prepare(
        'SELECT * FROM fragments WHERE waybill_id=? ORDER BY seq_no').all(w.id);
      const analysis = this.computeAnalysis(w, frags);
      if (analysis.complete && w.state === 'collecting') {
        this.db.prepare("UPDATE waybills SET state='ready' WHERE id=? AND state='collecting'")
          .run(w.id);
        w.state = 'ready';
      }
      this.audit(actor.username, 'fragment.upload', {
        waybill_no: w.waybill_no, fragment_no: nf.fragment_no, n_points: nf.points.length,
        complete: analysis.complete, n_gaps: analysis.gaps.length,
        n_breaches: analysis.n_breaches });
      return {
        idempotent: false, accepted: true, fragment_id: fragId,
        fragment_no: nf.fragment_no, content_hash,
        waybill: this.waybillDetail({ ...w }, actor),
      };
    }).immediate();
    return result;
  }

  // ----------------------------------------------------------- 质量处置
  confirmDecision(actor, waybillId, body) {
    const w = this.#getWaybill(waybillId);
    const disposition = body?.disposition;
    if (!['accept', 'quarantine'].includes(disposition)) {
      throw new ServiceError('BAD_DISPOSITION', "disposition 必须是 accept 或 quarantine");
    }
    if (typeof body.reason !== 'string' || !body.reason.trim()) {
      throw new ServiceError('BAD_REASON', '处置理由必填');
    }
    assertNeutral('reason', body.reason);
    const reason = body.reason.trim();

    return this.db.transaction(() => {
      // 并发双确认：条件 UPDATE 抢状态，只有一个事务 changes=1
      const taken = this.db.prepare(
        `UPDATE waybills SET state='decided'
         WHERE id=? AND state IN ('ready','revoked')`).run(w.id);
      if (taken.changes === 0) {
        const cur = this.#getWaybill(w.id);
        if (cur.state === 'decided') {
          // 重复确认（含并发落败方）：幂等返回原结果
          const latest = this.db.prepare(
            'SELECT * FROM decision_versions WHERE waybill_id=? ORDER BY revision DESC LIMIT 1')
            .get(w.id);
          this.audit(actor.username, 'decision.confirm_idempotent', {
            waybill_no: w.waybill_no, revision: latest.revision });
          return { idempotent: true, decision: this.#decisionOut(latest),
            waybill: this.waybillDetail(cur, actor) };
        }
        if (cur.state === 'revoking') {
          throw new ServiceError('REVOCATION_IN_REVIEW',
            '撤销复核未完成，不能做新的最终决定', 409);
        }
        throw new ServiceError('TIMELINE_INCOMPLETE',
          '时间线尚有缺口或冲突，只能显示待补传，不能形成最终处置', 409);
      }

      const prev = this.db.prepare(
        'SELECT MAX(revision) m FROM decision_versions WHERE waybill_id=?').get(w.id).m;
      const revision = (prev ?? 0) + 1;
      const fresh = this.#getWaybill(w.id);
      const analysis = this.computeAnalysis(fresh);
      if (!analysis.complete) {
        // 理论不可达（ready 意味着完整），防御性回滚
        throw new ServiceError('TIMELINE_INCOMPLETE', '时间线不完整', 409);
      }
      const r = this.db.prepare(
        `INSERT INTO decision_versions(waybill_id,revision,disposition,reason,
           analysis_json,decided_by,decided_at,revokes_revision)
         VALUES(?,?,?,?,?,?,?,?)`).run(
        w.id, revision, disposition, reason, JSON.stringify(analysis),
        actor.username, nowIso(), prev ?? null);
      this.audit(actor.username, 'decision.confirm', {
        waybill_no: w.waybill_no, revision, disposition,
        suggested: analysis.suggested_disposition, n_breaches: analysis.n_breaches });
      const d = this.db.prepare('SELECT * FROM decision_versions WHERE id=?').get(r.lastInsertRowid);
      return { idempotent: false, decision: this.#decisionOut(d),
        waybill: this.waybillDetail(this.#getWaybill(w.id), actor) };
    }).immediate();
  }

  #decisionOut(d) {
    return {
      revision: d.revision, disposition: d.disposition, reason: d.reason,
      decided_by: d.decided_by, decided_at: d.decided_at,
      revokes_revision: d.revokes_revision,
    };
  }

  requestRevocation(actor, waybillId, body) {
    const w = this.#getWaybill(waybillId);
    if (typeof body?.reason !== 'string' || !body.reason.trim()) {
      throw new ServiceError('BAD_REASON', '撤销理由必填');
    }
    assertNeutral('reason', body.reason);
    return this.db.transaction(() => {
      const pend = this.db.prepare(
        `SELECT * FROM revocation_requests WHERE waybill_id=? AND state='pending'`).get(w.id);
      if (pend) {
        // 重复请求幂等返回原申请（不换请求人、不改理由）
        return { idempotent: true, revocation: this.#revOut(pend) };
      }
      if (w.state !== 'decided') {
        throw new ServiceError('WAYBILL_NOT_DECIDED',
          '只有已有最终决定的运单才能申请撤销', 409);
      }
      const latest = this.db.prepare(
        'SELECT revision FROM decision_versions WHERE waybill_id=? ORDER BY revision DESC LIMIT 1')
        .get(w.id);
      const r = this.db.prepare(
        `INSERT INTO revocation_requests(waybill_id,revision,reason,requested_by,
           requested_at,state) VALUES(?,?,?,?,?, 'pending')`).run(
        w.id, latest.revision, body.reason.trim(), actor.username, nowIso());
      this.db.prepare("UPDATE waybills SET state='revoking' WHERE id=?").run(w.id);
      this.audit(actor.username, 'decision.revoke_request', {
        waybill_no: w.waybill_no, revision: latest.revision });
      return { idempotent: false,
        revocation: this.#revOut(this.db.prepare(
          'SELECT * FROM revocation_requests WHERE id=?').get(r.lastInsertRowid)) };
    }).immediate();
  }

  reviewRevocation(actor, requestId, body) {
    const approve = body?.approve === true;
    const note = typeof body?.note === 'string' ? body.note.trim() : '';
    assertNeutral('note', note);
    return this.db.transaction(() => {
      const req = this.db.prepare('SELECT * FROM revocation_requests WHERE id=?').get(requestId);
      if (!req) throw new ServiceError('REVOCATION_NOT_FOUND', '撤销申请不存在', 404);
      if (req.state !== 'pending') {
        return { idempotent: true, revocation: this.#revOut(req) };
      }
      // 必须由"另一名"质量管理员复核
      if (req.requested_by === actor.username) {
        throw new ServiceError('REVIEWER_MUST_DIFFER',
          '撤销必须由提出申请之外的另一名质量管理员复核', 403);
      }
      const state = approve ? 'approved' : 'rejected';
      this.db.prepare(
        `UPDATE revocation_requests SET state=?, reviewed_by=?, reviewed_at=?, review_note=?
         WHERE id=? AND state='pending'`).run(state, actor.username, nowIso(), note, req.id);
      const w = this.#getWaybill(req.waybill_id);
      this.db.prepare(
        `UPDATE waybills SET state=? WHERE id=? AND state='revoking'`)
        .run(approve ? 'revoked' : 'decided', w.id);
      this.audit(actor.username, 'decision.revoke_review', {
        waybill_no: w.waybill_no, request_id: req.id, approved: approve });
      return { idempotent: false,
        revocation: this.#revOut(this.db.prepare(
          'SELECT * FROM revocation_requests WHERE id=?').get(req.id)),
        waybill: this.waybillDetail(this.#getWaybill(w.id), actor) };
    }).immediate();
  }

  listRevocations(includeClosed = false) {
    const sql = includeClosed
      ? 'SELECT * FROM revocation_requests ORDER BY id DESC'
      : "SELECT * FROM revocation_requests WHERE state='pending' ORDER BY id DESC";
    return this.db.prepare(sql).all().map((r) => ({
      ...this.#revOut(r),
      waybill_no: this.#getWaybill(r.waybill_id).waybill_no,
    }));
  }

  #revOut(r) {
    return {
      id: r.id, waybill_id: r.waybill_id, revision: r.revision, reason: r.reason,
      requested_by: r.requested_by, requested_at: r.requested_at, state: r.state,
      reviewed_by: r.reviewed_by, reviewed_at: r.reviewed_at, review_note: r.review_note,
    };
  }

  // ----------------------------------------------------------- 处置凭据
  issueCredential(actor, waybillId) {
    const w = this.#getWaybill(waybillId);
    return this.db.transaction(() => {
      if (w.state !== 'decided') {
        throw new ServiceError('NO_FINAL_DECISION',
          '只有存在最终决定（且未处于撤销中）时才能签发凭据', 409);
      }
      const latest = this.db.prepare(
        'SELECT * FROM decision_versions WHERE waybill_id=? ORDER BY revision DESC LIMIT 1')
        .get(w.id);
      const existing = this.db.prepare(
        'SELECT envelope_json FROM credentials WHERE waybill_id=? AND revision=?')
        .get(w.id, latest.revision);
      if (existing) {
        return { idempotent: true, credential: JSON.parse(existing.envelope_json) };
      }
      const fragRows = this.db.prepare(
        'SELECT * FROM fragments WHERE waybill_id=? ORDER BY fragment_no').all(w.id);
      const versions = this.db.prepare(
        'SELECT * FROM decision_versions WHERE waybill_id=? ORDER BY revision').all(w.id)
        .map((d) => ({
          revision: d.revision, disposition: d.disposition, reason: d.reason,
          decided_by: d.decided_by, decided_at: d.decided_at,
          revokes_revision: d.revokes_revision,
          analysis_digest: analysisDigest(JSON.parse(d.analysis_json)),
        }));
      const credNo = 'CC-' + this.db.prepare(
        "SELECT printf('%04d', COALESCE(MAX(id),0)+1) n FROM credentials").get().n;
      const issuedAt = nowIso();
      const privD = this.db.prepare(
        "SELECT value FROM app_meta WHERE key='signing_private_jwk'").get().value;
      const envelope = buildCredential({
        cred_no: credNo,
        issued_at: issuedAt,
        issued_by: actor.username,
        waybill: {
          waybill_no: w.waybill_no, sensor_no: w.sensor_no,
          expected_start: w.expected_start, expected_end: w.expected_end,
          rule_version: w.rule_version, rule_min_c: w.rule_min_c,
          rule_max_c: w.rule_max_c, rule_breach_sec: w.rule_breach_sec,
          rule_offset_c: w.rule_offset_c,
        },
        fragments: fragRows.map((f) => ({
          fragment_no: f.fragment_no, interval_start: f.interval_start,
          interval_end: f.interval_end, points: JSON.parse(f.points_json),
        })),
        analysis: JSON.parse(latest.analysis_json),
        decision_versions: versions,
      }, privateKeyFromStored(privD));
      this.db.prepare(
        `INSERT INTO credentials(cred_no,waybill_id,revision,envelope_json,issued_by,issued_at)
         VALUES(?,?,?,?,?,?)`)
        .run(credNo, w.id, latest.revision, JSON.stringify(envelope), actor.username, issuedAt);
      this.audit(actor.username, 'credential.issue', {
        waybill_no: w.waybill_no, revision: latest.revision, cred_no: credNo,
        fragments_digest: envelope.payload.fragments_set_digest,
        decision_digest: envelope.payload.decision_chain_digest });
      return { idempotent: false, credential: envelope };
    }).immediate();
  }

  getCredentialByNo(credNo) {
    const row = this.db.prepare('SELECT envelope_json FROM credentials WHERE cred_no=?')
      .get(credNo);
    if (!row) throw new ServiceError('CREDENTIAL_NOT_FOUND', '凭据不存在', 404);
    return JSON.parse(row.envelope_json);
  }

  // ----------------------------------------------------------- 研究站点（只读、极简）
  siteListView() {
    return this.db.prepare('SELECT * FROM waybills ORDER BY id').all()
      .map((w) => this.siteView(w));
  }

  siteViewByNo(no) {
    return this.siteView(this.#getWaybill(no, { byNo: true }));
  }

  /** 站点只见：中性运单号 + 能否接收 + 一句话原因。无温度、无缺口明细、无规则、无片段。 */
  siteView(w) {
    let receivable = null;
    let status;
    let reason;
    switch (w.state) {
      case 'collecting':
        status = 'PENDING_UPLOAD';
        reason = '运输温度记录尚未传齐，等待补传';
        break;
      case 'ready':
        status = 'PENDING_REVIEW';
        reason = '温度记录已完整，等待质量处置';
        break;
      case 'revoking':
        status = 'UNDER_REVIEW';
        receivable = false;
        reason = '原处置正在撤销复核，暂不可接收';
        break;
      case 'revoked':
        status = 'PENDING_REVIEW';
        reason = '原处置已撤销，等待重新质量处置';
        break;
      case 'decided': {
        status = 'FINAL';
        const latest = this.db.prepare(
          'SELECT disposition FROM decision_versions WHERE waybill_id=? ORDER BY revision DESC LIMIT 1')
          .get(w.id);
        if (latest.disposition === 'accept') {
          receivable = true;
          reason = '温度记录完整且符合温控要求，可接收';
        } else {
          receivable = false;
          reason = '温度记录存在不可接受的偏离，不可接收';
        }
        break;
      }
      default:
        status = w.state;
        reason = '';
    }
    return { waybill_no: w.waybill_no, status, receivable, reason };
  }

  auditLog(limit = 200) {
    return this.db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?')
      .all(Math.min(Math.max(Number(limit) || 200, 1), 1000))
      .map((r) => ({ id: r.id, actor: r.actor, action: r.action,
        detail: JSON.parse(r.detail), created_at: r.created_at }));
  }
}

/** 复用引擎的 mergePoints（顶部已导入，预检用临时引用 -1）。 */
function asIsoOr400(v, field) {
  if (typeof v === 'number' && Number.isInteger(v)) return new Date(v).toISOString();
  if (typeof v !== 'string' || !Number.isFinite(Date.parse(v))) {
    throw new ServiceError('BAD_WAYBILL', `${field} 必须是 ISO 时间`);
  }
  return new Date(Date.parse(v)).toISOString();
}

/**
 * 冷链判定纯函数核心（无数据库依赖；同一份代码被服务端、Node 测试与浏览器校验器复用）。
 *
 * 职责：
 *   1. 片段"采样正文"的规范化与哈希 —— 幂等/冲突判定的唯一依据；
 *   2. 时间线合并 —— 重叠区间只能在逐点数据相同的部分合并，任何冲突逐点报出；
 *   3. 缺口计算 —— 缺测就是缺测，绝不按正常温度补齐；
 *   4. 连续越界计算 —— 按合并后的实际采样时刻连续计时，缺口打断连续段。
 *
 * 采样点统一表示：[tMs(整数毫秒), tempC(数值)]。
 */

/** Node 端需要 createHash；浏览器端只做凭据校验（走 SubtleCrypto 异步路径）。 */
let createHash = null;
try {
  ({ createHash } = await import('node:crypto'));
} catch { /* 浏览器环境：fragmentContentHash/sha256Hex 不可用，其余纯函数正常 */ }

/** 规范化 JSON：键序固定、无多余空白，保证跨进程结果一致。 */
export function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

export function sha256Hex(data) {
  if (!createHash) throw new Error('同步 sha256 仅在 Node 端可用');
  return createHash('sha256').update(data).digest('hex');
}

/** 数值规范化：避免 2 与 2.0、-0 这类表示差异造成伪冲突。 */
function numKey(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) throw new BadFragment('温度必须是有限数值');
  return Object.is(n, -0) ? 0 : n;
}

/**
 * 片段内容哈希：只取决于采样正文（声明区间 + 逐点数据），与上传顺序、上传时间、
 * 上传账号无关 —— 离线设备乱序补传/重复上传，同标识同正文必然得到相同哈希。
 */
export function fragmentContentHash(frag) {
  return sha256Hex(
    canonicalJSON({
      interval_start: frag.interval_start,
      interval_end: frag.interval_end,
      points: frag.points.map((p) => [Math.trunc(p[0]), numKey(p[1])]),
    }),
  );
}

export class BadFragment extends Error {
  constructor(message, field) {
    super(message);
    this.code = 'BAD_FRAGMENT';
    this.field = field;
  }
}

/** ISO 字符串（Z）；整数毫秒时间戳也接受并转为 ISO。 */
export function asIso(value, field) {
  if (typeof value === 'number' && Number.isInteger(value)) return new Date(value).toISOString();
  if (typeof value !== 'string') throw new BadFragment(field + ' 必须是 ISO 时间字符串或整数毫秒');
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new BadFragment(field + ' 时间无法解析: ' + value);
  return new Date(ms).toISOString();
}

/** 结构校验 + 归一化（不合法一律拒绝、不落库）。 */
export function normalizeFragment(input) {
  if (!input || typeof input !== 'object') throw new BadFragment('片段必须是对象');
  const fNo = input.fragment_no;
  if (typeof fNo !== 'string' || !fNo.trim()) throw new BadFragment('fragment_no 必填', 'fragment_no');
  const interval_start = asIso(input.interval_start, 'interval_start');
  const interval_end = asIso(input.interval_end, 'interval_end');
  const s = Date.parse(interval_start);
  const e = Date.parse(interval_end);
  if (!(s < e)) throw new BadFragment('采样区间必须满足 start < end', 'interval_end');
  if (!Array.isArray(input.points) || input.points.length === 0) {
    throw new BadFragment('points 必须为非空数组', 'points');
  }
  const points = [];
  for (const raw of input.points) {
    if (!Array.isArray(raw) || raw.length !== 2) throw new BadFragment('每个采样点必须是 [时刻, 温度]');
    let t = raw[0];
    if (typeof t === 'string') {
      const parsed = Date.parse(t);
      if (!Number.isFinite(parsed)) throw new BadFragment('采样时刻无法解析: ' + raw[0]);
      t = parsed;
    }
    t = Number(t);
    if (!Number.isInteger(t)) throw new BadFragment('采样时刻必须是整数毫秒');
    points.push([t, numKey(raw[1])]);
  }
  points.sort((a, b) => a[0] - b[0]);
  for (let i = 1; i < points.length; i++) {
    if (points[i][0] === points[i - 1][0]) {
      throw new BadFragment('同一片段内存在重复采样时刻 ' + new Date(points[i][0]).toISOString());
    }
  }
  if (points[0][0] < s || points[points.length - 1][0] > e) {
    throw new BadFragment('采样点必须落在声明区间 [interval_start, interval_end] 之内');
  }
  return {
    fragment_no: fNo.trim(),
    interval_start,
    interval_end,
    points,
  };
}

export class MergeConflict extends Error {
  constructor(conflicts) {
    super('重叠区间逐点数据不一致，拒绝合并');
    this.code = 'POINT_CONFLICT';
    this.conflicts = conflicts;
  }
}

/**
 * 把一个新片段并入既有逐点序列。
 * @param existing [[tMs, tempC, fragmentRef], ...] 已按时间排序
 * @param frag     normalizeFragment 的结果
 * @param ref      新片段的引用标记（id 或 fragment_no）
 *
 * 重叠区间的处理：
 *   - 重合时刻温度相同 → 同一证据点收敛为一份（"逐点数据相同的部分合并"）；
 *   - 重合时刻温度不同 → 冲突，全部冲突点逐个返回，调用方必须整体拒绝，不落库、不静默跳过。
 */
export function mergePoints(existing, frag, ref) {
  const conflicts = [];
  const merged = [];
  let i = 0;
  let j = 0;
  while (i < existing.length || j < frag.points.length) {
    if (j >= frag.points.length) {
      merged.push(existing[i++]);
    } else if (i >= existing.length) {
      merged.push([...frag.points[j++], ref]);
    } else if (existing[i][0] < frag.points[j][0]) {
      merged.push(existing[i++]);
    } else if (existing[i][0] > frag.points[j][0]) {
      merged.push([...frag.points[j++], ref]);
    } else {
      const [t, a, refA] = existing[i];
      const [, b] = frag.points[j];
      if (numKey(a) !== numKey(b)) {
        conflicts.push({ t_ms: t, existing_temp_c: a, incoming_temp_c: b,
          existing_ref: refA, incoming_ref: ref });
      }
      merged.push(existing[i]); // 值相同：重叠部分合并为一个点
      i++;
      j++;
    }
  }
  if (conflicts.length) throw new MergeConflict(conflicts);
  return { merged };
}

/** 覆盖并集 sweep：相邻/重叠声明区间合并为覆盖段。 */
function unionCoverage(intervals) {
  const sorted = intervals
    .map(([s, e, ref]) => [s, e, [ref]])
    .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const union = [];
  for (const [s, e, refs] of sorted) {
    const last = union[union.length - 1];
    if (last && s <= last[1]) {
      if (e > last[1]) last[1] = e;
      last[2].push(...refs);
    } else {
      union.push([s, e, [...refs]]);
    }
  }
  return union;
}

/** [t1,t2] 之间（不含端点本身）是否存在真实缺口；存在则连续段必须被打断。 */
function hasGapBetween(t1, t2, gaps) {
  return gaps.some((g) => {
    // 与开区间 (t1,t2) 有交集（正长度）即算被缺口隔断；
    // 缺口端点恰好落在采样时刻上（边界相接）不算隔断该时刻。
    const s = Math.max(g.start_ms, t1);
    const e = Math.min(g.end_ms, t2);
    return e - s > 0;
  });
}

const round3 = (x) => Math.round(x * 1000) / 1000;

/**
 * 构造合并时间线并计算缺口、连续越界与建议。纯函数：同样的运单参数 + 片段集合
 * 永远推出同样结果（"可复算"），不依赖数据库与当前时间。
 *
 * gaps.type：
 *   leading  运单起点 → 首个覆盖段
 *   internal 相邻覆盖段之间的空洞
 *   trailing 末个覆盖段 → 运单终点
 *   before   片段声明起点早于运单区间（异常）
 *   beyond   片段声明终点晚于运单区间（异常，不静默截断）
 */
export function analyzeTimeline(waybill, rule, fragments) {
  const expStart = Date.parse(waybill.expected_start);
  const expEnd = Date.parse(waybill.expected_end);
  if (!(expStart < expEnd)) throw new BadFragment('运单采样区间非法');

  // 1) 声明区间并集 → 缺口（缺失区间绝不补点）
  const union = unionCoverage(fragments.map(
    (f) => [Date.parse(f.interval_start), Date.parse(f.interval_end), f.fragment_no]));
  const gaps = [];
  for (const [s, e] of union) {
    if (s < expStart) gaps.push({ start_ms: s, end_ms: Math.min(e, expStart), type: 'before' });
    if (e > expEnd) gaps.push({ start_ms: Math.max(s, expEnd), end_ms: e, type: 'beyond' });
  }
  let cursor = expStart;
  for (const [s0, e0] of union) {
    const s = Math.max(s0, expStart);
    const e = Math.min(e0, expEnd);
    if (s > cursor && cursor < expEnd) {
      gaps.push({ start_ms: cursor, end_ms: s, type: cursor === expStart ? 'leading' : 'internal' });
    }
    if (e > cursor) cursor = e;
  }
  if (cursor < expEnd) gaps.push({ start_ms: cursor, end_ms: expEnd, type: 'trailing' });
  gaps.sort((a, b) => a.start_ms - b.start_ms);

  // 2) 逐点合并与跨片段冲突（按片段号确定顺序，结果与到达顺序无关）
  let points = [];
  const pointConflicts = [];
  for (const f of fragments.slice().sort((a, b) => a.fragment_no.localeCompare(b.fragment_no))) {
    try {
      points = mergePoints(points, f, f.fragment_no).merged;
    } catch (e) {
      if (e instanceof MergeConflict) pointConflicts.push(...e.conflicts);
      else throw e;
    }
  }

  // 3) 逐点判定：实测读数 + 校准偏移后与允许区间比较
  const lo = rule.temp_min_c;
  const hi = rule.temp_max_c;
  const offset = rule.calib_offset_c || 0;
  const judged = points.map(([t, raw]) => {
    const adjusted = round3(raw + offset);
    return { t_ms: t, raw_temp_c: raw, adjusted_temp_c: adjusted,
      state: adjusted < lo || adjusted > hi ? 'out' : 'in',
      iso: new Date(t).toISOString() };
  });

  // 4) 连续越界段：仅在覆盖不间断的相邻越界点之间累计；缺口（含 leading/trailing/
  //    internal）打断连续段。时长取首末实际采样时刻之差。
  const runs = [];
  let run = null;
  let prev = null;
  for (const p of judged) {
    const continues = run && prev && prev.state === 'out' &&
      !hasGapBetween(prev.t_ms, p.t_ms, gaps);
    if (p.state === 'out') {
      if (!continues) {
        run = { start_ms: p.t_ms, end_ms: p.t_ms, points: [p] };
        runs.push(run);
      } else {
        run.end_ms = p.t_ms;
        run.points.push(p);
      }
    } else {
      run = null;
    }
    prev = p;
  }
  const events = runs.map((r) => {
    const temps = r.points.map((p) => p.adjusted_temp_c);
    const extreme = temps.reduce((m, v) =>
      Math.abs(v - (lo + hi) / 2) > Math.abs(m - (lo + hi) / 2) ? v : m, temps[0]);
    const duration_sec = (r.end_ms - r.start_ms) / 1000;
    return {
      start_ms: r.start_ms, end_ms: r.end_ms,
      start_iso: new Date(r.start_ms).toISOString(), end_iso: new Date(r.end_ms).toISOString(),
      duration_sec, n_points: r.points.length, extreme_temp_c: extreme,
      breach: duration_sec > rule.max_breach_sec,
    };
  });
  const breaches = events.filter((e) => e.breach);

  // 5) 完整性：任何缺口/冲突/越界点之外的异常都使时间线不可判定
  const complete = gaps.length === 0 && pointConflicts.length === 0 && points.length > 0;

  // 6) 建议仅供质量管理员参考；时间线不完整时不产生合格/隔离建议
  const suggested = !complete ? null : (breaches.length ? 'quarantine' : 'accept');

  return {
    expected_start_ms: expStart,
    expected_end_ms: expEnd,
    n_points: points.length,
    points: judged,
    coverage: union.map(([s, e, refs]) => ({
      start_ms: s, end_ms: e,
      start_iso: new Date(s).toISOString(), end_iso: new Date(e).toISOString(),
      fragments: refs,
    })),
    gaps: gaps.map((g) => ({ ...g, start_iso: new Date(g.start_ms).toISOString(),
      end_iso: new Date(g.end_ms).toISOString(), duration_sec: (g.end_ms - g.start_ms) / 1000 })),
    point_conflicts: pointConflicts,
    events,
    n_breaches: breaches.length,
    complete,
    suggested_disposition: suggested,
    rule_applied: { temp_min_c: lo, temp_max_c: hi, calib_offset_c: offset,
      max_breach_sec: rule.max_breach_sec },
  };
}

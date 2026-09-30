/**
 * 运单完整时间线明细渲染（设备页与质量页共用）。
 * 纯 DOM + 内联 SVG，无第三方图表库。红色斜纹带=缺口，红带=越界窗口，
 * 绿底带=允许温度区间，折线按"加偏移后的判定温度"着色。
 */
import { esc, fmt } from './api.js';

function gapLabel(t) {
  return ({ leading: '前置缺口', internal: '中间缺口', trailing: '尾部缺口',
    before: '早于采样区间', beyond: '超出采样区间' })[t] || t;
}

function timelineSvg(a) {
  const W = 1080;
  const H = 150;
  const padL = 46;
  const padR = 12;
  const padT = 12;
  const padB = 22;
  const t0 = a.expected_start_ms;
  const t1 = a.expected_end_ms;
  const X = (ms) => padL + ((ms - t0) / (t1 - t0)) * (W - padL - padR);
  const temps = a.points;
  const minT = Math.min(a.rule_applied.temp_min_c, ...temps.map((p) => p.adjusted_temp_c));
  const maxT = Math.max(a.rule_applied.temp_max_c, ...temps.map((p) => p.adjusted_temp_c));
  const span = Math.max(maxT - minT, 1);
  const Y = (v) => padT + (1 - (v - minT) / span) * (H - padT - padB);
  const lo = a.rule_applied.temp_min_c;
  const hi = a.rule_applied.temp_max_c;

  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">`;
  // 允许区间带
  s += `<rect class="allowed-band" x="${padL}" y="${Y(hi)}" width="${W - padL - padR}" height="${Y(lo) - Y(hi)}"/>`;
  // 缺口带
  for (const g of a.gaps) {
    const x1 = X(Math.max(g.start_ms, t0));
    const x2 = X(Math.min(g.end_ms, t1));
    if (x2 > x1) s += `<rect class="gap-band" x="${x1}" y="${padT}" width="${x2 - x1}" height="${H - padT - padB}"/>`;
  }
  // 越界窗口带
  for (const e of a.events) {
    if (!e.breach) continue;
    const x1 = X(e.start_ms);
    const x2 = X(e.end_ms);
    s += `<rect class="breach-band" x="${x1}" y="${padT}" width="${Math.max(x2 - x1, 2)}" height="${H - padT - padB}"/>`;
  }
  // 区间边界
  s += `<line x1="${padL}" y1="${padT}" x2="${padL}" y2="${H - padB}" stroke="#94a3b8"/>`;
  s += `<line x1="${W - padR}" y1="${padT}" x2="${W - padR}" y2="${H - padB}" stroke="#94a3b8"/>`;
  s += `<text x="${padL + 4}" y="${Y(hi) - 3}" class="muted" font-size="10">${hi}℃</text>`;
  s += `<text x="${padL + 4}" y="${Y(lo) + 11}" class="muted" font-size="10">${lo}℃</text>`;
  // 折线（连续越界段红色，其余绿色）
  const breachMs = new Set();
  for (const e of a.events) {
    if (!e.breach) continue;
    temps.forEach((p) => { if (p.t_ms >= e.start_ms && p.t_ms <= e.end_ms && p.state === 'out') breachMs.add(p.t_ms); });
  }
  const seg = [];
  let cur = [];
  let curOut = null;
  for (const p of temps) {
    const out = breachMs.has(p.t_ms);
    if (curOut === null || out === curOut) {
      cur.push(p);
    } else {
      seg.push({ out: curOut, pts: cur });
      cur = [cur[cur.length - 1], p];
    }
    curOut = out;
  }
  if (cur.length) seg.push({ out: curOut, pts: cur });
  for (const g of seg) {
    const d = g.pts.map((p, i) => `${i ? 'L' : 'M'}${X(p.t_ms)},${Y(p.adjusted_temp_c)}`).join('');
    s += `<path class="${g.out ? 'line-out' : 'line-in'}" d="${d}"/>`;
  }
  for (const p of temps) {
    s += `<circle class="${breachMs.has(p.t_ms) ? 'dot-out' : 'dot-in'}" cx="${X(p.t_ms)}" cy="${Y(p.adjusted_temp_c)}" r="2.2"/>`;
  }
  s += `<text x="${padL}" y="${H - 6}" font-size="10" class="muted">${new Date(t0).toISOString().slice(11, 16)}Z</text>`;
  s += `<text x="${W - padR - 44}" y="${H - 6}" font-size="10" class="muted">${new Date(t1).toISOString().slice(11, 16)}Z</text>`;
  s += '</svg>';
  return s;
}

export function renderDetail(root, d, opts = {}) {
  const a = d.analysis;
  let html = `
  <div class="grid2">
    <div>
      <dl class="kv">
        <dt>中性运单号</dt><dd class="mono">${esc(d.waybill_no)}</dd>
        <dt>传感器编号</dt><dd class="mono">${esc(d.sensor_no)}</dd>
        <dt>采样区间</dt><dd class="mono">${fmt(d.expected_start)} → ${fmt(d.expected_end)}</dd>
        <dt>创建</dt><dd>${esc(d.created_by)} · ${fmt(d.created_at)}</dd>
      </dl>
      <h4>规则快照（创建时固化，之后改版不影响本单）</h4>
      <dl class="kv">
        <dt>规则版本</dt><dd>${esc(d.rule_snapshot.version)}</dd>
        <dt>允许区间</dt><dd>[${d.rule_snapshot.temp_min_c}, ${d.rule_snapshot.temp_max_c}] ℃</dd>
        <dt>连续越界限值</dt><dd>${d.rule_snapshot.max_breach_sec} 秒</dd>
        <dt>校准偏移</dt><dd>${d.rule_snapshot.calib_offset_c} ℃（判定前加到实测读数）</dd>
      </dl>
    </div>
    <div>
      <h4>计算明细</h4>
      <dl class="kv">
        <dt>合并点数</dt><dd>${a.n_points}（重叠且相同的点已收敛为一个）</dd>
        <dt>缺口</dt><dd>${a.gaps.length === 0 ? '<span class="tag tag-ok">时间线完整</span>' :
          a.gaps.map((g) => `<span class="tag tag-gap">${gapLabel(g.type)} ${g.duration_sec}s</span>`).join(' ')}</dd>
        <dt>逐点冲突</dt><dd>${a.point_conflicts.length === 0 ? '<span class="tag tag-ok">无</span>' :
          `<span class="tag tag-breach">${a.point_conflicts.length} 处</span>`}</dd>
        <dt>越界事件</dt><dd>${a.events.length === 0 ? '<span class="tag tag-ok">无</span>' :
          a.events.map((e) => `<span class="tag ${e.breach ? 'tag-breach' : 'tag-info'}">${e.duration_sec}s${e.breach ? ' 超限' : ''} 峰值${e.extreme_temp_c}℃</span>`).join(' ')}</dd>
        <dt>系统建议</dt><dd>${a.complete
          ? `<span class="tag ${a.suggested_disposition === 'accept' ? 'tag-ok' : 'tag-breach'}">${a.suggested_disposition === 'accept' ? '建议可接收' : '建议隔离'}</span>`
          : '<span class="tag tag-gap">时间线不完整：只能待补传，不出建议</span>'}</dd>
      </dl>
    </div>
  </div>
  <h4>合并时间线（绿带=允许区间；红斜纹=缺口；红带=超限窗口；红点=越界采样）</h4>
  ${a.points.length ? timelineSvg(a) : '<p class="muted">尚无采样点。</p>'}`;

  // 缺口明细
  if (a.gaps.length) {
    html += `<details><summary>缺口明细（${a.gaps.length} 处；缺失区间绝不按正常温度补齐）</summary><table>
      <thead><tr><th>类型</th><th>起</th><th>止</th><th>时长(秒)</th></tr></thead><tbody>
      ${a.gaps.map((g) => `<tr><td>${gapLabel(g.type)}</td><td class="mono">${fmt(g.start_iso)}</td>
        <td class="mono">${fmt(g.end_iso)}</td><td>${g.duration_sec}</td></tr>`).join('')}
      </tbody></table></details>`;
  }
  if (a.point_conflicts.length) {
    html += `<details open><summary>逐点冲突明细（${a.point_conflicts.length} 处）</summary><table>
      <thead><tr><th>时刻</th><th>既有温度</th><th>新传温度</th><th>既有片段</th><th>新传片段</th></tr></thead><tbody>
      ${a.point_conflicts.map((c) => `<tr><td class="mono">${fmt(new Date(c.t_ms).toISOString())}</td>
        <td>${c.existing_temp_c}℃</td><td>${c.incoming_temp_c}℃</td>
        <td class="mono">${esc(c.existing_ref)}</td><td class="mono">${esc(c.incoming_ref)}</td></tr>`).join('')}
      </tbody></table></details>`;
  }
  if (a.events.length) {
    html += `<details><summary>连续越界事件（${a.events.length} 段；按实际采样时刻计算，缺口打断连续段）</summary><table>
      <thead><tr><th>起</th><th>止</th><th>连续时长(秒)</th><th>点数</th><th>极端温度(加偏移)</th><th>判定</th></tr></thead><tbody>
      ${a.events.map((e) => `<tr><td class="mono">${fmt(e.start_iso)}</td><td class="mono">${fmt(e.end_iso)}</td>
        <td>${e.duration_sec}</td><td>${e.n_points}</td><td>${e.extreme_temp_c}℃</td>
        <td>${e.breach ? '<span class="tag tag-breach">超阈值</span>' : '<span class="tag tag-info">未超阈值</span>'}</td></tr>`).join('')}
      </tbody></table></details>`;
  }

  // 原始片段（质量页/设备页都可看；到达顺序与时间顺序解耦展示）
  if (d.fragments) {
    html += `<details><summary>原始片段（${d.fragments.length} 个，按到达顺序；含正文哈希）</summary>
      <div class="scroll"><table><thead><tr><th>到达序</th><th>片段标识</th><th>声明区间</th><th>点数</th>
      <th>上传者</th><th>上传时间</th><th>内容哈希</th></tr></thead><tbody>
      ${d.fragments.map((f) => `<tr><td>${f.seq_no}</td><td class="mono">${esc(f.fragment_no)}</td>
        <td class="mono">${fmt(f.interval_start)} → ${fmt(f.interval_end)}</td><td>${f.n_points}</td>
        <td>${esc(f.uploaded_by)}</td><td>${fmt(f.uploaded_at)}</td>
        <td class="mono" style="word-break:break-all;max-width:180px">${esc(f.content_hash)}</td></tr>`).join('')}
      </tbody></table></div></details>`;
  }

  // 决定版本链（设备页只能看到状态，不展示处置操作）
  if (d.decision_versions?.length) {
    html += `<h4>处置版本（append-only，撤销保留前后版本）</h4><div class="scroll"><table>
      <thead><tr><th>版本</th><th>处置</th><th>理由</th><th>决定人</th><th>时间</th><th>取代</th></tr></thead><tbody>
      ${d.decision_versions.map((v) => `<tr><td>r${v.revision}</td>
        <td><span class="badge b-${v.disposition}">${v.disposition === 'accept' ? '可接收' : '隔离'}</span></td>
        <td>${esc(v.reason)}</td><td>${esc(v.decided_by)}</td><td>${fmt(v.decided_at)}</td>
        <td>${v.revokes_revision ? 'r' + v.revokes_revision : '—'}</td></tr>`).join('')}
      </tbody></table></div>`;
  }
  if (d.pending_revocation) {
    html += `<p><span class="tag tag-gap">撤销复核待处理</span>
      ${esc(d.pending_revocation.requested_by)} 针对 r${d.pending_revocation.revision} 提出：
      ${esc(d.pending_revocation.reason)}（${fmt(d.pending_revocation.requested_at)}）<br>
      <span class="muted">必须由提出者之外的另一名质量管理员复核。</span></p>`;
  }
  if (d.credentials?.length) {
    html += `<h4>处置凭据</h4><table><thead><tr><th>凭据号</th><th>版本</th><th>签发人</th><th>时间</th></tr></thead><tbody>
      ${d.credentials.map((c) => `<tr><td class="mono">${esc(c.cred_no)}</td><td>r${c.revision}</td>
        <td>${esc(c.issued_by)}</td><td>${fmt(c.issued_at)}</td></tr>`).join('')}</tbody></table>`;
  }
  root.innerHTML = html;
}

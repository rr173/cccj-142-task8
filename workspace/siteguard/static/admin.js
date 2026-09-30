/* 安全管理台：注册码签发、设备/证书视图、轮换授权、隔离、本站点记录。 */
const $ = (id) => document.getElementById(id);
const token = SG.getToken();
const id = SG.identity();
if (!token || !id || id.role !== 'admin') location.href = '/';
$('who').textContent = `${id.display} · ${id.site_code}`;

$('logoutBtn').onclick = async () => {
  try { await SG.api('POST', '/api/logout', {}, token); } catch { /* 忽略 */ }
  SG.clearSession();
  location.href = '/';
};

/* ------------------------------------------------------------ 注册码 */
$('issueCodeBtn').onclick = async () => {
  const roles = [...document.querySelectorAll('#rolePick input:checked')].map((x) => x.value);
  try {
    const r = await SG.api('POST', '/api/admin/register-codes', {
      roles, minutes: Number($('codeMinutes').value),
    }, token);
    SG.flash($('codeMsg'), 'ok',
      `注册码 ${r.code_ref} 已签发（仅本次显示明文，用后即废）`);
    $('newCode').style.display = 'block';
    $('newCode').textContent =
      `注册码（交给现场，仅此时出现一次）：\n${r.code}\n\n角色：${r.roles.join(' / ')}\n有效期：${r.minutes} 分钟`;
    loadCodesHint();
  } catch (e) {
    SG.flash($('codeMsg'), 'err', `[${e.code}] ${e.message}`);
  }
};

async function loadCodesHint() {
  // 列表不再回显明文码，仅在控制台/视图展示使用状态（中性）
  const rows = await SG.api('GET', '/api/admin/register-codes', undefined, token);
  console.info('注册码使用状态（不含明文）', rows);
}

/* ------------------------------------------------------------ 设备表 */
function statusTag(status) {
  if (status === 'active') return '<span class="tag ok">active 可落款</span>';
  if (status === 'rotated') return '<span class="tag warn">rotated 仅历史</span>';
  return '<span class="tag err">quarantined 已隔离</span>';
}

async function loadDevices() {
  const devs = await SG.api('GET', '/api/admin/devices', undefined, token);
  if (!devs.length) {
    $('devicesBox').innerHTML = '<p class="muted">本站点尚无登记设备。</p>';
    return;
  }
  $('devicesBox').innerHTML = '<table><thead><tr>' +
    '<th>设备编号</th><th>标识</th><th>状态</th><th>证书代次</th><th>操作</th>' +
    '</tr></thead><tbody>' +
    devs.map((d) => {
      const certs = d.certificates.map((c) =>
        `<div style="margin-bottom:4px">${statusTag(c.status)}
          <span class="mono">${c.cert_id}</span> 第 ${c.gen} 代
          <span class="muted">[${c.roles.join('/')}] 至 ${c.not_after}</span></div>`).join('');
      const btns = d.quarantined
        ? `<span class="tag err">已隔离：${SG.escapeHtml(d.quarantined_reason || '')}</span>`
        : `<button class="danger" data-q="${d.device_id}">隔离设备</button>
           <button class="secondary" data-r="${d.current_cert_id}" data-d="${d.device_id}">颁发轮换授权</button>`;
      return `<tr>
        <td class="mono">${d.device_id}</td>
        <td>${SG.escapeHtml(d.label)}</td>
        <td>${d.quarantined ? '<span class="tag err">已隔离</span>' : '<span class="tag ok">在用</span>'}</td>
        <td>${certs}</td>
        <td>${btns}</td>
      </tr>`;
    }).join('') + '</tbody></table>';

  document.querySelectorAll('button[data-q]').forEach((b) => {
    b.onclick = async () => {
      const reason = prompt('隔离原因（必填，将随审计留痕）：');
      if (!reason) return;
      try {
        const r = await SG.api('POST', '/api/admin/devices/quarantine',
          { device_id: b.dataset.q, reason }, token);
        alert(r.idempotent ? '设备此前已隔离（幂等）' : `设备 ${r.device_id} 已即时隔离`);
        loadDevices();
      } catch (e) { alert(`[${e.code}] ${e.message}`); }
    };
  });
  document.querySelectorAll('button[data-r]').forEach((b) => {
    b.onclick = async () => {
      try {
        const r = await SG.api('POST', '/api/admin/certificates/rotate',
          { cert_id: b.dataset.r }, token);
        prompt('轮换授权码（短时一次性，交终端完成密钥轮换）：', r.rotation_nonce);
      } catch (e) { alert(`[${e.code}] ${e.message}`); }
    };
  });
}

$('refreshDevBtn').onclick = loadDevices;

/* ------------------------------------------------------------ 记录表 */
async function loadRecords() {
  const recs = await SG.api('GET', '/api/admin/records', undefined, token);
  if (!recs.length) {
    $('recordsBox').innerHTML = '<p class="muted">暂无落款记录。</p>';
    return;
  }
  $('recordsBox').innerHTML = '<table><thead><tr>' +
    '<th>记录号</th><th>设备</th><th>证书</th><th>动作</th><th>会话</th><th>角色</th>' +
    '<th>正文摘要</th><th>结果摘要</th><th>时刻</th></tr></thead><tbody>' +
    recs.map((r) => `<tr>
      <td class="mono">${r.record_id}</td>
      <td class="mono">${r.device_id}</td>
      <td class="mono">${r.cert_id}</td>
      <td>${r.action}</td><td class="mono">${r.session_id}</td><td>${r.role}</td>
      <td class="mono">${r.body_digest.slice(0, 16)}…</td>
      <td class="mono">${r.result_digest.slice(0, 16)}…</td>
      <td>${r.at}</td></tr>`).join('') + '</tbody></table>';
}
$('refreshRecBtn').onclick = loadRecords;

loadDevices();
loadRecords();

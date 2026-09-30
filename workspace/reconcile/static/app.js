const App = {
  token: localStorage.getItem('recon_token') || '',
  user: null,
  cycle: 'CYCLE-2026-09',

  async api(path, opts={}) {
    const res = await fetch(path, {
      method: opts.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...(this.token ? {Authorization: `Bearer ${this.token}`} : {})
      },
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`${data.error || res.status}: ${data.message || ''}`);
    return data;
  },

  async login() {
    try {
      const data = await this.api('/api/auth/login', {method:'POST', body:{
        login: document.getElementById('login').value,
        password: document.getElementById('password').value
      }});
      this.token = data.token; this.user = data.user;
      localStorage.setItem('recon_token', this.token);
      this.show();
    } catch (e) { document.getElementById('error').textContent = e.message; }
  },

  logout() {
    this.token=''; this.user=null; localStorage.removeItem('recon_token'); location.reload();
  },

  async show() {
    if (!this.token) return;
    try { this.user = (await this.api('/api/me')).user; }
    catch { return this.logout(); }
    document.getElementById('login').hidden = true;
    document.getElementById('app').hidden = false;
    document.getElementById('who').innerHTML =
      `${this.user.name}（${this.user.role}${this.user.inst_id?' / '+this.user.inst_id:''}） <button class="secondary" onclick="App.logout()">退出</button>`;
    document.querySelectorAll('.tabs button').forEach(b => {
      b.hidden = (b.dataset.view === 'compliance' && this.user.role !== 'compliance')
        || (b.dataset.view === 'site' && this.user.role !== 'site')
        || (b.dataset.view === 'participant' && this.user.role !== 'participant');
    });
    const initial = {compliance:'compliance', site:'site', participant:'participant'}[this.user.role];
    await this.tab(initial);
    document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => this.tab(b.dataset.view));
  },

  async tab(name) {
    document.querySelectorAll('.page').forEach(p => p.hidden = p.id !== name);
    document.querySelectorAll('.tabs button').forEach(b => b.className = b.dataset.view===name?'':'secondary');
    if (name === 'compliance') await this.compliance();
    if (name === 'site') await this.site();
    if (name === 'participant') await this.participant();
  },

  esc(v) { return String(v ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); },
  rows(items) {
    return items.map(x => `<tr><td>${x.id}</td><td>${x.subject_id}<br><small>${x.inst_id}</small></td>
      <td>${x.op}<br><small>${x.purpose}</small></td><td>${x.occurred_at}</td><td><code>${x.basis_version}</code></td>
      <td><span class="pill ${x.result}">${x.result}</span><br><small>${x.reason}</small></td>
      <td>${x.latest_disposition ? `<span class="pill ${x.latest_disposition.status}">${x.latest_disposition.status}</span><br>${this.esc(x.latest_disposition.original.decision)}: ${this.esc(x.latest_disposition.original.reason)}` : ''}</td></tr>`).join('');
  },

  async compliance() {
    const el = document.getElementById('compliance');
    el.innerHTML = `
      <div class="card"><h2>周期 ${this.cycle}</h2>
        <div class="row"><label>周期 <input id="cycle" value="${this.cycle}"></label>
        <button onclick="App.recompute(false)">重新计算/返回已有版本</button>
        <button class="danger" onclick="App.recompute(true)">演练：发布后退出</button></div>
        <p class="hint">同输入重算返回同一版本；后补材料只会形成新版本，不能追认发生时无资格的行为。</p>
      </div>
      <div class="card"><h2>最新版本差异</h2><div id="version"></div></div>
      <div class="grid"><div class="card"><h2>待复核处置</h2><div id="reviews"></div></div>
      <div class="card"><h2>处置记录</h2><div id="dispositions"></div></div></div>`;
    document.getElementById('cycle').onchange = e => this.cycle = e.target.value;
    await this.loadCompliance();
  },

  async loadCompliance() {
    try {
      const v = await this.api(`/api/cycles/${encodeURIComponent(this.cycle)}/versions/latest`);
      document.getElementById('version').innerHTML =
        `<p>版本 v${v.version}，发布于 ${v.published_at}；${JSON.stringify(v.counts)}</p>
         <table><tr><th>#</th><th>对象</th><th>操作/用途</th><th>发生时刻</th><th>依据版本</th><th>结果</th><th>处置</th></tr>${this.rows(v.items)}</table>
         <div id="actions"></div>`;
      document.getElementById('actions').innerHTML = v.items.filter(x=>x.result!=='explained').map(x => `
        <div class="card"><b>#${x.id} ${x.claim_id} / ${x.result}</b>
          <div class="row"><label>采用快照<input id="snap-${x.id}" value="${x.matched_snapshot_id || x.detail.input_snapshot_id || ''}"></label>
          <label>决定<select id="dec-${x.id}"><option>accepted</option><option>escalated</option><option>waived</option></select></label>
          <label>理由<input id="why-${x.id}" placeholder="必须填写理由"></label>
          <button onclick="App.dispose(${x.id})">记录处置</button></div></div>`).join('');
      const [reviews, dis] = await Promise.all([
        this.api('/api/dispositions?status=needs_review'),
        this.api('/api/dispositions')
      ]);
      document.getElementById('reviews').innerHTML = reviews.length ? reviews.map(this.dispo).join('') : '<p>无</p>';
      document.getElementById('dispositions').innerHTML = dis.length ? dis.map(this.dispo).join('') : '<p>无</p>';
    } catch(e) { document.getElementById('version').innerHTML = `<p class="error">${e.message}</p>`; }
  },

  dispo(d) { return `<p><span class="pill ${d.status}">${d.status}</span> #${d.id} item#${d.item_id}<br>
    原判断：${d.original.decision} / ${App.esc(d.original.reason)}<br><small>原快照 ${d.original.snapshot_id}</small></p>`; },

  async recompute(crash) {
    this.cycle = document.getElementById('cycle').value;
    try { await this.api(`/api/cycles/${encodeURIComponent(this.cycle)}/recompute`, {method:'POST', body:{crash_after_publish:crash}}); }
    catch(e) { if (!crash) alert(e.message); }
    if (crash) setTimeout(()=>location.reload(), 800); else await this.loadCompliance();
  },

  async dispose(id) {
    await this.api(`/api/items/${id}/disposition`, {method:'POST', body:{
      adopted_snapshot_id: Number(document.getElementById(`snap-${id}`).value),
      decision: document.getElementById(`dec-${id}`).value,
      reason: document.getElementById(`why-${id}`).value
    }});
    await this.loadCompliance();
  },

  async site() {
    const el = document.getElementById('site');
    el.innerHTML = `<div class="card"><h2>本站差异</h2><label>周期<input id="scycle" value="${this.cycle}"></label>
      <button onclick="App.loadSite()">查看本站</button></div><div class="card" id="sview"></div>`;
    document.getElementById('scycle').onchange = e => this.cycle = e.target.value;
    await this.loadSite();
  },
  async loadSite() {
    try {
      const data = await this.api(`/api/cycles/${encodeURIComponent(this.cycle)}/site-items`);
      document.getElementById('sview').innerHTML = `<p>版本 v${data.version.version}，机构 ${data.site_id}</p>
        <table><tr><th>#</th><th>对象</th><th>操作</th><th>时刻</th><th>结果</th><th>处置</th></tr>${this.rows(data.items)}</table>`;
    } catch(e) { document.getElementById('sview').innerHTML = `<p class="error">${e.message}</p>`; }
  },

  async participant() {
    const el = document.getElementById('participant');
    const data = await this.api('/api/my/executions');
    el.innerHTML = `<div class="card"><h2>我相关的执行依据</h2><p>对象 ${data.subject_id}</p>
      <table><tr><th>周期/版本</th><th>操作/用途</th><th>发生时刻</th><th>请求依据</th><th>时间点裁定</th></tr>
      ${data.items.map(x=>`<tr><td>${x.cycle_id}<br>v${x.published_version}</td><td>${x.op}<br>${x.purpose}</td>
      <td>${x.occurred_at}</td><td><code>${x.basis_version}</code></td>
      <td><span class="pill ${x.result}">${x.result}</span><br><small>${x.reason}</small></td></tr>`).join('')}
      </table></div>`;
  }
};
if (App.token) App.show();

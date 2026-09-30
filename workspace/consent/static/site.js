boot("site", "app", async main => {
  let current = null; // 当前选中的本机构对象
  main.innerHTML = `
  <div class="card">
    <h2>本机构办理对象</h2>
    <table><thead><tr><th>选择</th><th>对象</th><th>首选语种</th><th>人群条件</th></tr></thead>
      <tbody id="subjRows"></tbody></table>
  </div>

  <div id="workArea"></div>`;

  const subjects = await api("GET", "/api/subjects");
  document.getElementById("subjRows").innerHTML = subjects.map(s => `
    <tr><td><button class="small" data-pick="${s.id}">办理</button></td>
      <td>${esc(s.name)} <span class="muted">${esc(s.id)}</span></td>
      <td>${esc(s.language)}</td>
      <td><code>${esc(JSON.stringify(s.conditions))}</code></td></tr>`).join("");
  document.querySelectorAll("[data-pick]").forEach(b => b.onclick = () => loadSubject(b.dataset.pick));

  async function loadSubject(sid) {
    current = await api("GET", `/api/subjects/${sid}`);
    const area = document.getElementById("workArea");
    area.innerHTML = `
    <div class="card">
      <h2>可开单材料 — ${esc(current.name)}（只显示 机构/首选语种/人群条件 全部吻合的现行版）</h2>
      <div id="eligMsg"></div>
      <table><thead><tr><th>材料族</th><th>版本</th><th>正文</th><th>必签角色</th>
        <th>允许操作</th><th>封存指纹</th><th></th></tr></thead><tbody id="eligRows"></tbody></table>
    </div>
    <div class="card">
      <h2>办理进度与具体缺项</h2>
      <div id="sessList"></div>
    </div>
    <div class="card">
      <h2>操作前许可查询 / 执行确认（采血·影像·用药·留存再利用）</h2>
      <div class="row">
        <div><label>操作</label><select id="opSel">
          ${Object.entries(OP_LABELS).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}
        </select></div>
        <div><label>用途（sample_reuse 的新增用途必填）</label><input id="purpose" placeholder="如 biomarker-study-2026"></div>
        <div style="flex:0 0 auto"><label>&nbsp;</label><button id="btnCheck">查询许可</button>
        <button id="btnExec" class="ghost">执行确认</button></div>
      </div>
      <div id="checkMsg"></div>
    </div>
    <div class="card">
      <h2>执行/拒绝记录（撤销前已形成的记录保留）</h2>
      <table><thead><tr><th>#</th><th>时刻(UTC)</th><th>操作</th><th>用途</th><th>结果</th>
        <th>依据版本</th><th>原因</th></tr></thead><tbody id="execRows"></tbody></table>
    </div>`;
    await refreshAll();
    document.getElementById("btnCheck").onclick = () => check(false);
    document.getElementById("btnExec").onclick = () => check(true);
  }

  async function refreshAll() {
    const [elig, sessions, execs] = await Promise.all([
      api("GET", `/api/subjects/${current.id}/eligibility`),
      api("GET", `/api/subjects/${current.id}/sessions`),
      api("GET", `/api/subjects/${current.id}/executions`),
    ]);
    document.getElementById("eligRows").innerHTML = elig.map(m => `
      <tr>
        <td>${esc(m.family)}</td><td>v${m.version}</td>
        <td><details><summary>${esc(m.body.slice(0, 24))}…</summary><pre>${esc(m.body)}</pre></details></td>
        <td>${roleList(m.roles)}</td><td>${opList(m.scope)}</td>
        <td class="hash">${esc(m.body_hash.slice(0, 16))}…</td>
        <td>${m.eligible
          ? `<button class="small" data-start="${m.id}">开单</button>`
          : `<span class="pill no">${esc(m.reject_reasons.join(","))}</span>`}</td>
      </tr>`).join("");
    document.querySelectorAll("[data-start]").forEach(b => b.onclick = async () => {
      try {
        await TRUST.send("POST", `/api/subjects/${current.id}/sessions`, { material_id: Number(b.dataset.start) },
          { action: "session.start", resource: current.id });
        await refreshAll();
      } catch (e) { alert(e.message); }
    });

    document.getElementById("sessList").innerHTML = sessions.length ? sessions.map(s => `
      <div style="border-bottom:1px solid #edf0f3;padding:10px 0">
        <b>${esc(s.material.family)} v${s.material.version}</b> ${pill(s.status)}
        <span class="muted">会话 ${esc(s.id)} · 开单 ${esc(s.created_at)} · 指纹 ${esc(s.material.body_hash.slice(0, 12))}…</span>
        <table style="margin-top:6px"><tr>
          ${s.slots.map(sl => `<td style="border:0">${esc(sl.role_label)}：${
            sl.filled ? `<span class="pill ok">${esc(sl.signer_name)} @ ${esc(sl.signed_at)}</span>`
                      : `<span class="pill no miss">缺</span>`}</td>`).join("")}
        </tr></table>
        ${s.status === "open"
          ? `<div style="margin-top:6px">
             <button class="small ghost" data-sign="${s.id}">我（现场负责人）签署</button>
             <button class="small ghost" data-tokens="${s.id}">生成见证者签名链接</button>
             <span class="muted">参与人请用本人账号在自助页签署</span></div>
             <div id="tk-${s.id}"></div>`
          : s.status === "completed"
            ? `<div class="muted" style="margin-top:4px">许可已生成；许可操作以该封存版本为依据。</div>`
            : `<div class="muted" style="margin-top:4px">${
                s.status === "blocked" ? "材料停用导致冻结，须用新版重新开单，不会降级到旧版。" : "参与人已撤销。"}</div>`}
      </div>`).join("") : `<p class="muted">暂无会话。</p>`;

    document.querySelectorAll("[data-sign]").forEach(b => b.onclick = async () => {
      try {
        await TRUST.send("POST", `/api/sessions/${b.dataset.sign}/sign`, { role: "site_owner" },
          { action: "sign", resource: b.dataset.sign, role: "site_owner" });
        await refreshAll();
      } catch (e) { alert(e.message); }
    });
    document.querySelectorAll("[data-tokens]").forEach(b => b.onclick = async () => {
      try {
        const r = await TRUST.send("POST", `/api/sessions/${b.dataset.tokens}/tokens`, {},
          { action: "witness.tokens", resource: b.dataset.tokens });
        const links = Object.entries(r.tokens).map(([role, tk]) =>
          `<div>${ROLE_LABELS[role]} 一次性签名链接：
            <a href="/witness.html?session=${r.session_id}&role=${role}&token=${tk}&enrollment=${r.enrollment_codes[role]}" target="_blank">
            /witness.html?session=${r.session_id}&role=${role}&token=…&enrollment=…</a>
            <div class="hash">${tk} / ${r.enrollment_codes[role]}</div></div>`).join("");
        document.getElementById("tk-" + b.dataset.tokens).innerHTML =
          `<div class="okbox">${links || "暂无待签角色"}</div>`;
      } catch (e) { alert(e.message); }
    });

    document.getElementById("execRows").innerHTML = execs.map(e => `
      <tr><td>${e.id}</td><td class="muted">${esc(e.created_at)}</td>
        <td>${esc(OP_LABELS[e.op] || e.op)}</td><td>${esc(e.purpose || "")}</td>
        <td>${e.result === "performed"
          ? '<span class="pill ok">已执行</span>' : '<span class="pill no">已拒绝</span>'}</td>
        <td>${e.material_family ? esc(e.material_family) + " v" + e.version : "—"}</td>
        <td>${esc(e.reason || "")}</td></tr>`).join("");
  }

  async function check(doExecute) {
    const box = document.getElementById("checkMsg");
    const op = document.getElementById("opSel").value;
    const purpose = document.getElementById("purpose").value || null;
    try {
      if (doExecute) {
        const r = await TRUST.send("POST", `/api/subjects/${current.id}/execute`,
          { op, purpose }, { action: "execute", resource: current.id });
        box.innerHTML = r.result === "performed"
          ? `<div class="okbox">✅ 已执行确认（#${r.execution_id}），依据 ${esc(r.basis.family)} v${r.basis.version}
             <div class="hash">${esc(r.basis.body_hash.slice(0, 20))}…</div>获准范围：${opList(r.scope)}</div>`
          : `<div class="err">⛔ 执行被拒绝：<b>${esc(r.reason)}</b><pre>${esc(JSON.stringify(r.missing, null, 2))}</pre></div>`;
      } else {
        const r = await api("GET", `/api/subjects/${current.id}/check?op=${op}`
          + (purpose ? `&purpose=${encodeURIComponent(purpose)}` : ""));
        if (r.allowed) {
          box.innerHTML = `<div class="okbox">允许：依据 ${esc(r.basis.family)} v${r.basis.version}
            （${esc(r.basis.issued_at)}）<br>获准范围：${opList(r.scope)}</div>`;
        } else {
          box.innerHTML = `<div class="err">不允许（${esc(r.reason)}）
            <pre>${esc(JSON.stringify(r.missing, null, 2))}</pre></div>`;
        }
      }
      await refreshAll();
    } catch (e) { toast(box, e); }
  }
});

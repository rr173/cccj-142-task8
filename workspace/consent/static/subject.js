boot("subject", "app", async main => {
  let me;
  async function loadMe() {
    const r = await api("GET", "/api/me");
    me = r.subject;
  }
  await loadMe();

  main.innerHTML = `
  <div class="card">
    <h2>我的许可与办理中事项 — ${esc(me.name)}</h2>
    <p class="muted">你签过的每份材料都展示其<b>封存原文、版本与指纹</b>；会话自开单起即钉死在该版本，不会被挪到新版本。</p>
    <div id="sessList"></div>
  </div>

  <div class="card">
    <h2>当前许可（撤销后拒绝其后的新操作和新增用途；撤销前已形成的记录保留）</h2>
    <table><thead><tr><th>许可</th><th>材料</th><th>版本</th><th>获准范围</th><th>状态</th>
        <th>签发时刻(UTC)</th><th>封存指纹</th></tr></thead><tbody id="permitRows"></tbody></table>
  </div>

  <div class="card">
    <h2>与我相关的操作记录</h2>
    <table><thead><tr><th>#</th><th>时刻(UTC)</th><th>操作</th><th>用途</th><th>结果</th><th>依据版本</th></tr></thead>
      <tbody id="execRows"></tbody></table>
  </div>`;

  async function refresh() {
    const [sessions, permits, execs] = await Promise.all([
      api("GET", `/api/subjects/${me.id}/sessions`),
      api("GET", `/api/subjects/${me.id}/permits`),
      api("GET", `/api/subjects/${me.id}/executions`),
    ]);
    document.getElementById("sessList").innerHTML = sessions.map(s => `
      <div style="border-bottom:1px solid #edf0f3;padding:10px 0">
        <b>${esc(s.material.family)} v${s.material.version}</b> ${pill(s.status)}
        <span class="muted">${esc(s.id)} · 开单 ${esc(s.created_at)}</span>
        <details><summary class="muted">查看封存原文与指纹</summary>
          <pre>${esc(s.material.body)}</pre>
          <div class="hash">封存指纹（正文/语种/条件/角色/范围）：${esc(s.material.body_hash)}</div>
        </details>
        <table style="margin-top:6px"><tr>
          ${s.slots.map(sl => `<td style="border:0">${esc(sl.role_label)}：${
            sl.filled ? `<span class="pill ok">${esc(sl.signer_name)} @ ${esc(sl.signed_at)}</span>`
                      : `<span class="pill no miss">缺</span>`}</td>`).join("")}
        </tr></table>
        ${s.status === "open"
          ? `<div style="margin-top:6px">
               <button class="small" data-sign="${s.id}">我（参与人）在线签署</button>
               <button class="small danger" data-revoke="${s.id}">撤销办理意愿</button>
             </div><div id="msg-${s.id}"></div>`
          : s.status === "completed"
            ? `<div style="margin-top:6px"><button class="small danger" data-revoke="${s.id}">撤销该许可</button>
               <span class="muted">撤销前已执行的记录仍合法保留，之后的新操作将被拒绝。</span>
               <div id="msg-${s.id}"></div></div>`
            : `<div class="muted" style="margin-top:4px">${
                s.status === "withdrawn" ? `已撤销于 ${esc(s.withdrawn_at)}`
                : `因材料停用冻结于 ${esc(s.blocked_at)}，请用新版重新办理`}</div>`}
      </div>`).join("") || `<p class="muted">暂无办理记录。</p>`;

    document.querySelectorAll("[data-sign]").forEach(b => b.onclick = async () => {
      const box = document.getElementById("msg-" + b.dataset.sign);
      try {
        const r = await TRUST.send("POST", `/api/sessions/${b.dataset.sign}/sign`, { role: "subject" },
          { action: "sign", resource: b.dataset.sign, role: "subject" });
        okbox(box, r.result === "completed"
          ? `已签署且全部角色齐备，许可 ${r.permit_id} 已生成。`
          : "已记录你的签署。");
        await refresh();
      } catch (e) { toast(box, e); }
    });
    document.querySelectorAll("[data-revoke]").forEach(b => b.onclick = async () => {
      if (!confirm("确认撤销？撤销前已执行的记录保留，之后的新操作/新增用途会被拒绝。")) return;
      const box = document.getElementById("msg-" + b.dataset.revoke);
      try {
        const r = await TRUST.send("POST", `/api/sessions/${b.dataset.revoke}/revoke`, {},
          { action: "revoke", resource: b.dataset.revoke });
        okbox(box, "结果：" + r.result);
        await refresh();
      } catch (e) { toast(box, e); }
    });

    document.getElementById("permitRows").innerHTML = permits.map(p => `
      <tr><td>${esc(p.id)}</td><td>${esc(p.family)}</td><td>v${p.version}</td>
        <td>${opList(p.scope)}</td><td>${pill(p.status)}</td>
        <td>${esc(p.issued_at)}</td><td class="hash">${esc(p.body_hash.slice(0, 16))}…</td></tr>`)
      .join("") || `<tr><td colspan="7" class="muted">暂无许可</td></tr>`;

    document.getElementById("execRows").innerHTML = execs.map(e => `
      <tr><td>${e.id}</td><td class="muted">${esc(e.created_at)}</td>
        <td>${esc(OP_LABELS[e.op] || e.op)}</td><td>${esc(e.purpose || "")}</td>
        <td>${e.result === "performed" ? '<span class="pill ok">已执行</span>'
          : '<span class="pill no">已拒绝</span>'}</td>
        <td>${e.material_family ? esc(e.material_family) + " v" + e.version : "—"}</td></tr>`).join("");
  }
  await refresh();
});

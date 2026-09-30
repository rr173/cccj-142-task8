boot("admin", "app", async main => {
  const deviceCard = `
  <div class="card">
    <h2>可信终端登记 / 停用 / 审计</h2>
    <div class="row">
      <div><label>账号 ID</label><input id="devUserId" placeholder="u-site-a / u-wang"></div>
      <div><label>&nbsp;</label><button id="btnEnrollDevice">签发一次性登记授权</button></div>
    </div>
    <div id="enrollDeviceMsg"></div>
    <div class="row">
      <div><label>停用设备号</label><input id="revokeDeviceId" placeholder="D-..."></div>
      <div><label>原因</label><input id="revokeDeviceReason" placeholder="硬件封禁/遗失"></div>
      <div><label>&nbsp;</label><button id="btnRevokeDevice" class="danger">停用设备</button></div>
    </div>
    <div id="revokeDeviceMsg"></div>
    <button id="btnDeviceAudit" class="ghost">刷新设备审计</button>
    <pre id="deviceAudit" class="hash" style="max-height:260px;overflow:auto"></pre>
  </div>`;
  main.innerHTML = deviceCard + `
  <div class="card">
    <h2>发布 / 另立版本（发布即封存正文、语种、适用条件、必签角色、允许操作）</h2>
    <div class="row">
      <div><label>材料族 family</label><input id="f_family" value="GENERAL-TRIAL"></div>
      <div><label>适用机构</label><select id="f_inst"></select></div>
      <div><label>语种</label><select id="f_lang"><option value="zh">中文 zh</option><option value="en">English en</option></select></div>
    </div>
    <label>告知正文（文字任何变化都会另立版本）</label>
    <textarea id="f_body"></textarea>
    <div class="row">
      <div><label>适用人群条件 JSON（全部满足才吻合）</label><input id="f_cond" value='{"adult": true}'></div>
    </div>
    <label class="muted" style="margin-top:10px">必签角色</label>
    <div class="checks">
      <label><input type="checkbox" id="r_subject" checked disabled> 参与人</label>
      <label><input type="checkbox" id="r_site" checked disabled> 现场负责人</label>
      <label><input type="checkbox" id="r_witness" checked> 见证者</label>
    </div>
    <label class="muted" style="margin-top:8px">允许开展的操作</label>
    <div class="checks">
      <label><input type="checkbox" class="op" value="blood_draw" checked> 采血</label>
      <label><input type="checkbox" class="op" value="imaging" checked> 影像检查</label>
      <label><input type="checkbox" class="op" value="medication" checked> 用药</label>
      <label><input type="checkbox" class="op" value="sample_reuse" checked> 留存材料再次利用</label>
    </div>
    <div class="row" style="margin-top:8px">
      <div class="checks" style="flex:2">
        <label style="display:block;color:#52606d;font-size:13px">本版要求再次同意的操作（规则修订触发冻结，待新版补签后解锁）</label>
        <label><input type="checkbox" id="rc_blood_draw" class="rcop" value="blood_draw"> 采血</label>
        <label><input type="checkbox" class="rcop" value="imaging"> 影像检查</label>
        <label><input type="checkbox" class="rcop" value="medication"> 用药</label>
        <label><input type="checkbox" class="rcop" value="sample_reuse"> 留存材料再次利用</label>
      </div>
    </div>
    <div style="margin-top:8px"><button id="btnPub">封存并发布</button></div>
    <div id="pubMsg"></div>
  </div>

  <div class="card">
    <h2>已封存版本（含已停用）</h2>
    <table><thead><tr><th>族</th><th>版本</th><th>机构</th><th>语种</th><th>条件</th><th>必签</th>
      <th>允许操作</th><th>再次同意</th><th>状态</th><th>封存指纹</th><th></th></tr></thead>
    <tbody id="matRows"></tbody></table>
    <p class="muted">审计视图中参与人身份已打码；维护员没有任何替人落款入口。</p>
  </div>

  <div class="card">
    <h2>发布/停用审计（参与人身份打码）</h2>
    <table><thead><tr><th>#</th><th>时刻(UTC)</th><th>事件</th><th>机构</th><th>材料</th><th>明细</th></tr></thead>
    <tbody id="auditRows"></tbody></table>
  </div>`;

  document.getElementById("btnEnrollDevice").onclick = async () => {
    const box = document.getElementById("enrollDeviceMsg");
    try {
      const r = await api("POST", "/api/admin/device-enrollments",
        { user_id: document.getElementById("devUserId").value.trim() });
      okbox(box, `一次性登记授权（请安全转交，仅显示一次）：${r.enrollment_code}`);
    } catch (e) { toast(box, e); }
  };
  document.getElementById("btnRevokeDevice").onclick = async () => {
    const box = document.getElementById("revokeDeviceMsg");
    try {
      const r = await api("POST", "/api/devices/revoke", {
        device_id: document.getElementById("revokeDeviceId").value.trim(),
        reason: document.getElementById("revokeDeviceReason").value.trim(),
      });
      okbox(box, r.idempotent ? "设备此前已停用" : `设备 ${r.device_id} 已停用`);
    } catch (e) { toast(box, e); }
  };
  document.getElementById("btnDeviceAudit").onclick = async () => {
    const r = await api("GET", "/api/device-audit?limit=100");
    document.getElementById("deviceAudit").textContent = JSON.stringify(r, null, 2);
  };
  const insts = await api("GET", "/api/institutions");
  document.getElementById("f_inst").innerHTML =
    insts.map(i => `<option value="${i.id}">${esc(i.id)} · ${esc(i.name)}</option>`).join("");
  document.getElementById("f_body").value =
    "【通用临床试验告知书 v2】\n在此粘贴本版正文……文字或覆盖范围一旦变化就另立版本。";

  const refresh = async () => {
    const mats = await api("GET", "/api/materials?include_retired=1");
    document.getElementById("matRows").innerHTML = mats.map(m => `
      <tr>
        <td>${esc(m.family)}</td><td>v${m.version}</td><td>${esc(m.inst_id)}</td>
        <td>${esc(m.language)}</td>
        <td><code>${esc(JSON.stringify(m.conditions))}</code></td>
        <td>${roleList(m.roles)}</td>
        <td>${opList(m.scope)}</td>
        <td>${m.requires_reconsent ? opList(m.reconsent_ops) : "—"}</td>
        <td>${pill(m.status)}<div class="muted">${esc(m.published_at)}</div></td>
        <td class="hash">${esc(m.body_hash.slice(0, 20))}…</td>
        <td>${m.status === "active" ? `<button class="small danger" data-ret="${m.id}">停用</button>` : ""}</td>
      </tr>`).join("");
    document.querySelectorAll("[data-ret]").forEach(b => b.onclick = async () => {
      if (!confirm("停用后，未结束会话会立即冻结；已发许可继续有效。确认停用？")) return;
      try {
        await api("POST", `/api/materials/${b.dataset.ret}/retire`, {});
        await refresh();
      } catch (e) { alert(e.message); }
    });
    const events = await api("GET", "/api/audit?limit=60");
    document.getElementById("auditRows").innerHTML = events
      .filter(e => e.kind.startsWith("material") || e.kind === "login")
      .map(e => `<tr><td>${e.seq}</td><td class="muted">${esc(e.ts)}</td><td>${esc(e.kind)}</td>
        <td>${esc(e.inst_id || "")}</td><td>${e.material_id || ""}</td>
        <td class="hash">${esc(JSON.stringify(e.detail))}</td></tr>`).join("");
  };

  document.getElementById("btnPub").onclick = async () => {
    const box = document.getElementById("pubMsg");
    try {
      const roles = ["subject", "site_owner"];
      if (document.getElementById("r_witness").checked) roles.push("witness");
      const scope = [...document.querySelectorAll(".op:checked")].map(x => x.value);
      const rcops = [...document.querySelectorAll(".rcop:checked")].map(x => x.value);
      let conditions;
      try { conditions = JSON.parse(document.getElementById("f_cond").value); }
      catch { throw new Error("适用人群条件不是合法 JSON"); }
      const m = await api("POST", "/api/materials", {
        family: document.getElementById("f_family").value.trim(),
        inst_id: document.getElementById("f_inst").value,
        language: document.getElementById("f_lang").value,
        body: document.getElementById("f_body").value,
        conditions, roles, scope,
        requires_reconsent: rcops.length > 0, reconsent_ops: rcops,
      });
      okbox(box, `已封存发布 ${m.family} v${m.version}（指纹 ${m.body_hash.slice(0, 16)}…）`);
      await refresh();
    } catch (e) { toast(box, e); }
  };

  await refresh();
});

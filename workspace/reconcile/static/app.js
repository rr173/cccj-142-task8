function $(id){ return document.getElementById(id); }
function v(id){ return $(id).value.trim(); }
async function api(path, body, method='POST'){
  const opts = {method, headers:{'Content-Type':'application/json'}};
  if(localStorage.token) opts.headers.Authorization = 'Bearer ' + localStorage.token;
  if(body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const data = await res.json().catch(()=>({}));
  if(!res.ok) throw Object.assign(new Error(data.message || res.statusText), {data});
  return data;
}
function esc(x){
  return String(x ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function logout(){ localStorage.removeItem('token'); location='/'; }
async function me(){
  const u = await api('/api/me', undefined, 'GET');
  $('who').textContent = `${u.user.name}（${u.user.role} / ${u.user.inst_id || '全局'}）`;
  return u.user;
}
function rows(items){
  return items.map(i => `<tr>
    <td>${i.item_no}</td><td>${esc(i.occurred_at)}</td><td>${esc(i.subject_id)}</td>
    <td>${esc(i.inst_id)}</td><td>${esc(i.neutral_op)}</td><td>${esc(i.purpose)}</td>
    <td>${esc(i.basis_family)}@${i.basis_version}</td><td><b>${i.result_label}</b></td>
    <td>${esc(JSON.stringify(i.detail))}</td>
    <td>${i.disposition ? esc(i.disposition.resolution) : ''}</td>
  </tr>`).join('');
}

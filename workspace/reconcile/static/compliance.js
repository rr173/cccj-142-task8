let current;
async function boot(){
  await me();
  const cycles = await api('/api/cycles', undefined, 'GET');
  $('cycle').innerHTML = cycles.map(c=>`<option>${c.id}</option>`).join('');
  if(cycles.length) loadLatest();
}
async function loadLatest(){
  $('msg').textContent='';
  try{
    current = await api(`/api/cycles/${$('cycle').value}/latest`, undefined, 'GET');
    render();
  }catch(e){ $('items').innerHTML=''; $('counts').innerHTML='<p>尚未发布版本</p>'; }
}
function render(){
  $('counts').innerHTML = Object.entries(current.counts).map(([k,n])=>`<div class="metric"><b>${n}</b><br>${k}</div>`).join('');
  $('items').innerHTML = rows(current.items);
}
async function recompute(){
  current = await api(`/api/cycles/${$('cycle').value}/recompute`, {});
  render(); $('msg').textContent=`已发布版本 ${current.version_no}`;
}
async function createCycle(){
  const body=JSON.parse($('newCycle').value); await api('/api/cycles',body); location.reload();
}
async function dispose(){
  try{
    const r=await api(`/api/items/${v('itemId')}/disposition`, {resolution:v('resolution'),reason:v('reason'),adopted_snapshot_version:Number(v('snapVer'))});
    $('msg').textContent='已保存 '+r.id; loadLatest();
  }catch(e){ $('msg').textContent=e.message; }
}
async function post(path,id){
  try{ const r=await api(path, JSON.parse($(id).value)); $('ingestMsg').textContent=JSON.stringify(r,null,2); }
  catch(e){ $('ingestMsg').textContent=e.message; }
}
async function claim(){ await post('/api/claims','claim'); }
async function batch(){ await post('/api/claim-batches','claim'); }
async function loadStale(){
  const list=await api('/api/dispositions/stale',undefined,'GET');
  $('stale').innerHTML=list.map(d=>`<div class="card"><b>#${d.id}</b> claim=${esc(d.claim_id)}
    <br>原结论：${d.resolution}；快照版本：${d.adopted_snapshot_version}<br>原因：${esc(d.reason)}
    <br><span class="pill">${d.stale_reason}</span>
    <input placeholder="复核意见" id="rv${d.id}"><button onclick="review(${d.id})">保留原判断并记录复核</button></div>`).join('') || '<p>无</p>';
}
async function review(id){
  await api(`/api/dispositions/${id}/review`,{review_note:v('rv'+id)}); loadStale();
}
boot().catch(e=>$('msg').textContent=e.message);

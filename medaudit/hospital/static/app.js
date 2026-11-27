
const $ = s => document.querySelector(s), app = $('#app');
let token = null, me = null, idleTimer = null, IDLE = 900;
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function api(path, method='GET', body) {
  const r = await fetch(path, {method, headers: {'Content-Type':'application/json', ...(token?{Authorization:'Bearer '+token}:{})},
                               body: body ? JSON.stringify(body) : undefined});
  let data = null; try { data = await r.json(); } catch(e) {}
  if (r.status === 401 && token && path !== '/api/login') { signedOut('Your session has ended. Please sign in again.'); throw new Error('401'); }
  if (!r.ok) { const d = data?.detail; throw new Error(typeof d === 'string' ? d : Array.isArray(d) ? d.map(x=>x.msg).join('; ') : 'Request failed'); }
  return data;
}
function resetIdle() { clearTimeout(idleTimer); if (token) idleTimer = setTimeout(() => signedOut('Signed out after inactivity.'), IDLE*1000); }
['click','keydown'].forEach(e => document.addEventListener(e, resetIdle));
function signedOut(msg) { token = null; me = null; clearTimeout(idleTimer); showLogin(msg); }

function chrome() {
  $('#who').hidden = $('#logout').hidden = !me;
  if (me) $('#who').innerHTML = `<b>${esc(me.full_name)}</b> · ${esc(me.role)}`;
}
$('#patients-nav').onclick=()=>home();
$('#logout').onclick = async () => { try { await api('/api/logout','POST'); } catch(e) {} signedOut(); };

function showLogin(msg='') {
  chrome(); $('#clinic-shell').hidden = true; $('#auth').hidden = false;
  $('#auth').innerHTML = `<main class="login-layout"><section class="login-story"><div class="brand"><span class="brand-mark" aria-hidden="true">+</span>MedAudit</div><div><div class="eyebrow">PATIENT CARE / PROTECTED BY DESIGN</div><h1>Care with context.<br><em>Access with purpose.</em></h1><p>Your clinical workspace connects patient care with accountable access. Every record interaction is encrypted into a tamper-evident audit trail.</p><div class="trust-flow"><div class="trust-node">Authenticate<small>Verify the person</small></div><span class="trust-arrow">→</span><div class="trust-node">Authorize<small>Check the relationship</small></div><span class="trust-arrow">→</span><div class="trust-node">Audit first<small>Then release the data</small></div></div></div><div class="footer-line">MEDAUDIT / HOSPITAL WORKSPACE / SYNTHETIC DEMONSTRATION</div></section><section class="login-panel"><form class="login-form" id="staff-login"><span class="login-tag">HOSPITAL WORKSPACE</span><h2>Good care starts here.</h2><p class="muted">Sign in with your staff account.</p>${msg?`<div class="notice warn">${esc(msg)}</div>`:''}<label for="u">Username</label><input id="u" name="username" autocomplete="username" required placeholder="Your staff username"><label for="p">Password</label><div class="password-row"><input id="p" name="password" type="password" autocomplete="current-password" required><button type="button" id="toggle" aria-pressed="false">Show</button></div><div id="err" role="alert"></div><button class="primary" id="go" type="submit">Sign in to hospital →</button><div class="login-note"><b>Access follows your role and care assignment.</b><br>Clinical records are restricted to authorized caregivers. Emergency access requires a reason and independent review.<br><br>Demo accounts and passwords are in the README. All patient records are synthetic.</div></form></section></main>`;
  $('#staff-login').onsubmit = async event => {
    event.preventDefault(); $('#go').disabled=true;
    try { const r=await api('/api/login','POST',{username:$('#u').value,password:$('#p').value}); token=r.token; IDLE=r.idle_seconds; me=r.user; resetIdle(); home(); }
    catch(e) { $('#err').innerHTML=`<div class="notice bad">${esc(e.message)}</div>`; $('#go').disabled=false; }
  };
  $('#toggle').onclick=()=>{const show=$('#p').type==='password';$('#p').type=show?'text':'password';$('#toggle').textContent=show?'Hide':'Show';$('#toggle').setAttribute('aria-pressed',String(show));};
}

async function home() {
  $('#auth').hidden=true; $('#clinic-shell').hidden=false;
  chrome();
  if (me.role === 'admin') return adminView();
  patientList();
}

async function patientList(q='') {
  app.innerHTML = `<div class="card"><div class="row"><div class="grow"><div class="eyebrow">CLINICAL WORKSPACE</div><h1 style="margin:0">Patient directory</h1><p class="hint" style="margin:8px 0">Find a patient. Access follows your care relationship.</p></div>
    <input aria-label="Search patients" id="q" class="grow" placeholder="Search by name or ID" value="${esc(q)}"><button id="s">Search</button>
    ${['receptionist','doctor'].includes(me.role)?'<button class="primary" id="new">Register patient</button>':''}</div>
    <div id="list" style="margin-top:10px"></div></div>`;
  $('#s').onclick = () => patientList($('#q').value); $('#q').addEventListener('keydown', e => { if (e.key === 'Enter') patientList($('#q').value); });
  $('#new') && ($('#new').onclick = newPatient);
  try {
    const rows = await api('/api/patients?q=' + encodeURIComponent(q));
    $('#list').innerHTML = rows.length ? `<table><tr><th>ID</th><th>Name</th><th>DOB</th><th>Sex</th><th>Ward</th></tr>` +
      rows.map(r => `<tr class="click" data-pid="${esc(r.pid)}"><td>${esc(r.pid)}</td><td><button data-patient="${esc(r.pid)}">${esc(r.name)}</button></td><td>${esc(r.dob)}</td><td>${esc(r.sex)}</td><td>${esc(r.ward)}</td></tr>`).join('') + '</table>'
      : '<p class="hint">No patients found.</p>';
    document.querySelectorAll('[data-patient]').forEach(button => button.onclick=()=>patientView(button.dataset.patient));
  } catch(e) { $('#list').innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; }
}

function newPatient() {
  app.innerHTML = `<div class="card"><h2>Register patient</h2><div class="row">
    <div class="grow"><label for="n">Full name</label><input id="n"></div><div class="grow"><label for="d">Date of birth</label><input id="d" type="date"></div></div>
    <div class="row"><div class="grow"><label for="x">Sex</label><select id="x"><option value="M">Male</option><option value="F">Female</option><option value="O">Other</option></select></div>
    <div class="grow"><label for="w">Ward</label><input id="w"></div></div><div id="err"></div>
    <div class="row" style="margin-top:14px"><button class="primary" id="ok">Register</button><button id="cancel">Cancel</button></div></div>`;
  $('#cancel').onclick = () => patientList();
  $('#ok').onclick = async () => {
    try { const r = await api('/api/patients','POST',{name:$('#n').value, dob:$('#d').value, sex:$('#x').value, ward:$('#w').value}); patientView(r.pid); }
    catch(e) { $('#err').innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; }
  };
}

async function patientView(pid) {
  let p; try { p = await api('/api/patients/' + pid); } catch(e) { app.innerHTML = `<div class="card"><div class="notice bad">${esc(e.message)}</div><button id="error-back">Back</button></div>`; $('#error-back').onclick=()=>patientList(); return; }
  const clinical = p.clinical_access !== 'restricted';
  app.innerHTML = `<div class="card"><div class="row"><h2 class="grow" style="margin:0">${esc(p.name)} <span class="pill">${esc(p.pid)}</span></h2><button id="back">← Back</button></div>
    <div class="kv" style="margin-top:12px"><div>Date of birth</div><div>${esc(p.dob)}</div><div>Sex</div><div>${esc(p.sex)}</div><div>Ward</div><div>${esc(p.ward)||'—'}</div></div>
    <h3>Clinical record</h3>
    ${clinical ? `${p.clinical_access==='break_glass'?'<div class="notice warn"><b>Emergency (break-glass) access</b> — this access is flagged and will be reviewed by compliance.</div>':''}
      <label for="dx">Diagnosis</label><textarea id="dx" ${p.can_edit?'':'readonly'}>${esc(p.diagnosis)}</textarea>
      <label for="nt">Clinical notes</label><textarea id="nt" ${p.can_edit?'':'readonly'}>${esc(p.notes)}</textarea><div id="msg"></div>
      ${p.can_edit?'<div class="row" style="margin-top:10px"><button class="primary" id="save">Save changes</button></div>':'<p class="hint">Read-only for your role.</p>'}`
    : `<div class="notice warn">You are not assigned to this patient, so the clinical record is hidden. This attempt has been logged.</div>
       ${p.can_break_glass?`<p class="hint">In a genuine emergency you may use break-glass access. You must state a reason; it is logged as a critical event and reviewed.</p>
       <label for="why">Reason for emergency access</label><input id="why" placeholder="e.g. Patient collapsed in corridor; treating"><div id="msg"></div>
       <div class="row" style="margin-top:10px"><button class="danger" id="bg">Break glass</button></div>`:''}`}</div>`;
  $('#back').onclick = () => patientList();
  $('#save') && ($('#save').onclick = async () => {
    try { await api(`/api/patients/${pid}/clinical`,'PUT',{diagnosis:$('#dx').value, notes:$('#nt').value}); $('#msg').innerHTML = '<div class="notice ok">Saved.</div>'; }
    catch(e) { $('#msg').innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; }
  });
  $('#bg') && ($('#bg').onclick = async () => {
    try { await api(`/api/patients/${pid}/break-glass`,'POST',{reason:$('#why').value}); patientView(pid); }
    catch(e) { $('#msg').innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; }
  });
}

async function adminView(tab='users') {
  let d, ids; try { d = await api('/api/admin/users'); ids = await api('/api/admin/patient-ids'); } catch(e) { return; }
  app.innerHTML = `<div class="card"><h2>Administration <span class="hint">(no access to patient data)</span></h2><div id="msg"></div>
    <h3>Staff accounts</h3><table><tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th></th></tr>
    ${d.users.map(u => `<tr><td>${esc(u.username)}</td><td>${esc(u.full_name)}</td><td>${esc(u.role)}</td>
      <td><span class="pill ${u.active?'':'off'}">${u.active?'active':'disabled'}</span></td>
      <td>${u.username===me.username?'':`<button data-u="${esc(u.username)}" data-a="${u.active?0:1}">${u.active?'Disable':'Enable'}</button>`}</td></tr>`).join('')}</table>
    <h3>Add staff account</h3><div class="row"><div class="grow"><label for="nu">Username</label><input id="nu"></div><div class="grow"><label for="nf">Full name</label><input id="nf"></div>
    <div class="grow"><label for="nr">Role</label><select id="nr"><option>doctor</option><option>nurse</option><option>receptionist</option><option>admin</option></select></div>
    <div class="grow"><label for="np">Initial password</label><input id="np" type="password"></div><button class="primary" id="add" style="margin-top:22px">Create</button></div>
    <h3>Care assignments</h3><table><tr><th>Staff</th><th>Patient ID</th><th></th></tr>
    ${d.assignments.map(a => `<tr><td>${esc(a.username)}</td><td>${esc(a.pid)}</td><td><button data-rm="${esc(a.username)}|${esc(a.pid)}">Remove</button></td></tr>`).join('')}</table>
    <div class="row" style="margin-top:10px"><div class="grow"><label for="au">Staff (doctor/nurse)</label><select id="au">${d.users.filter(u=>['doctor','nurse'].includes(u.role)).map(u=>`<option>${esc(u.username)}</option>`).join('')}</select></div>
    <div class="grow"><label for="ap">Patient</label><select id="ap">${ids.map(i=>`<option>${esc(i)}</option>`).join('')}</select></div><button id="asg" style="margin-top:22px">Assign</button></div></div>`;
  const msg = (t,k='bad') => $('#msg').innerHTML = `<div class="notice ${k}">${esc(t)}</div>`;
  document.querySelectorAll('button[data-u]').forEach(b => b.onclick = async () => { try { await api(`/api/admin/users/${b.dataset.u}/active`,'POST',{active:b.dataset.a==='1'}); adminView(); } catch(e) { msg(e.message); } });
  document.querySelectorAll('button[data-rm]').forEach(b => b.onclick = async () => { const [u,p]=b.dataset.rm.split('|'); try { await api('/api/admin/assign','POST',{username:u,pid:p,assigned:false}); adminView(); } catch(e) { msg(e.message); } });
  $('#add').onclick = async () => { try { await api('/api/admin/users','POST',{username:$('#nu').value, full_name:$('#nf').value, role:$('#nr').value, password:$('#np').value}); adminView(); } catch(e) { msg(e.message); } };
  $('#asg').onclick = async () => { try { await api('/api/admin/assign','POST',{username:$('#au').value, pid:$('#ap').value, assigned:true}); adminView(); } catch(e) { msg(e.message); } };
}

(async () => {
  if (token) { try { me = await api('/api/me'); resetIdle(); return home(); } catch(e) {} }
  showLogin();
})();

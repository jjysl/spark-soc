// ── AUTENTICACAO ──────────────────────────────────────────────────────────
// Carrega info do usuario logado e popula o topbar
(async function loadSession() {
  try {
    const resp = await fetch('/auth/me', { credentials: 'include' });
    if (resp.status === 401) { window.location.href = '/login'; return; }
    const user = await resp.json();
    document.getElementById('userAvatar').textContent = user.avatar || user.name?.slice(0,2).toUpperCase() || 'SC';
    document.getElementById('userName').textContent   = user.name || user.username;
    document.getElementById('userRole').textContent   = user.role + (user.provider !== 'local' ? ' · ' + user.provider : '');
  } catch(e) {
    window.location.href = '/login';
  }
})();

async function doLogout() {
  await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
  window.location.href = '/login';
}

// CLOCK
function tick(){const s=new Date().toUTCString().split(' ')[4]+' UTC';document.getElementById('clock').textContent=s;document.getElementById('footerClock').textContent=s;}
tick();setInterval(tick,1000);

// TAB SWITCH
function switchTab(id,btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tbtn').forEach(b=>b.classList.remove('active'));
  document.getElementById('panel-'+id).classList.add('active');
  btn.classList.add('active');
}

// TIME SELECTOR
document.querySelectorAll('.tsel span').forEach(el=>{
  el.addEventListener('click',function(){this.closest('.tsel').querySelectorAll('span').forEach(s=>s.classList.remove('active'));this.classList.add('active');});
});

// INCIDENT DATA — SLA thresholds from Fortinet SOCaaS datasheet
const incidents=[
  {id:'INC-2026-0183',ts:'14:32',desc:'Active lateral movement — VLAN 10',tactic:'Lateral Movement',p:'P1',badge:'bp1',analyst:'R. Lima',sla:'0h 12m',slac:'slbr',fillc:'fbr',pct:88,status:'binv',stl:'Investigating'},
  {id:'INC-2026-0182',ts:'14:21',desc:'SSH brute force — 847 attempts',tactic:'Credential Access',p:'P1',badge:'bp1',analyst:'D. Souza',sla:'0h 40m',slac:'slbr',fillc:'fbr',pct:65,status:'binv',stl:'Investigating'},
  {id:'INC-2026-0181',ts:'14:09',desc:'Anomalous outbound data transfer',tactic:'Exfiltration',p:'P2',badge:'bp2',analyst:'J. Silva',sla:'2h 10m',slac:'slwarn',fillc:'fwarn',pct:45,status:'binv',stl:'Investigating'},
  {id:'INC-2026-0180',ts:'13:58',desc:'C2 DNS tunneling detected',tactic:'Command & Control',p:'P2',badge:'bp2',analyst:'M. Pereira',sla:'3h 40m',slac:'slok',fillc:'fok',pct:22,status:'bcont',stl:'Contained'},
  {id:'INC-2026-0179',ts:'13:45',desc:'PowerShell encoded payload execution',tactic:'Execution',p:'P3',badge:'bp3',analyst:'R. Lima',sla:'1h 20m',slac:'slok',fillc:'fok',pct:12,status:'bcont',stl:'Contained'},
  {id:'INC-2026-0178',ts:'13:30',desc:'Unauthorized scheduled task created',tactic:'Persistence',p:'P3',badge:'bp3',analyst:'D. Souza',sla:'2h 05m',slac:'slok',fillc:'fok',pct:8,status:'bnew',stl:'New'},
  {id:'INC-2026-0177',ts:'12:55',desc:'FIM alert — /etc/passwd modified',tactic:'Defense Evasion',p:'P4',badge:'bp4',analyst:'Unassigned',sla:'4h 30m',slac:'slok',fillc:'fok',pct:4,status:'bnew',stl:'New'},
];
const tbody=document.getElementById('exec-wq');
if(tbody) incidents.forEach(i=>{
  tbody.innerHTML+=`<tr>
    <td><span class="mono">${i.id}</span></td>
    <td><span class="mono">${i.ts}</span></td>
    <td><span class="edesc">${i.desc}</span></td>
    <td><span class="tpill">${i.tactic}</span></td>
    <td><span class="badge ${i.badge}">${i.p}</span></td>
    <td style="font-size:12px;color:var(--t2)">${i.analyst}</td>
    <td><div class="slaw"><span class="slat ${i.slac}">${i.sla}</span><div class="slbar"><div class="slbf ${i.fillc}" style="width:${i.pct}%"></div></div></div></td>
    <td><span class="badge ${i.status}">${i.stl}</span></td>
  </tr>`;
});

// KILL CHAIN
const kcSteps=[
  {label:'Reconnaissance',done:true,sub:'Port scan from 185.220.101.4 — T1595'},
  {label:'Initial Access',done:true,sub:'Phishing — credential compromised · T1566'},
  {label:'Execution',done:true,sub:'PowerShell encoded payload · T1059.001'},
  {label:'Lateral Movement',done:true,sub:'Pass-the-Hash across 3 hosts · T1550.002'},
  {label:'Exfiltration (blocked)',active:true,sub:'Attempt blocked by FortiGate · T1041'},
];
const kcd=document.getElementById('killchain');
if(kcd) kcSteps.forEach(s=>{
  const cls=s.done?'done':s.active?'act':'pend';
  const icon=s.done?'✓':s.active?'⟳':'○';
  kcd.innerHTML+=`<div class="kcstep"><div class="kcicon ${cls}">${icon}</div><div><div class="kct">${s.label}</div><div class="kcs">${s.sub}</div></div></div>`;
});


// PLAYBOOK
const pbSteps=[
  {label:'Automated detection',done:true,sub:'FortiAnalyzer ML correlation · 14:23:04 UTC'},
  {label:'Alert enrichment — FortiGuard IOC',done:true,sub:'IOC #FG-2026-0441 matched · CVSS correlated'},
  {label:'Host isolation via FortiGate API',done:true,sub:'POST /api/v2/monitor/user/quarantine · WRK-042 · 14:24:01'},
  {label:'FortiEDR forensic snapshot',active:true,sub:'Memory image in progress — ETA 3 min'},
  {label:'Analyst notification',done:false,sub:'Pending forensic completion'},
  {label:'Automated compliance report',done:false,sub:'Scheduled on incident closure'},
];
const pbd=document.getElementById('playbook');
if(pbd) pbSteps.forEach(s=>{
  const cls=s.done?'done':s.active?'act':'pend';
  const icon=s.done?'✓':s.active?'⟳':'○';
  pbd.innerHTML+=`<div class="pbstep"><div class="pbicon ${cls}">${icon}</div><div><div class="kct">${s.label}</div><div class="kcs">${s.sub}</div></div></div>`;
});

// IR TIMELINE
const irt=[
  {t:'14:23:04',text:'FortiAnalyzer ML alert — lateral movement pattern',color:'#da291c'},
  {t:'14:23:31',text:'MITRE ATT&CK correlation: T1550.002 (Pass-the-Hash)',color:'#f59e0b'},
  {t:'14:23:47',text:'FortiGuard IOC match: IOC #FG-2026-0441',color:'#f59e0b'},
  {t:'14:24:01',text:'SOAR playbook triggered — FortiOS API call initiated',color:'#3b82f6'},
  {t:'14:24:01',text:'POST /api/v2/monitor/user/quarantine — WRK-042',color:'#3b82f6'},
  {t:'14:24:18',text:'Host WRK-042 successfully isolated',color:'#10b981'},
  {t:'14:37:00',text:'FortiEDR forensic snapshot in progress',color:'#f59e0b'},
];
const irtd=document.getElementById('ir-timeline');
if(irtd) irt.forEach(e=>{irtd.innerHTML+=`<div class="tlitem"><span class="tltime">${e.t}</span><div class="tldot" style="background:${e.color}"></div><span class="tltext">${e.text}</span></div>`;});

// API ACTIONS
const apiActions=[
  {status:'200 OK',ok:true,ep:'POST /api/v2/cmdb/firewall/policy — block IP 185.220.101.48'},
  {status:'200 OK',ok:true,ep:'POST /api/v2/monitor/user/quarantine — isolate host WRK-042'},
  {status:'200 OK',ok:true,ep:'GET /api/v2/monitor/firewall/session — active sessions snapshot'},
  {status:'200 OK',ok:true,ep:'POST /api/v2/log/fortianalyzer/setting — ingest IOC #FG-2026-0441'},
];
const aad=document.getElementById('api-actions');
if(aad) apiActions.forEach(a=>{aad.innerHTML+=`<div class="apirow"><span class="badge ${a.ok?'blive':'bcrit'}">${a.status}</span><span style="color:var(--t2);flex:1">${a.ep}</span></div>`;});


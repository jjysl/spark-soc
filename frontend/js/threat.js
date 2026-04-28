// MITRE HEATMAP
const mitTactics=['Recon','Resource Dev','Initial Access','Execution','Persistence','Priv Esc','Def. Evasion','Cred. Access','Discovery','Lateral Move','Exfiltration'];
const mitData=[[0,0,3,4,2,1,3,5,2,5,3],[1,0,2,3,3,2,3,4,3,3,2],[0,1,4,3,1,3,4,3,1,2,4],[0,0,2,2,2,1,2,3,2,2,2]];
const mitColors=['#f1f5f9','#fee2e2','#fca5a5','#f87171','#ef4444','#b91c1c'];
const mw=document.getElementById('mitre-wrap');
if(mw){
  let h='<div style="display:grid;grid-template-columns:repeat(11,1fr);gap:2px;margin-bottom:5px">';
  mitTactics.forEach(t=>{h+=`<div style="font-size:8.5px;font-weight:600;color:var(--tm);text-align:center;line-height:1.2;padding-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${t}</div>`;});
  h+='</div><div style="display:grid;grid-template-columns:repeat(11,1fr);gap:2px">';
  mitData.forEach(row=>row.forEach((v,ci)=>{
    const tc=v>=3?'#fff':'#991b1b';
    h+=`<div style="aspect-ratio:1;border-radius:3px;background:${mitColors[v]};cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:600;color:${tc};transition:opacity .15s" title="${mitTactics[ci]} · ${v>0?v+' event'+(v>1?'s':''):'No hits'}" onmouseover="this.style.opacity=.7" onmouseout="this.style.opacity=1">${v>0?v:''}</div>`;
  }));
  h+='</div><div style="display:flex;align-items:center;gap:6px;margin-top:10px"><span style="font-size:10px;color:var(--tm)">Low</span>';
  mitColors.forEach(c=>{h+=`<div style="width:14px;height:10px;border-radius:2px;background:${c}"></div>`;});
  h+='<span style="font-size:10px;color:var(--tm)">High</span></div>';
  mw.innerHTML=h;
}

// ALERT FEED
const alertData=[
  {ts:'14:32:07',desc:'Multiple failed SSH logins — brute force pattern',src:'192.168.4.22',tactic:'Credential Access',sev:'bcrit',sevl:'Critical',st:'binv',stl:'Investigating'},
  {ts:'14:29:54',desc:'SMB enumeration from domain user account',src:'10.0.1.88',tactic:'Lateral Movement',sev:'bcrit',sevl:'Critical',st:'bnew',stl:'New'},
  {ts:'14:27:11',desc:'Anomalous outbound transfer to 91.108.4.12',src:'10.0.2.14',tactic:'Exfiltration',sev:'bhigh',sevl:'High',st:'binv',stl:'Investigating'},
  {ts:'14:21:40',desc:'PowerShell execution with Base64 payload',src:'10.0.1.45',tactic:'Execution',sev:'bhigh',sevl:'High',st:'bcont',stl:'Contained'},
  {ts:'14:15:03',desc:'New scheduled task — non-admin user',src:'10.0.3.7',tactic:'Persistence',sev:'bmed',sevl:'Medium',st:'bnew',stl:'New'},
  {ts:'14:09:38',desc:'DNS query to known C2 infrastructure',src:'10.0.1.99',tactic:'Command & Control',sev:'bhigh',sevl:'High',st:'bcont',stl:'Contained'},
];
const af=document.getElementById('alert-feed');
if(af) alertData.forEach(a=>{
  af.innerHTML+=`<tr><td><span class="mono">${a.ts}</span></td><td><span class="edesc">${a.desc}</span></td><td><span class="mono">${a.src}</span></td><td><span class="tpill">${a.tactic}</span></td><td><span class="badge ${a.sev}">${a.sevl}</span></td><td><span class="badge ${a.st}">${a.stl}</span></td></tr>`;
});

// IOC CHART
const iocCtx=document.getElementById('iocChart');
if(iocCtx){
  new Chart(iocCtx.getContext('2d'),{type:'line',data:{labels:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],datasets:[
    {label:'Malicious IPs',data:[28,32,29,41,38,44,47],borderColor:'#da291c',backgroundColor:'rgba(218,41,28,0.06)',borderWidth:1.5,pointRadius:3,tension:.3,fill:true},
    {label:'Malicious Domains',data:[14,15,18,20,19,21,23],borderColor:'#f59e0b',backgroundColor:'rgba(245,158,11,0.05)',borderWidth:1.5,pointRadius:3,tension:.3,fill:true}
  ]},options:{responsive:true,maintainAspectRatio:true,animation:{duration:500},plugins:{legend:{position:'top',align:'end',labels:{boxWidth:10,boxHeight:10,font:{size:10,family:'Inter'},padding:10}}},scales:{x:{grid:{display:false},ticks:{font:{size:10,family:'Inter'},color:'#8a95a3'}},y:{grid:{color:'#e2e5ea',lineWidth:.5},ticks:{font:{size:10},color:'#8a95a3'},border:{display:false}}}}});
}


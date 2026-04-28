// COMPLIANCE BARS
const compData=[
  {label:'ISO 27001 — Controls A.12 / A.16',pct:91,color:'#10b981'},
  {label:'PCI DSS 4.0 — Req. 10 & 11',pct:76,color:'#f59e0b'},
  {label:'LGPD / GDPR — Art. 46',pct:88,color:'#10b981'},
  {label:'HIPAA — §164.312',pct:82,color:'#3b82f6'},
  {label:'NIST CSF 2.0',pct:79,color:'#8b5cf6'},
];
const cbd=document.getElementById('comp-bars');
if(cbd) compData.forEach(c=>{cbd.innerHTML+=`<div class="cbar"><div class="chead"><span>${c.label}</span><span class="cval">${c.pct}%</span></div><div class="ctrack"><div class="cfill" style="width:${c.pct}%;background:${c.color}"></div></div></div>`;});

// DRIFT TABLE
const driftData=[
  {device:'FortiGate-01',finding:'Admin policy without MFA enabled',det:'14:05 UTC',sev:'bhigh',sevl:'High',st:'bnew',stl:'Open'},
  {device:'FortiSwitch-Core',finding:'Unauthorized VLAN 99 added',det:'12:30 UTC',sev:'bmed',sevl:'Medium',st:'binv',stl:'Investigating'},
  {device:'FortiAP-03',finding:'Firmware outdated — 7.0.3 (current: 7.4.1)',det:'09:00 UTC',sev:'blow',sevl:'Low',st:'bnew',stl:'Scheduled'},
];
const dt=document.getElementById('drift-table');
if(dt) driftData.forEach(d=>{dt.innerHTML+=`<tr><td style="font-size:12px;font-weight:500;color:var(--t1)">${d.device}</td><td style="font-size:12px;color:var(--t2)">${d.finding}</td><td><span class="mono">${d.det}</span></td><td><span class="badge ${d.sev}">${d.sevl}</span></td><td><span class="badge ${d.st}">${d.stl}</span></td></tr>`;});

// RISK SEGMENTS
const segData=[
  {name:'VLAN 10 — Corporate',risk:72,color:'#f97316'},
  {name:'VLAN 20 — Servers',risk:45,color:'#f59e0b'},
  {name:'VLAN 30 — Finance',risk:28,color:'#10b981'},
  {name:'DMZ',risk:58,color:'#f97316'},
  {name:'Cloud (FortiCASB)',risk:34,color:'#10b981'},
];
const rsd=document.getElementById('risk-seg');
if(rsd) segData.forEach(s=>{rsd.innerHTML+=`<div class="rseg"><span class="rsname">${s.name}</span><div class="rsbar"><div class="rsfill" style="width:${s.risk}%;background:${s.color}"></div></div><span class="rsval">${s.risk}</span></div>`;});

// TREND CHART
const trendCtx=document.getElementById('trendChart');
if(trendCtx){
  const hours=Array.from({length:24},(_,i)=>String(i).padStart(2,'0')+':00');
  window.trendChartRef = new Chart(trendCtx.getContext('2d'),{type:'bar',data:{labels:hours,datasets:[
    {label:'P1 Critical',data:[0,0,1,0,0,0,2,1,0,1,0,3,1,2,1,0,1,2,3,2,1,2,1,3],backgroundColor:'#da291c',stack:'a',barPercentage:.75},
    {label:'P2 High',data:[1,0,2,1,1,2,3,2,1,2,3,4,2,3,2,3,4,5,4,3,5,4,3,4],backgroundColor:'#f59e0b',stack:'a',barPercentage:.75},
    {label:'P3 / P4',data:[2,1,3,2,2,3,4,3,2,3,4,5,3,5,4,5,6,7,6,5,7,5,4,6],backgroundColor:'#e2e5ea',stack:'a',barPercentage:.75}
  ]},options:{responsive:true,maintainAspectRatio:true,animation:{duration:500},
    plugins:{legend:{position:'top',align:'end',labels:{boxWidth:10,boxHeight:10,font:{size:10,family:'Inter'},padding:10}}},
    scales:{x:{stacked:true,grid:{display:false},ticks:{font:{size:9,family:'JetBrains Mono'},color:'#8a95a3',maxTicksLimit:8,maxRotation:0}},
      y:{stacked:true,grid:{color:'#e2e5ea',lineWidth:.5},ticks:{font:{size:10},color:'#8a95a3'},border:{display:false}}}}});
}

const API_BASE = '';

async function fetchLiveData() {
  try {
    const [stats, wazuh, fg, topIps, timeline] = await Promise.allSettled([
      fetch('/spark/stats').then(r => r.json()),
      fetch('/spark/wazuh-alerts').then(r => r.json()),
      fetch('/spark/fortigate-status').then(r => r.json()),
      fetch('/spark/top-ips').then(r => r.json()),
      fetch('/spark/timeline').then(r => r.json()),
    ]);

    // ── KPI: P1 Count (Wazuh level >= 10) ──
    if (wazuh.status === 'fulfilled') {
      const w = wazuh.value;
      const p1count = Object.entries(w.levels)
        .filter(([lv]) => parseInt(lv) >= 10)
        .reduce((acc, [, cnt]) => acc + cnt, 0);
      const p1cards = document.querySelectorAll('.kpi.ka .kv');
      if (p1cards[0]) p1cards[0].textContent = p1count;

      // ── KPI: badge de notificações ──
      document.querySelector('.nbadge').textContent = p1count;

      // ── Alert Feed (Threat Detection) ──
      const af = document.getElementById('alert-feed');
      if (af && w.alerts.length > 0) {
        af.innerHTML = '';
        w.alerts.filter(a => a.src_ip).slice(0, 6).forEach(a => {
          const lv = parseInt(a.level || 0);
          const sev  = lv >= 10 ? 'bcrit' : lv >= 7 ? 'bhigh' : lv >= 4 ? 'bmed' : 'blow';
          const sevl = lv >= 10 ? 'Critical' : lv >= 7 ? 'High'  : lv >= 4 ? 'Medium' : 'Low';
          const ts = a.timestamp ? a.timestamp.substring(11, 19) : '--:--:--';
          af.innerHTML += `<tr>
            <td><span class="mono">${ts}</span></td>
            <td><span class="edesc">${a.description}</span></td>
            <td><span class="mono">${a.src_ip || a.agent_ip || '--'}</span></td>
            <td><span class="tpill">${a.mitre_tactic || 'Network Threat'}</span></td>
            <td><span class="badge ${sev}">${sevl}</span></td>
            <td><span class="badge binv">Investigating</span></td>
          </tr>`;
        });
      }

      // ── AI Triage Box (dinâmico) ──
      const topAlerts = w.alerts.filter(a => a.src_ip).slice(0, 3);
      if (topAlerts.length > 0) {
        const ips = [...new Set(topAlerts.map(a => a.src_ip))].join(', ');
        const aibox = document.querySelector('.aibox');
        if (aibox) aibox.innerHTML = `<strong>OpenSearch Live Triage:</strong> ${w.stats.total} alertas indexados. IPs maliciosos ativos: ${ips}. Último evento: ${topAlerts[0].description} em ${topAlerts[0].timestamp.substring(11,19)} UTC. Ação recomendada: verificar bloqueio via FortiGate Policy API.`;
      }
    }

    // ── KPI: Assets at Risk (SQLite) ──
    if (stats.status === 'fulfilled') {
      const s = stats.value;
      const riskCards = document.querySelectorAll('.kpi.ka .kv');
      // último card KPI ka é "Endpoints at Risk" na aba Network
      // no Executive o único .ka é P1 — já atualizado acima
      // Atualiza o subtítulo do P1
      const p1sub = document.querySelector('.kpi.ka .kd');
      if (p1sub) p1sub.innerHTML = `<span class="up">${s.malicious}</span> IPs maliciosos no banco · SLA: 15 min`;
    }

    // ── FortiGate Live ──
    if (fg.status === 'fulfilled' && fg.value.source === 'fortigate-live') {
      const f = fg.value;
      ['cpuVal','cpuVal2'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = f.cpu + '%';
      });
      ['sessVal','sessVal2'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = f.sessions.toLocaleString();
      });
    }

    // ── Top IPs ──
    if (topIps.status === 'fulfilled' && topIps.value.length > 0) {
      const ipRows = document.querySelectorAll('.iprow');
      topIps.value.slice(0, 5).forEach((ip, i) => {
        if (!ipRows[i]) return;
        const maxHits = topIps.value[0].hits || 1;
        const pct = Math.round((ip.hits / maxHits) * 100);
        ipRows[i].querySelector('.ipaddr').textContent = ip.src_ip;
        ipRows[i].querySelector('.ipgeo').textContent  = ip.country_code || 'XX';
        ipRows[i].querySelector('.ipbf').style.width   = pct + '%';
        ipRows[i].querySelector('.ipcnt').textContent  = ip.hits.toLocaleString();
      });
    }

    // ── Timeline Chart ──
    if (timeline.status === 'fulfilled' && window.trendChartRef) {
      const tl = timeline.value;
      const hoursSet = [...new Set(tl.map(t => t.hour.substring(11,13)+':00'))].sort();
      const p1data = hoursSet.map(h => {
        const r = tl.find(t => t.hour.substring(11,13) === h.split(':')[0] && t.status === 'MALICIOUS');
        return r ? r.count : 0;
      });
      const p2data = hoursSet.map(h => {
        const r = tl.find(t => t.hour.substring(11,13) === h.split(':')[0] && t.status === 'SUSPICIOUS');
        return r ? r.count : 0;
      });
      const p3data = hoursSet.map(h => {
        const r = tl.find(t => t.hour.substring(11,13) === h.split(':')[0] && t.status === 'CLEAN');
        return r ? r.count : 0;
      });
      window.trendChartRef.data.labels = hoursSet;
      window.trendChartRef.data.datasets[0].data = p1data;
      window.trendChartRef.data.datasets[1].data = p2data;
      window.trendChartRef.data.datasets[2].data = p3data;
      window.trendChartRef.update();
    }

  } catch(e) {
    console.warn('[SPARK SOC] Erro:', e.message);
  }
}

fetchLiveData();
setInterval(fetchLiveData, 30000);

// ════════════════════════════════════════════════════════════
//  TICKETS DE INCIDENTES — com IA, Bloqueio de IP, Escalonamento
// ════════════════════════════════════════════════════════════


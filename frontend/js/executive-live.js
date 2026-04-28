function executivePriorityBadge(priority) {
  return {P1:'bp1', P2:'bp2', P3:'bp3', P4:'bp4'}[priority] || 'bp3';
}

function renderExecutiveWorkqueue(items) {
  const body = document.getElementById('exec-wq');
  if (!body || !Array.isArray(items)) return;
  body.innerHTML = items.map(i => `<tr>
    <td><span class="mono">${i.id || 'WAZUH'}</span></td>
    <td><span class="mono">${i.time || '--:--'}</span></td>
    <td><span class="edesc">${i.description || 'Wazuh alert'}</span></td>
    <td><span class="tpill">${i.tactic || 'Detection'}</span></td>
    <td><span class="badge ${i.badge || executivePriorityBadge(i.priority)}">${i.priority || 'P3'}</span></td>
    <td style="font-size:12px;color:var(--t2)">${i.analyst || 'SOC'}</td>
    <td><div class="slaw"><span class="slat ${i.slaClass || 'slok'}">${i.sla || '90 min'}</span><div class="slbar"><div class="slbf ${i.fillClass || 'fok'}" style="width:${i.slaPct || 20}%"></div></div></div></td>
    <td><span class="badge ${i.statusBadge || 'bnew'}">${i.status || 'New'}</span></td>
  </tr>`).join('');
}

function renderExecutiveTrend(timeline) {
  if (!window.trendChartRef || !Array.isArray(timeline) || timeline.length === 0) return;
  const last = timeline.slice(-24);
  window.trendChartRef.data.labels = last.map(row => {
    const hour = row.hour || '';
    return hour.length >= 13 ? hour.substring(11, 13) + ':00' : '--:--';
  });
  window.trendChartRef.data.datasets[0].data = last.map(row => row.p1 || 0);
  window.trendChartRef.data.datasets[1].data = last.map(row => row.p2 || 0);
  window.trendChartRef.data.datasets[2].data = last.map(row => row.p3 || 0);
  window.trendChartRef.update();
}

function applyExecutiveOverview(data) {
  if (!data || !data.kpis) return;
  const cards = document.querySelectorAll('#panel-exec .krow .kpi');
  if (cards[0]) {
    cards[0].querySelector('.kv').textContent = data.kpis.critical_incidents ?? 0;
    cards[0].querySelector('.kd').innerHTML = `<span class="up">${data.kpis.events_24h ?? 0}</span> alertas 24h · SLA: 15 min`;
  }
  if (cards[1]) {
    cards[1].querySelector('.kv').textContent = data.kpis.mttd || 'live';
    cards[1].querySelector('.kd').innerHTML = '<span class="dn">Wazuh live</span>';
  }
  if (cards[2]) {
    cards[2].querySelector('.kv').textContent = data.kpis.mttr || 'live';
    cards[2].querySelector('.kd').innerHTML = '<span class="dn">Shuffle SOAR</span>';
  }
  if (cards[3]) {
    cards[3].querySelector('.kv').textContent = `${data.kpis.sla_compliance ?? 0}%`;
    cards[3].querySelector('.kd').innerHTML = '<span class="dn">Target: 95%</span>';
  }
  if (cards[4]) {
    cards[4].querySelector('.kv').textContent = data.kpis.monitored_assets ?? 0;
    cards[4].querySelector('.kd').innerHTML = `<span class="up">${data.kpis.assets_alerting ?? 0}</span> em alerta`;
  }

  const triage = document.querySelector('#panel-exec .aibox');
  if (triage) triage.innerHTML = `<strong>SPARK Live Triage:</strong> ${data.triage || 'Dados integrados recebidos.'}`;

  renderExecutiveWorkqueue(data.workqueue || []);
  renderExecutiveTrend(data.wazuh?.timeline || []);
}

async function loadExecutiveOverview() {
  try {
    const response = await fetch('/spark/executive-overview', {credentials: 'include'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    applyExecutiveOverview(await response.json());
  } catch (err) {
    console.warn('[SPARK SOC] executive overview offline:', err.message);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadExecutiveOverview();
  setInterval(loadExecutiveOverview, 30000);
});

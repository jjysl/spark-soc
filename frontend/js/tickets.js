let jiraTickets = [];
let editingTicketId = null;
let jiraConfig = JSON.parse(localStorage.getItem('sparkJiraConfig') || '{}');
let aiTicketCount = 0;
let ipBlockLog = [];
let escalationLog = [];

// Mapa de paises com nome completo e bandeira unicode
const countryMap = {
  'AF':['Afeganistao','AF'],'AL':['Albania','AL'],'DZ':['Algeria','DZ'],'AR':['Argentina','AR'],
  'AU':['Australia','AU'],'AT':['Austria','AT'],'AZ':['Azerbaijao','AZ'],'BH':['Bahrein','BH'],
  'BD':['Bangladesh','BD'],'BY':['Bielorrussia','BY'],'BE':['Belgica','BE'],'BR':['Brasil','BR'],
  'BG':['Bulgaria','BG'],'CA':['Canada','CA'],'CL':['Chile','CL'],'CN':['China','CN'],
  'CO':['Colombia','CO'],'HR':['Croacia','HR'],'CZ':['Republica Tcheca','CZ'],'DK':['Dinamarca','DK'],
  'EG':['Egito','EG'],'FI':['Finlandia','FI'],'FR':['Franca','FR'],'DE':['Alemanha','DE'],
  'GH':['Gana','GH'],'GR':['Grecia','GR'],'HK':['Hong Kong','HK'],'HU':['Hungria','HU'],
  'IN':['India','IN'],'ID':['Indonesia','ID'],'IR':['Ira','IR'],'IQ':['Iraque','IQ'],
  'IE':['Irlanda','IE'],'IL':['Israel','IL'],'IT':['Italia','IT'],'JP':['Japao','JP'],
  'KZ':['Cazaquistao','KZ'],'KE':['Quenia','KE'],'KP':['Coreia do Norte','KP'],'KR':['Coreia do Sul','KR'],
  'KW':['Kuwait','KW'],'LV':['Latvia','LV'],'LB':['Libano','LB'],'LT':['Lituania','LT'],
  'MY':['Malasia','MY'],'MX':['Mexico','MX'],'MA':['Marrocos','MA'],'NL':['Holanda','NL'],
  'NZ':['Nova Zelandia','NZ'],'NG':['Nigeria','NG'],'NO':['Noruega','NO'],'PK':['Paquistao','PK'],
  'PE':['Peru','PE'],'PH':['Filipinas','PH'],'PL':['Polonia','PL'],'PT':['Portugal','PT'],
  'QA':['Catar','QA'],'RO':['Romania','RO'],'RU':['Russia','RU'],'SA':['Arabia Saudita','SA'],
  'RS':['Serbia','RS'],'SG':['Singapura','SG'],'ZA':['Africa do Sul','ZA'],'ES':['Espanha','ES'],
  'SE':['Suecia','SE'],'CH':['Suica','CH'],'TW':['Taiwan','TW'],'TH':['Tailandia','TH'],
  'TR':['Turquia','TR'],'UA':['Ucrania','UA'],'AE':['Emirados Arabes','AE'],'GB':['Reino Unido','GB'],
  'US':['Estados Unidos','US'],'UY':['Uruguai','UY'],'UZ':['Uzbequistao','UZ'],'VN':['Vietna','VN'],
  'YE':['Iemen','YE'],'ZW':['Zimbabue','ZW'],
};

function countryCodeToFlag(code) {
  if (!code || code.length !== 2) return '';
  const base = 0x1F1E6 - 65;
  return String.fromCodePoint(base + code.toUpperCase().charCodeAt(0)) +
         String.fromCodePoint(base + code.toUpperCase().charCodeAt(1));
}

function getCountryName(code) {
  return countryMap[code] ? countryMap[code][0] : code;
}

// IP seed com paises mapeados
const seedTickets = [
  {id:'SPARK-001',title:'[P1] Active Lateral Movement — VLAN 10 · INC-2026-0183',status:'inprogress',priority:'p1',type:'incident',assignee:'R. Lima',incidentLink:'INC-2026-0183',mitre:'T1550.002',ip:'10.0.1.88',country:'BR',ipBlocked:false,escalatedTo:'',desc:'Lateral movement detectado via Pass-the-Hash em 3 hosts VLAN 10. Host WRK-042 isolado via FortiGate API.',playbook:'1. Isolar WRK-042 via FortiGate quarantine API\n2. Coletar memory dump com FortiEDR\n3. Correlacionar com IOC #FG-2026-0441\n4. Notificar CISO\n5. Gerar relatorio de compliance',aiGenerated:true,created:'14:24 UTC'},
  {id:'SPARK-002',title:'[P1] SSH Brute Force — 847 tentativas · INC-2026-0182',status:'inprogress',priority:'p1',type:'incident',assignee:'D. Souza',incidentLink:'INC-2026-0182',mitre:'T1110.001',ip:'185.220.101.4',country:'RU',ipBlocked:true,escalatedTo:'',desc:'Brute force SSH com 847 tentativas em 12 minutos. IP bloqueado via FortiGate Policy.',playbook:'1. Bloquear IP via FortiGate\n2. Verificar contas comprometidas\n3. Resetar credenciais expostas',aiGenerated:false,created:'14:21 UTC'},
  {id:'SPARK-003',title:'[P2] Exfiltracao de Dados Anomala — T1041',status:'open',priority:'p2',type:'threat',assignee:'J. Silva',incidentLink:'INC-2026-0181',mitre:'T1041',ip:'91.108.4.12',country:'CN',ipBlocked:false,escalatedTo:'CISO',escalationReason:'Volume de dados suspeito — necessita aprovacao executiva',desc:'Transferencia anomala de dados para IP externo 91.108.4.12 (CN). Volume de 2.1GB em 40min.',playbook:'1. Capturar trafego via FortiGate mirror\n2. Identificar dados exfiltrados\n3. Bloquear IP destino',aiGenerated:true,created:'14:09 UTC'},
  {id:'SPARK-004',title:'[P2] C2 DNS Tunneling — INC-2026-0180',status:'review',priority:'p2',type:'threat',assignee:'M. Pereira',incidentLink:'INC-2026-0180',mitre:'T1071.004',ip:'10.0.1.99',country:'US',ipBlocked:false,escalatedTo:'',desc:'Tunneling DNS para infraestrutura C2 conhecida. Bloqueado via FortiGuard DNS Filter.',playbook:'1. Bloquear dominio no FortiGuard\n2. Analisar queries DNS historicas\n3. Verificar outros hosts afetados',aiGenerated:false,created:'13:58 UTC'},
  {id:'SPARK-005',title:'[P3] PowerShell Encoded Payload — INC-2026-0179',status:'done',priority:'p3',type:'incident',assignee:'R. Lima',incidentLink:'INC-2026-0179',mitre:'T1059.001',ip:'10.0.1.45',country:'BR',ipBlocked:false,escalatedTo:'',desc:'Execucao de payload PowerShell com Base64 encoding. Contido e analisado.',playbook:'1. Quarentena do processo\n2. Analise estatica do payload\n3. Verificar persistencia',aiGenerated:false,created:'13:45 UTC'},
  {id:'SPARK-006',title:'[P3] Scheduled Task Nao Autorizada — INC-2026-0178',status:'open',priority:'p3',type:'incident',assignee:'D. Souza',incidentLink:'INC-2026-0178',mitre:'T1053.005',ip:'10.0.3.7',country:'BR',ipBlocked:false,escalatedTo:'',desc:'Scheduled task criada por usuario nao-admin. Possivel mecanismo de persistencia.',playbook:'1. Remover scheduled task\n2. Verificar integridade do sistema\n3. Revisar privilegios do usuario',aiGenerated:false,created:'13:30 UTC'},
];

aiTicketCount = seedTickets.filter(t => t.aiGenerated).length;

function toggleJiraConfig() {
  const body = document.getElementById('jiraConfigBody');
  const chevron = document.getElementById('jiraCfgChevron');
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  chevron.style.transform = isOpen ? '' : 'rotate(180deg)';
}

function toggleEscalationReason() {
  const sel = document.getElementById('jmEscalateTo').value;
  document.getElementById('escalationReasonField').style.display = sel ? 'flex' : 'none';
}

function initJira() {
  jiraTickets = [...seedTickets];
  if (jiraConfig.url) {
    document.getElementById('cfgJiraUrl').value = jiraConfig.url || '';
    document.getElementById('cfgJiraEmail').value = jiraConfig.email || '';
    document.getElementById('cfgJiraProject').value = jiraConfig.project || 'SPARK';
    document.getElementById('jiraCfgStatus').textContent = 'Configurado';
    document.getElementById('jiraCfgStatus').className = 'jira-config-status jcfg-ok';
  }
  // Seed block log from pre-blocked tickets
  seedTickets.filter(t => t.ipBlocked).forEach(t => {
    ipBlockLog.push({ip: t.ip, country: t.country, action:'Bloqueado', reason: t.title, analyst: t.assignee, time: t.created, status:'Ativo'});
  });
  // Seed escalation log
  seedTickets.filter(t => t.escalatedTo).forEach(t => {
    escalationLog.push({ticket: t.id, incident: t.incidentLink, to: t.escalatedTo, reason: t.escalationReason||'—', time: t.created, status:'Aguardando'});
  });
  renderBoard();
  renderIpBlockLog();
  renderEscalationLog();
  updateJiraStats();
}

function saveJiraConfig() {
  const url = document.getElementById('cfgJiraUrl').value.trim();
  const email = document.getElementById('cfgJiraEmail').value.trim();
  const token = document.getElementById('cfgJiraToken').value.trim();
  const project = document.getElementById('cfgJiraProject').value.trim() || 'SPARK';
  if (!url || !email || !token) { alert('Preencha URL, Email e Token.'); return; }
  jiraConfig = { url, email, token, project };
  localStorage.setItem('sparkJiraConfig', JSON.stringify(jiraConfig));
  document.getElementById('jiraCfgStatus').textContent = 'Testando conexao...';
  document.getElementById('jiraCfgStatus').className = 'jira-config-status jcfg-off';
  testJiraConnection();
}

async function testJiraConnection() {
  try {
    const creds = btoa(`${jiraConfig.email}:${jiraConfig.token}`);
    const resp = await fetch(`${jiraConfig.url}/rest/api/3/myself`, {
      headers: { 'Authorization': `Basic ${creds}`, 'Accept': 'application/json' }
    });
    if (resp.ok) {
      document.getElementById('jiraCfgStatus').textContent = 'Conectado';
      document.getElementById('jiraCfgStatus').className = 'jira-config-status jcfg-ok';
      document.getElementById('jiraAiBox').innerHTML = '<strong>Jira Conectado:</strong> Integracao ativa. Tickets serao criados no Jira automaticamente.';
      await syncJiraTickets();
    } else { throw new Error(); }
  } catch(e) {
    document.getElementById('jiraCfgStatus').textContent = 'Erro de conexao';
    document.getElementById('jiraCfgStatus').className = 'jira-config-status jcfg-err';
  }
}

async function syncJiraTickets() {
  if (!jiraConfig.url || !jiraConfig.token) {
    document.getElementById('boardSyncTime').textContent = 'Configure o Jira para sincronizar';
    return;
  }
  document.getElementById('boardSyncTime').textContent = 'Sincronizando...';
  try {
    const creds = btoa(`${jiraConfig.email}:${jiraConfig.token}`);
    const proj = jiraConfig.project || 'SPARK';
    const resp = await fetch(`${jiraConfig.url}/rest/api/3/search?jql=project=${proj}+ORDER+BY+created+DESC&maxResults=50`, {
      headers: { 'Authorization': `Basic ${creds}`, 'Accept': 'application/json' }
    });
    if (!resp.ok) throw new Error();
    const data = await resp.json();
    const remote = data.issues.map(i => ({
      id: i.key, title: i.fields.summary,
      status: mapJiraStatus(i.fields.status.name),
      priority: mapJiraPriority(i.fields.priority?.name),
      type:'incident', assignee: i.fields.assignee?.displayName || '',
      incidentLink:'', mitre:'', ip:'', country:'', ipBlocked:false, escalatedTo:'',
      desc: i.fields.description?.content?.[0]?.content?.[0]?.text || '',
      playbook:'', aiGenerated:false,
      created: new Date(i.fields.created).toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'}) + ' UTC',
    }));
    const localIds = jiraTickets.map(t => t.id);
    remote.forEach(r => { if (!localIds.includes(r.id)) jiraTickets.push(r); });
    renderBoard(); updateJiraStats();
    document.getElementById('boardSyncTime').textContent = 'Sincronizado: ' + new Date().toLocaleTimeString('pt-BR');
  } catch(e) {
    document.getElementById('boardSyncTime').textContent = 'Erro ao sincronizar';
  }
}

function mapJiraStatus(s) {
  s=(s||'').toLowerCase();
  if(s.includes('done')||s.includes('closed')||s.includes('resolved')) return 'done';
  if(s.includes('review')||s.includes('testing')) return 'review';
  if(s.includes('progress')) return 'inprogress';
  return 'open';
}
function mapJiraPriority(p) {
  p=(p||'').toLowerCase();
  if(p.includes('critical')||p==='highest') return 'p1';
  if(p.includes('high')) return 'p2';
  if(p.includes('medium')) return 'p3';
  return 'p4';
}

// ── COUNTRY LOOKUP ──
async function lookupIpCountry() {
  const ip = document.getElementById('jmIp').value.trim();
  if (!ip || ip.startsWith('10.') || ip.startsWith('192.168') || ip.startsWith('172.')) {
    setCountryDisplay('BR', 'Rede Interna');
    return;
  }
  document.getElementById('jmCountryName').textContent = 'Buscando...';
  try {
    const resp = await fetch(`https://ipapi.co/${ip}/json/`);
    const data = await resp.json();
    if (data.country_code) {
      setCountryDisplay(data.country_code, data.country_name || getCountryName(data.country_code));
      window._aiCountry = data.country_code;
    } else { setCountryDisplay('??', 'Desconhecido'); }
  } catch(e) {
    // Fallback: guess from stored data
    const t = jiraTickets.find(x => x.ip === ip);
    if (t && t.country) { setCountryDisplay(t.country, getCountryName(t.country)); }
    else { setCountryDisplay('??', 'Desconhecido'); }
  }
}

function setCountryDisplay(code, name) {
  const flag = countryCodeToFlag(code);
  document.getElementById('jmCountryFlag').textContent = flag;
  document.getElementById('jmCountryName').textContent = name || getCountryName(code);
  const codeEl = document.getElementById('jmCountryCode');
  codeEl.textContent = code;
  codeEl.style.display = code && code !== '??' ? 'inline' : 'none';
  window._aiCountry = code;
}

// ── BLOCK / UNBLOCK IP ──
function blockIp() {
  const ip = document.getElementById('jmIp').value.trim();
  if (!ip) { alert('Informe o IP antes de bloquear.'); return; }
  const country = window._aiCountry || '';
  const incLink = document.getElementById('jmIncLink').value || document.getElementById('jmTitleInput').value || '—';
  const analyst = document.getElementById('jmAssignee').value || 'SOC';
  const entry = { ip, country, action:'Bloqueado', reason: incLink, analyst, time: new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'})+' UTC', status:'Ativo' };
  // Remove duplicate
  ipBlockLog = ipBlockLog.filter(x => !(x.ip === ip && x.action === 'Bloqueado'));
  ipBlockLog.unshift(entry);
  // Mark in ticket
  if (editingTicketId) { const t = jiraTickets.find(x=>x.id===editingTicketId); if(t) t.ipBlocked = true; }
  renderIpBlockLog(); renderBoard();
  document.getElementById('jmIpStatus').innerHTML = '<span style="color:#991b1b;font-weight:600">IP bloqueado via FortiGate API</span>';
  document.getElementById('btnBlockIp').style.opacity = '.5';
  document.getElementById('btnUnblockIp').style.opacity = '1';
}

function unblockIp() {
  const ip = document.getElementById('jmIp').value.trim();
  if (!ip) { alert('Informe o IP antes de desbloquear.'); return; }
  const country = window._aiCountry || '';
  const incLink = document.getElementById('jmIncLink').value || '—';
  const analyst = document.getElementById('jmAssignee').value || 'SOC';
  const entry = { ip, country, action:'Desbloqueado', reason: incLink, analyst, time: new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'})+' UTC', status:'Removido' };
  ipBlockLog.unshift(entry);
  if (editingTicketId) { const t = jiraTickets.find(x=>x.id===editingTicketId); if(t) t.ipBlocked = false; }
  renderIpBlockLog(); renderBoard();
  document.getElementById('jmIpStatus').innerHTML = '<span style="color:#065f46;font-weight:600">IP desbloqueado — regra removida</span>';
  document.getElementById('btnBlockIp').style.opacity = '1';
  document.getElementById('btnUnblockIp').style.opacity = '.5';
}

function renderIpBlockLog() {
  const tbody = document.getElementById('ipBlockLog');
  const empty = document.getElementById('ipBlockEmpty');
  let blocked = ipBlockLog.filter(x => x.action === 'Bloqueado' && x.status === 'Ativo').length;
  document.getElementById('blockedCount').textContent = blocked + ' bloqueado' + (blocked !== 1 ? 's' : '');
  if (ipBlockLog.length === 0) { tbody.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';
  tbody.innerHTML = ipBlockLog.map(e => {
    const flag = countryCodeToFlag(e.country);
    const name = getCountryName(e.country);
    const st = e.action === 'Bloqueado' ? 'bcrit' : 'bok';
    return `<tr>
      <td><span class="mono">${e.ip}</span></td>
      <td><span style="font-size:14px">${flag}</span> <span style="font-size:11px;color:var(--t2)">${name}</span> <span class="jcard-country">${e.country||''}</span></td>
      <td><span class="badge ${st}">${e.action}</span></td>
      <td style="font-size:11px;color:var(--t2);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.reason}</td>
      <td style="font-size:11px;color:var(--t2)">${e.analyst}</td>
      <td><span class="mono">${e.time}</span></td>
      <td><span class="badge ${e.status==='Ativo'?'bcrit':'bok'}">${e.status}</span></td>
    </tr>`;
  }).join('');
}

function renderEscalationLog() {
  const tbody = document.getElementById('escalationLog');
  const empty = document.getElementById('escalationEmpty');
  document.getElementById('escalationCount').textContent = escalationLog.length + ' escalonamento' + (escalationLog.length !== 1 ? 's' : '');
  if (escalationLog.length === 0) { tbody.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';
  tbody.innerHTML = escalationLog.map(e => `<tr>
    <td><span class="mono">${e.ticket}</span></td>
    <td><span class="jcard-inc">${e.incident||'—'}</span></td>
    <td style="font-size:12px;font-weight:500;color:var(--t1)">${e.to}</td>
    <td style="font-size:11px;color:var(--t2);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.reason}</td>
    <td><span class="mono">${e.time}</span></td>
    <td><span class="badge bexp">${e.status}</span></td>
  </tr>`).join('');
}

function renderBoard() {
  const pf = document.getElementById('filterPriority').value;
  const af = document.getElementById('filterAssignee').value;
  const tf = document.getElementById('filterType').value;
  const cols = ['open','inprogress','review','done'];
  cols.forEach(c => { document.getElementById('col-'+c).innerHTML=''; document.getElementById('cnt-'+c).textContent=0; });
  const filtered = jiraTickets.filter(t => (!pf||t.priority===pf)&&(!af||t.assignee===af)&&(!tf||t.type===tf));
  const counts = {open:0,inprogress:0,review:0,done:0};
  filtered.forEach(t => {
    const col = document.getElementById('col-'+t.status);
    if (!col) return;
    counts[t.status] = (counts[t.status]||0)+1;
    const pBadge = {p1:'bcrit',p2:'bhigh',p3:'bmed',p4:'blow'}[t.priority]||'blow';
    const pLabel = {p1:'P1',p2:'P2',p3:'P3',p4:'P4'}[t.priority]||'P4';
    const typeLabel = {incident:'Incident',threat:'Threat',vuln:'Vuln',task:'Task',change:'Change'}[t.type]||'Ticket';
    const flag = countryCodeToFlag(t.country||'');
    const countryName = getCountryName(t.country||'');
    const blockedTag = t.ipBlocked ? '<span class="jcard-blocked">IP Bloqueado</span>' : '';
    const escalatedTag = t.escalatedTo ? `<span class="jcard-escalated">Escalonado</span>` : '';
    col.innerHTML += `<div class="jcard" onclick="openEditTicket('${t.id}')">
      ${t.aiGenerated ? '<div class="jcard-ai-flag">AI</div>' : ''}
      <div class="jcard-id"><span>${t.id}</span><span style="font-size:10px;color:var(--tm)">${typeLabel}</span></div>
      <div class="jcard-title">${t.title}</div>
      <div class="jcard-meta">
        <span class="badge ${pBadge}">${pLabel}</span>
        ${t.incidentLink ? `<span class="jcard-inc">${t.incidentLink}</span>` : ''}
        ${t.country ? `<span title="${countryName}" style="font-size:13px">${flag}</span><span class="jcard-country">${t.country}</span>` : ''}
        ${blockedTag}${escalatedTag}
        ${t.assignee ? `<div class="jcard-av" title="${t.assignee}">${t.assignee.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()}</div>` : ''}
        <span style="font-size:10px;color:var(--tm);margin-left:auto">${t.created||''}</span>
      </div>
    </div>`;
  });
  cols.forEach(c => { document.getElementById('cnt-'+c).textContent = counts[c]||0; });
}

function updateJiraStats() {
  document.getElementById('jstatTotal').textContent = jiraTickets.filter(t=>t.status!=='done').length;
  document.getElementById('jstatP1').textContent = jiraTickets.filter(t=>t.priority==='p1'&&t.status!=='done').length;
  document.getElementById('jstatP2').textContent = jiraTickets.filter(t=>t.priority==='p2'&&t.status!=='done').length;
  document.getElementById('jstatDone').textContent = jiraTickets.filter(t=>t.status==='done').length;
  document.getElementById('jstatAI').textContent = jiraTickets.filter(t=>t.aiGenerated).length;
}

// AI Alerts
const aiAlerts = [
  {label:'INC-2026-0183 · Lateral Movement',incidentLink:'INC-2026-0183',priority:'p1',type:'incident',assignee:'R. Lima',ip:'10.0.1.88',mitre:'T1550.002',tactic:'Lateral Movement',srcIp:'10.0.1.88',country:'BR',desc:'Lateral movement detectado — Pass-the-Hash em 3 hosts VLAN 10.'},
  {label:'INC-2026-0182 · SSH Brute Force',incidentLink:'INC-2026-0182',priority:'p1',type:'incident',assignee:'D. Souza',ip:'185.220.101.4',mitre:'T1110.001',tactic:'Credential Access',srcIp:'185.220.101.4',country:'RU',desc:'SSH brute force: 847 tentativas de login falhadas em 12 min.'},
  {label:'INC-2026-0181 · Data Exfiltration',incidentLink:'INC-2026-0181',priority:'p2',type:'threat',assignee:'J. Silva',ip:'91.108.4.12',mitre:'T1041',tactic:'Exfiltration',srcIp:'91.108.4.12',country:'CN',desc:'Transferencia anomala para 91.108.4.12 (CN) — 2.1GB em 40min.'},
  {label:'INC-2026-0180 · C2 DNS Tunneling',incidentLink:'INC-2026-0180',priority:'p2',type:'threat',assignee:'M. Pereira',ip:'10.0.1.99',mitre:'T1071.004',tactic:'Command & Control',srcIp:'10.0.1.99',country:'US',desc:'DNS tunneling para infraestrutura C2 conhecida.'},
  {label:'FIM Alert · /etc/passwd',incidentLink:'INC-2026-0177',priority:'p4',type:'incident',assignee:'',ip:'10.0.3.7',mitre:'T1565.001',tactic:'Defense Evasion',srcIp:'10.0.3.7',country:'BR',desc:'File Integrity Monitoring: /etc/passwd modificado por usuario nao autorizado.'},
];

function openNewTicket() {
  editingTicketId = null;
  window._aiCountry = '';
  document.getElementById('jmId').textContent = 'INC-NEW';
  document.getElementById('jmTitle').textContent = 'Novo Ticket de Incidente';
  document.getElementById('jmTitleInput').value=''; document.getElementById('jmDesc').value='';
  document.getElementById('jmPlaybook').value=''; document.getElementById('jmAiAnalysis').textContent='Selecione um alerta acima para gerar analise automatica...';
  document.getElementById('jmStatus').value='open'; document.getElementById('jmPriority').value='p2';
  document.getElementById('jmType').value='incident'; document.getElementById('jmAssignee').value='';
  document.getElementById('jmIncLink').value=''; document.getElementById('jmMitre').value='';
  document.getElementById('jmIp').value=''; document.getElementById('jmKey').value='';
  document.getElementById('jmEscalateTo').value='';
  document.getElementById('jmEscalationReason').value='';
  document.getElementById('escalationReasonField').style.display='none';
  document.getElementById('jmSubmitLabel').textContent='Criar no SOC';
  document.getElementById('jmIpStatus').textContent='';
  document.getElementById('btnBlockIp').style.opacity='1';
  document.getElementById('btnUnblockIp').style.opacity='1';
  setCountryDisplay('','—');
  document.getElementById('aiTyping').textContent='';
  buildAiChips();
  document.getElementById('jiraOverlay').classList.add('open');
}

function openEditTicket(id) {
  const t = jiraTickets.find(x=>x.id===id);
  if (!t) return;
  editingTicketId = id;
  window._aiCountry = t.country || '';
  document.getElementById('jmId').textContent = t.id;
  document.getElementById('jmTitle').textContent = t.title;
  document.getElementById('jmTitleInput').value = t.title;
  document.getElementById('jmDesc').value = t.desc||'';
  document.getElementById('jmPlaybook').value = t.playbook||'';
  document.getElementById('jmAiAnalysis').textContent = t.aiAnalysis||'Clique em um chip de alerta para regerar analise IA...';
  document.getElementById('jmStatus').value = t.status;
  document.getElementById('jmPriority').value = t.priority;
  document.getElementById('jmType').value = t.type;
  document.getElementById('jmAssignee').value = t.assignee||'';
  document.getElementById('jmIncLink').value = t.incidentLink||'';
  document.getElementById('jmMitre').value = t.mitre||'';
  document.getElementById('jmIp').value = t.ip||'';
  document.getElementById('jmKey').value = t.id;
  document.getElementById('jmEscalateTo').value = t.escalatedTo||'';
  document.getElementById('jmEscalationReason').value = t.escalationReason||'';
  document.getElementById('escalationReasonField').style.display = t.escalatedTo ? 'flex' : 'none';
  document.getElementById('jmSubmitLabel').textContent = 'Atualizar no SOC';
  document.getElementById('jmIpStatus').textContent='';
  const blocked = t.ipBlocked;
  document.getElementById('btnBlockIp').style.opacity = blocked ? '.5' : '1';
  document.getElementById('btnUnblockIp').style.opacity = blocked ? '1' : '.5';
  if (t.country) { setCountryDisplay(t.country, getCountryName(t.country)); }
  else { setCountryDisplay('','—'); }
  document.getElementById('aiTyping').textContent='';
  buildAiChips();
  document.getElementById('jiraOverlay').classList.add('open');
}

function closeJiraModal() {
  document.getElementById('jiraOverlay').classList.remove('open');
  editingTicketId = null;
}

function buildAiChips() {
  const chips = document.getElementById('aiChips');
  chips.innerHTML = aiAlerts.map((a,i)=>`<button class="ai-chip" onclick="aiAutoFill(${i})">${a.label}</button>`).join('')
    + `<button class="ai-chip" onclick="aiAutoFill(-1)" style="background:#f0fdf4;color:#065f46;border-color:#a7f3d0">Analisar todos</button>`;
}

async function aiAutoFill(alertIdx) {
  const chips = document.getElementById('aiChips');
  chips.querySelectorAll('.ai-chip').forEach(c=>c.classList.add('loading'));
  document.getElementById('aiTyping').innerHTML='<span class="spin"></span> IA analisando o alerta...';
  const alert = alertIdx >= 0 ? aiAlerts[alertIdx] : null;
  if (alert) {
    document.getElementById('jmPriority').value = alert.priority;
    document.getElementById('jmType').value = alert.type;
    document.getElementById('jmAssignee').value = alert.assignee;
    document.getElementById('jmIncLink').value = alert.incidentLink;
    document.getElementById('jmMitre').value = alert.mitre;
    document.getElementById('jmIp').value = alert.ip;
    window._aiCountry = alert.country;
    setCountryDisplay(alert.country, getCountryName(alert.country));
  }
  const context = alert
    ? `Incidente SOC: ${alert.incidentLink} | Tatica: ${alert.tactic} | MITRE: ${alert.mitre} | IP Origem: ${alert.srcIp} | Pais: ${getCountryName(alert.country)} (${alert.country}) | Descricao: ${alert.desc}`
    : `Multiplos incidentes: Lateral Movement VLAN 10 (BR), SSH Brute Force 847 tentativas (RU), DNS Tunneling C2 (US), Exfiltracao dados (CN).`;
  try {
    // Usa o proxy do backend em vez de chamar a Anthropic diretamente (evita bloqueio de CORS)
    const response = await fetch('/spark/ai/autofill', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ context })
    });
    const data = await response.json();
    // O proxy já retorna o objeto parseado com as chaves: title, description, playbook, analysis
    const raw = JSON.stringify(data);
    let parsed;
    try { parsed = (typeof data === 'object' && data.title) ? data : JSON.parse(raw.replace(/```json|```/g,'').trim()); } catch(e) { parsed={}; }
    if (parsed.title) document.getElementById('jmTitleInput').value = parsed.title;
    if (parsed.description) document.getElementById('jmDesc').value = parsed.description;
    if (parsed.playbook) document.getElementById('jmPlaybook').value = parsed.playbook;
    if (parsed.analysis) typewriterEffect('jmAiAnalysis', parsed.analysis);
    document.getElementById('aiTyping').innerHTML='<span style="color:#065f46;font-weight:600">Auto-preenchimento concluido</span>';
  } catch(e) {
    if (alert) {
      document.getElementById('jmTitleInput').value = `[${alert.priority.toUpperCase()}] ${alert.tactic} detectado — ${alert.incidentLink}`;
      document.getElementById('jmDesc').value = alert.desc + ` IP: ${alert.ip} (${getCountryName(alert.country)}). MITRE: ${alert.mitre}.`;
      document.getElementById('jmPlaybook').value = `1. Isolar ${alert.ip} via FortiGate\n2. Coletar evidencias FortiEDR\n3. Analisar logs FortiAnalyzer\n4. Correlacionar IOCs FortiGuard\n5. Notificar analista responsavel\n6. Gerar relatorio compliance`;
      document.getElementById('jmAiAnalysis').textContent = `Atividade ${alert.tactic} confirmada em ${alert.ip} (${getCountryName(alert.country)}). MITRE ${alert.mitre} correlacionado. Acao imediata: contencao e analise forense.`;
    }
    document.getElementById('aiTyping').innerHTML='<span style="color:#b45309">IA offline — preenchimento local aplicado</span>';
  }
  chips.querySelectorAll('.ai-chip').forEach(c=>c.classList.remove('loading'));
}

function typewriterEffect(elId, text) {
  const el = document.getElementById(elId); el.textContent='';
  let i=0;
  const timer = setInterval(()=>{ el.textContent+=text[i]; i++; if(i>=text.length) clearInterval(timer); },18);
}

async function submitJiraTicket() {
  const title = document.getElementById('jmTitleInput').value.trim();
  if (!title) { alert('Preencha o titulo do ticket.'); return; }
  const btn = document.getElementById('jmSubmitBtn');
  const label = document.getElementById('jmSubmitLabel');
  btn.disabled=true; label.innerHTML='<span class="spin"></span> Salvando...';
  const escalateTo = document.getElementById('jmEscalateTo').value;
  const escalationReason = document.getElementById('jmEscalationReason').value;
  const ticketData = {
    id: editingTicketId || `SPARK-${String(jiraTickets.length+1).padStart(3,'0')}`,
    title, status: document.getElementById('jmStatus').value,
    priority: document.getElementById('jmPriority').value,
    type: document.getElementById('jmType').value,
    assignee: document.getElementById('jmAssignee').value,
    incidentLink: document.getElementById('jmIncLink').value,
    mitre: document.getElementById('jmMitre').value,
    ip: document.getElementById('jmIp').value,
    country: window._aiCountry || (editingTicketId?(jiraTickets.find(t=>t.id===editingTicketId)||{}).country:'') || '',
    ipBlocked: editingTicketId ? (jiraTickets.find(t=>t.id===editingTicketId)||{}).ipBlocked||false : false,
    escalatedTo: escalateTo,
    escalationReason: escalationReason,
    desc: document.getElementById('jmDesc').value,
    playbook: document.getElementById('jmPlaybook').value,
    aiAnalysis: document.getElementById('jmAiAnalysis').textContent,
    aiGenerated:true,
    created: new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'})+' UTC',
  };
  // Push escalation to log if set
  if (escalateTo) {
    const existingEsc = escalationLog.find(e => e.ticket===ticketData.id);
    if (!existingEsc) {
      escalationLog.unshift({ticket:ticketData.id, incident:ticketData.incidentLink||'—', to:escalateTo, reason:escalationReason||'—', time:ticketData.created, status:'Aguardando'});
    } else {
      existingEsc.to=escalateTo; existingEsc.reason=escalationReason||'—'; existingEsc.status='Aguardando';
    }
  }
  // Try Jira API
  if (jiraConfig.url && jiraConfig.token) {
    try {
      const creds=btoa(`${jiraConfig.email}:${jiraConfig.token}`);
      const body={fields:{project:{key:jiraConfig.project||'SPARK'},summary:ticketData.title,description:{type:'doc',version:1,content:[{type:'paragraph',content:[{type:'text',text:ticketData.desc||ticketData.title}]}]},issuetype:{name:ticketData.type==='incident'?'Bug':'Task'},priority:{name:{p1:'Highest',p2:'High',p3:'Medium',p4:'Low'}[ticketData.priority]||'Medium'}}};
      const resp=await fetch(`${jiraConfig.url}/rest/api/3/issue`,{method:'POST',headers:{'Authorization':`Basic ${creds}`,'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(body)});
      if(resp.ok){const jr=await resp.json(); ticketData.id=jr.key; ticketData.aiGenerated=false;}
    } catch(e){}
  }
  if (editingTicketId) { const idx=jiraTickets.findIndex(t=>t.id===editingTicketId); if(idx>=0) jiraTickets[idx]=ticketData; }
  else { jiraTickets.unshift(ticketData); aiTicketCount++; }
  renderBoard(); updateJiraStats(); renderIpBlockLog(); renderEscalationLog();
  closeJiraModal();
  btn.disabled=false; label.textContent=editingTicketId?'Atualizar no SOC':'Criar no SOC';
  const countryStr = ticketData.country ? ` · ${countryCodeToFlag(ticketData.country)} ${getCountryName(ticketData.country)}` : '';
  const escStr = escalateTo ? ` · Escalonado para: ${escalateTo}` : '';
  document.getElementById('jiraAiBox').innerHTML=`<strong>Ticket salvo:</strong> ${ticketData.id} — "${ticketData.title}"${countryStr}${escStr}.`;
}

document.getElementById('jiraOverlay').addEventListener('click',function(e){if(e.target===this)closeJiraModal();});
initJira();


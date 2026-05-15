(function () {
  const h = React.createElement;
  const C = window.SparkComponents;
  const L = window.SparkLayout;
  const api = window.SparkApi;

  function ComplianceRisk() {
    const [range, setRange] = React.useState('7d');
    const live = window.SparkHooks.useLiveData(() => api.compliance.getComplianceRisk(range), {interval: 60000, deps: [range]});
    const payload = live.data || {};
    const modules = payload.modules || {};
    const rows = [
      ['FortiGate containment', 'T1562 / T1071', 'Respond', 'Technical safeguards', 'A.5/A.8 evidence', 'FortiGate API + SPARK evidence', modules.fortigate ? 'Evidence Collected' : 'Partially Covered'],
      ['Endpoint monitoring', 'Multiple', 'Detect', 'Security monitoring', 'A.8 logging', 'Wazuh agent/indexer', payload.agents?.active ? 'Evidence Collected' : 'Requires Review'],
      ['File integrity / SCA', 'T1036', 'Protect', 'Control validation', 'A.8 configuration', 'Wazuh SCA/FIM', modules.sca || modules.fim ? 'Evidence Collected' : 'Not Covered'],
    ];
    return h(L.PageContainer, {
      title: 'Compliance / Risk',
      subtitle: 'Auditable technical evidence mapped to security controls.',
      actions: h('div', {className: 'tsel'}, ['24h', '7d', '30d'].map(item => h('span', {key: item, className: item === range ? 'active' : '', onClick: () => setRange(item)}, item))),
    },
      live.loading ? h(C.LoadingState, {title: 'Loading evidence coverage'}) : null,
      live.error ? h(C.ErrorState, {detail: live.error.message}) : null,
      h('div', {className: 'g4'},
        h(C.MetricCard, {label: 'Findings', value: payload.total_findings || 0, detail: `${payload.returned || 0} returned`}),
        h(C.MetricCard, {label: 'Agents Active', value: payload.agents?.active || 0, detail: `${payload.agents?.total || 0} monitored`}),
        h(C.MetricCard, {label: 'Evidence Sources', value: Object.values(modules).filter(Boolean).length, detail: 'Wazuh modules with data'}),
        h(C.MetricCard, {label: 'Status', value: payload.source || 'partial', detail: Object.keys(payload.errors || {}).join(', ') || 'Live evidence'})
      ),
      h(window.SparkCompliance.ComplianceEvidenceTable, {rows}),
      h('div', {className: 'card table-scroll'},
        h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Recent Evidence Findings'), h('div', {className: 'cs'}, 'Raw technical evidence requiring analyst/auditor review'))),
        h('table', {className: 'ftable'},
          h('thead', null, h('tr', null, ['Time', 'Module', 'Rule', 'Agent', 'Level'].map(col => h('th', {key: col}, col)))),
          h('tbody', null, (payload.findings || []).slice(0, 25).map(item => h('tr', {key: item.document_id || `${item.rule_id}-${item.timestamp}`},
            h('td', {className: 'mono'}, item.timestamp || '-'),
            h('td', null, item.module || item.decoder_name || '-'),
            h('td', null, item.description || item.rule_id || '-'),
            h('td', null, item.agent_name || '-'),
            h('td', null, h(C.StatusBadge, {status: item.level || item.severity || 'review'}))
          )))
        )
      )
    );
  }

  window.SparkPages = window.SparkPages || {};
  window.SparkPages.ComplianceRisk = ComplianceRisk;
})();

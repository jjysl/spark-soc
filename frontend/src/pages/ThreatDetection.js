(function () {
  const h = React.createElement;
  const C = window.SparkComponents;
  const L = window.SparkLayout;
  const api = window.SparkApi;

  function ThreatDetection() {
    const [range, setRange] = React.useState('24h');
    const live = window.SparkHooks.useLiveData(() => api.integrations.getThreatDetection(range), {interval: 45000, deps: [range]});
    const payload = live.data || {};
    const alerts = payload.alerts || payload.items || [];
    return h(L.PageContainer, {
      title: 'Threat Detection',
      subtitle: 'Live Wazuh alert stream with MITRE context.',
      actions: h('div', {className: 'tsel'}, ['1h', '6h', '24h', '7d'].map(item => h('span', {key: item, className: item === range ? 'active' : '', onClick: () => setRange(item)}, item))),
    },
      live.loading ? h(C.LoadingState, {title: 'Loading threat telemetry'}) : null,
      live.error ? h(C.ErrorState, {detail: live.error.message}) : null,
      h('div', {className: 'g4'},
        h(C.MetricCard, {label: 'Alerts', value: payload.total || alerts.length || 0, detail: `Range ${range}`}),
        h(C.MetricCard, {label: 'P1', value: payload.counts?.p1 || payload.p1 || 0, detail: 'Critical severity'}),
        h(C.MetricCard, {label: 'P2', value: payload.counts?.p2 || payload.p2 || 0, detail: 'High severity'}),
        h(C.MetricCard, {label: 'Source', value: payload.source || 'live', detail: payload.error || 'Indexer telemetry'})
      ),
      h('div', {className: 'card table-scroll'},
        h('table', {className: 'ftable'},
          h('thead', null, h('tr', null, ['Time', 'Severity', 'Description', 'Agent', 'Source IP', 'MITRE'].map(col => h('th', {key: col}, col)))),
          h('tbody', null, alerts.slice(0, 30).map(item => h('tr', {key: item.document_id || `${item.rule_id}-${item.timestamp}`},
            h('td', {className: 'mono'}, item.timestamp || '-'),
            h('td', null, h(C.StatusBadge, {status: item.priority || item.severity || item.level || 'info'})),
            h('td', null, item.description || item.title || 'Wazuh alert'),
            h('td', null, item.agent_name || 'unknown'),
            h('td', {className: 'mono'}, item.src_ip || '-'),
            h('td', null, item.mitre_technique || item.mitre_tactic || '-')
          )))
        )
      )
    );
  }

  window.SparkPages = window.SparkPages || {};
  window.SparkPages.ThreatDetection = ThreatDetection;
})();

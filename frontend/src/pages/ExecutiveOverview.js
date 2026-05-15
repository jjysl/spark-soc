(function () {
  const h = React.createElement;
  const {useLiveData} = window.SparkHooks;
  const C = window.SparkComponents;
  const L = window.SparkLayout;
  const api = window.SparkApi;

  function ExecutiveOverview() {
    const [range, setRange] = React.useState('24h');
    const live = useLiveData(() => api.integrations.getExecutiveOverview(range), {interval: 45000, deps: [range]});
    const data = live.data || {};
    const kpis = data.kpis || {};
    const errors = data.errors || {};
    const cards = [
      ['Critical Incidents', kpis.critical_incidents || 0, 'P1 alerts promoted into SOC workqueue', true],
      ['Events', kpis.events || 0, `Range ${data.range || range}`],
      ['Assets', kpis.monitored_assets || 0, `${kpis.assets_alerting || 0} require review`],
      ['SLA', kpis.sla_compliance ?? 'N/A', kpis.sla_detail || 'Escalation policy coverage'],
    ];
    return h(L.PageContainer, {
      title: 'Executive Overview',
      subtitle: data.triage || 'Live posture from Wazuh, FortiGate and Shuffle.',
      actions: h(RangeControl, {range, setRange, onRefresh: live.refresh}),
    },
      live.loading && !data.kpis ? h(C.LoadingState, {title: 'Loading executive posture'}) : null,
      live.error ? h(C.ErrorState, {detail: live.error.message}) : null,
      h('div', {className: 'krow'},
        cards.map(card => h(C.MetricCard, {key: card[0], label: card[0], value: card[1], detail: card[2], critical: card[3]}))
      ),
      h('div', {className: 'g11'},
        h('div', {className: 'card'},
          h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Integration Health'), h('div', {className: 'cs'}, 'Runtime services used by the dashboard'))),
          h('div', {className: 'cb health-grid'},
            h(window.SparkIntegrations.IntegrationHealthCard, {name: 'Wazuh Indexer', status: errors.wazuh_indexer ? 'offline' : 'online', detail: errors.wazuh_indexer || `${kpis.events || 0} events`}),
            h(window.SparkIntegrations.IntegrationHealthCard, {name: 'Wazuh Manager', status: errors.wazuh_api ? 'offline' : 'online', detail: errors.wazuh_api || `${kpis.monitored_assets || 0} assets`}),
            h(window.SparkIntegrations.IntegrationHealthCard, {name: 'FortiGate', status: errors.fortigate ? 'offline' : 'online', detail: errors.fortigate || `${data.fortigate?.sessions || 0} sessions`}),
            h(window.SparkIntegrations.IntegrationHealthCard, {name: 'Shuffle', status: errors.shuffle ? 'offline' : 'online', detail: errors.shuffle || 'SOAR reachable'})
          )
        ),
        h('div', {className: 'card'},
          h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Workqueue'), h('div', {className: 'cs'}, 'Recent promoted cases'))),
          h('div', {className: 'cb stack'},
            (data.workqueue || []).slice(0, 6).map(item => h('div', {className: 'list-row', key: item.case_id || item.title},
              h('div', null, h('div', {className: 'row-title'}, item.title || item.description || 'Incident case'), h('div', {className: 'muted'}, item.owner || 'Unassigned')),
              h(C.StatusBadge, {status: item.priority || item.status || 'review'})
            )),
            !(data.workqueue || []).length ? h(C.EmptyState, {title: 'No active cases', detail: 'No promoted cases are pending in this range.'}) : null
          )
        )
      )
    );
  }

  function RangeControl({range, setRange, onRefresh}) {
    return h(React.Fragment, null,
      h('div', {className: 'tsel'}, ['1h', '6h', '24h', '7d', '30d'].map(item => h('span', {key: item, className: item === range ? 'active' : '', onClick: () => setRange(item)}, item))),
      h('button', {className: 'btn', onClick: onRefresh}, 'Refresh')
    );
  }

  window.SparkPages = window.SparkPages || {};
  window.SparkPages.ExecutiveOverview = ExecutiveOverview;
})();

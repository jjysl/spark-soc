(function () {
  const h = React.createElement;
  const C = window.SparkComponents;
  const L = window.SparkLayout;
  const api = window.SparkApi;

  function NetworkEndpoint() {
    const live = window.SparkHooks.useLiveData(() => api.integrations.getNetworkEndpoint(), {interval: 60000});
    const payload = live.data || {};
    const agents = payload.agents?.agents || payload.agents || [];
    const interfaces = payload.fortigate?.interfaces || [];
    return h(L.PageContainer, {title: 'Network / Endpoint', subtitle: 'Agent posture and FortiGate network context.', actions: h('button', {className: 'btn', onClick: live.refresh}, 'Refresh')},
      live.loading ? h(C.LoadingState, {title: 'Loading network telemetry'}) : null,
      live.error ? h(C.ErrorState, {detail: live.error.message}) : null,
      h('div', {className: 'g4'},
        h(C.MetricCard, {label: 'Agents', value: payload.agents?.total || agents.length || 0, detail: `${payload.agents?.active || 0} active`}),
        h(C.MetricCard, {label: 'Disconnected', value: payload.agents?.disconnected || 0, detail: 'Require review'}),
        h(C.MetricCard, {label: 'FortiGate', value: payload.fortigate?.source || 'unknown', detail: payload.fortigate?.error || 'Monitor API'}),
        h(C.MetricCard, {label: 'Interfaces', value: interfaces.length || 0, detail: 'FortiGate table'})
      ),
      h('div', {className: 'g11'},
        h('div', {className: 'card table-scroll'},
          h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Wazuh Agents'), h('div', {className: 'cs'}, 'Endpoint visibility'))),
          h('table', {className: 'ftable'},
            h('thead', null, h('tr', null, ['Name', 'IP', 'Status', 'OS'].map(col => h('th', {key: col}, col)))),
            h('tbody', null, agents.slice(0, 20).map(item => h('tr', {key: item.id || item.name || item.ip},
              h('td', null, item.name || item.id || 'agent'),
              h('td', {className: 'mono'}, item.ip || '-'),
              h('td', null, h(C.StatusBadge, {status: item.status || 'unknown'})),
              h('td', null, item.os || item.os_name || '-')
            )))
          )
        ),
        h('div', {className: 'card table-scroll'},
          h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'FortiGate Interfaces'), h('div', {className: 'cs'}, 'API-visible network surfaces'))),
          h('table', {className: 'ftable'},
            h('thead', null, h('tr', null, ['Name', 'IP', 'Status', 'Role'].map(col => h('th', {key: col}, col)))),
            h('tbody', null, interfaces.slice(0, 20).map(item => h('tr', {key: item.name || item.interface},
              h('td', null, item.name || item.interface || '-'),
              h('td', {className: 'mono'}, item.ip || item.address || '-'),
              h('td', null, h(C.StatusBadge, {status: item.status || 'unknown'})),
              h('td', null, item.role || item.type || '-')
            )))
          )
        )
      )
    );
  }

  window.SparkPages = window.SparkPages || {};
  window.SparkPages.NetworkEndpoint = NetworkEndpoint;
})();

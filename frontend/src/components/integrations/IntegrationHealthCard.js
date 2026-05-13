(function () {
  const h = React.createElement;

  function IntegrationHealthCard({name, status, endpoint, detail, checkedAt}) {
    const ok = ['online', 'success', 'connected', 'live'].includes(String(status || '').toLowerCase());
    return h('div', {className: 'card integration-health-card'},
      h('div', {className: 'ch'},
        h('div', null, h('div', {className: 'ct'}, name), h('div', {className: 'cs'}, endpoint || 'Endpoint not configured')),
        h(window.SparkComponents.StatusBadge, {status: ok ? 'online' : status || 'offline'})
      ),
      h('div', {className: 'cb'},
        h('div', {className: 'apirow'}, h('span', {className: `adot ${ok ? 'ok' : 'warn'}`}), h('span', null, detail || 'Waiting for telemetry')),
        checkedAt ? h('div', {className: 'empty-detail'}, `Last check: ${checkedAt}`) : null
      )
    );
  }

  window.SparkIntegrations = window.SparkIntegrations || {};
  window.SparkIntegrations.IntegrationHealthCard = IntegrationHealthCard;
})();

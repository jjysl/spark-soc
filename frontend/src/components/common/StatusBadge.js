(function () {
  const h = React.createElement;
  const classes = {
    online: 'blive',
    success: 'blive',
    blocked: 'bcrit',
    unblocked: 'binfo',
    degraded: 'bmed',
    offline: 'bhigh',
    error: 'bcrit',
    failed: 'bcrit',
    not_configured: 'binfo',
    critical: 'bp1',
    high: 'bp2',
    medium: 'bp3',
    low: 'bp4',
  };

  function StatusBadge({status, label}) {
    const key = String(status || '').toLowerCase();
    const display = label || (key === 'not_configured' ? 'Connector not configured' : status) || 'unknown';
    return h('span', {className: `badge ${classes[key] || 'binfo'}`}, display);
  }

  function SourceChip({label, ok, status}) {
    return h('span', {className: `source-chip ${ok ? 'ok' : 'warn'}`},
      h('span', {className: 'source-dot'}),
      `${label} ${status || (ok ? 'Online' : 'Offline')}`
    );
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.StatusBadge = StatusBadge;
  window.SparkComponents.SourceChip = SourceChip;
})();

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
    p1: 'bp1',
    high: 'bp2',
    p2: 'bp2',
    medium: 'bp3',
    p3: 'bp3',
    low: 'bp4',
    p4: 'bp4',
    active: 'bok',
    open: 'bnew',
    closed: 'bclose',
    review: 'bmed',
  };

  function StatusBadge({status, label}) {
    const key = String(status || '').toLowerCase();
    return h('span', {className: `badge ${classes[key] || 'binfo'}`}, label || status || 'unknown');
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

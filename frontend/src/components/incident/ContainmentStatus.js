(function () {
  const h = React.createElement;

  function ContainmentStatus({evidence}) {
    const StatusBadge = window.SparkComponents.StatusBadge;
    return h('div', {className: 'containment-status'},
      h(StatusBadge, {status: evidence?.status || 'not_configured', label: evidence?.status || 'No containment action'}),
      evidence?.object_name ? h('span', {className: 'mono'}, evidence.object_name) : null
    );
  }

  window.SparkIncident = window.SparkIncident || {};
  window.SparkIncident.ContainmentStatus = ContainmentStatus;
})();

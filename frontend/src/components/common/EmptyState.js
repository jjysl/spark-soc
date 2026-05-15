(function () {
  const h = React.createElement;

  function EmptyState({title, detail}) {
    return h('div', {className: 'card state-card'},
      h('div', {className: 'state-title'}, title || 'No data'),
      detail ? h('div', {className: 'state-detail'}, detail) : null
    );
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.EmptyState = EmptyState;
})();

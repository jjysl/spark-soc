(function () {
  const h = React.createElement;

  function LoadingState({title, detail}) {
    return h('div', {className: 'card state-card state-inline'},
      h('span', {className: 'spin'}),
      h('div', null,
        h('div', {className: 'state-title'}, title || 'Loading'),
        h('div', {className: 'state-detail'}, detail || 'Collecting live telemetry.')
      )
    );
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.LoadingState = LoadingState;
})();

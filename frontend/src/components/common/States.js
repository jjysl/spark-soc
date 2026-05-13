(function () {
  const h = React.createElement;

  function EmptyState({title, detail}) {
    return h('div', {className: 'cb empty-state'},
      h('div', {className: 'empty-title'}, title),
      h('div', {className: 'empty-detail'}, detail)
    );
  }

  function LoadingState({title, detail}) {
    return h('div', {className: 'cb loading-state'},
      h('span', {className: 'spin'}),
      h('div', null,
        h('div', {className: 'empty-title'}, title || 'Loading'),
        h('div', {className: 'empty-detail'}, detail || 'Collecting live telemetry.')
      )
    );
  }

  function ErrorState({title, detail}) {
    return h('div', {className: 'cb error-state'},
      h('div', {className: 'empty-title'}, title || 'Request failed'),
      h('div', {className: 'empty-detail'}, detail)
    );
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.EmptyState = EmptyState;
  window.SparkComponents.LoadingState = LoadingState;
  window.SparkComponents.ErrorState = ErrorState;
})();

(function () {
  const h = React.createElement;

  function ErrorState({title, detail}) {
    return h('div', {className: 'card state-card state-error'},
      h('div', {className: 'state-title'}, title || 'Request failed'),
      h('div', {className: 'state-detail'}, detail || 'Unable to load this view.')
    );
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.ErrorState = ErrorState;
})();

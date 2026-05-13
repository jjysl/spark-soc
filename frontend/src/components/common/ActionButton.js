(function () {
  const h = React.createElement;

  function ActionButton({children, loading, disabled, variant, onClick, title}) {
    return h('button', {
      className: `btn ${variant === 'primary' ? 'btnp' : ''}`,
      disabled: disabled || loading,
      onClick,
      title,
    }, loading ? h(React.Fragment, null, h('span', {className: 'spin'}), children) : children);
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.ActionButton = ActionButton;
})();

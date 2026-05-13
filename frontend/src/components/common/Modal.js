(function () {
  const h = React.createElement;

  function Modal({open, title, children, footer, onClose}) {
    if (!open) return null;
    return h('div', {className: 'modal-backdrop'},
      h('div', {className: 'modal-panel'},
        h('div', {className: 'modal-head'},
          h('div', {className: 'ct'}, title),
          h('button', {className: 'btn btnlink', onClick: onClose}, 'Close')
        ),
        h('div', {className: 'modal-body'}, children),
        footer ? h('div', {className: 'modal-footer'}, footer) : null
      )
    );
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.Modal = Modal;
})();

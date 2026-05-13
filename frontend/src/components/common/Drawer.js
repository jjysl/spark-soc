(function () {
  const h = React.createElement;

  function Drawer({open, title, children, onClose}) {
    if (!open) return null;
    return h('div', {className: 'drawer-backdrop'},
      h('aside', {className: 'drawer-panel'},
        h('div', {className: 'modal-head'},
          h('div', {className: 'ct'}, title),
          h('button', {className: 'btn btnlink', onClick: onClose}, 'Close')
        ),
        h('div', {className: 'modal-body'}, children)
      )
    );
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.Drawer = Drawer;
})();

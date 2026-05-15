(function () {
  const h = React.createElement;
  function PageSection({title, subtitle, children, actions}) {
    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null, h('div', {className: 'ptitle'}, title), subtitle ? h('div', {className: 'psub'}, subtitle) : null),
        actions ? h('div', {className: 'ha'}, actions) : null
      ),
      children
    );
  }
  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.PageSection = PageSection;
})();

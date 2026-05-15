(function () {
  const h = React.createElement;

  function PageContainer({title, subtitle, actions, children}) {
    return h('section', {className: 'page-container'},
      h('div', {className: 'ph'},
        h('div', null,
          h('h1', {className: 'ptitle'}, title),
          subtitle ? h('div', {className: 'psub'}, subtitle) : null
        ),
        actions ? h('div', {className: 'ha'}, actions) : null
      ),
      children
    );
  }

  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.PageContainer = PageContainer;
})();

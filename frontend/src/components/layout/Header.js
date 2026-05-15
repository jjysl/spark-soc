(function () {
  const h = React.createElement;
  function Header({user, integrations, updatedAt}) {
    const online = Object.values(integrations || {}).filter(Boolean).length;
    return h('header', {className: 'spark-product-header'},
      h('div', {className: 'spark-product-brand'},
        h('div', {className: 'bmark'}, 'S'),
        h('div', null,
          h('div', {className: 'bname'}, 'SPARK SOC'),
          h('div', {className: 'bsub'}, 'NG-SOC / MDR Command Center')
        )
      ),
      h('div', {className: 'spark-product-flow'},
        ['Detect', 'Decide', 'Respond', 'Document'].map(step => h('span', {key: step}, step))
      ),
      h('div', {className: 'spark-product-session'},
        h('span', {className: 'badge blive'}, `${online || 0} integrations online`),
        h('span', {className: 'mts'}, updatedAt || '--:--:-- BRT'),
        h('span', {className: 'av'}, user?.avatar || 'SC')
      )
    );
  }
  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.Header = Header;
})();

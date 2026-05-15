(function () {
  const h = React.createElement;
  function SidebarOrTabs({items, active, onNavigate}) {
    return h('nav', {className: 'spark-product-nav'},
      (items || []).map(([id, label]) => h('button', {
        key: id,
        className: active === id ? 'active' : '',
        onClick: () => onNavigate && onNavigate(id),
      }, label))
    );
  }
  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.SidebarOrTabs = SidebarOrTabs;
})();

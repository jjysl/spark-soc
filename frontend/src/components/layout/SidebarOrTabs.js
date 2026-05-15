(function () {
  const h = React.createElement;

  function SidebarOrTabs({items, activePage, onNavigate}) {
    return h('nav', {className: 'tabbar app-tabs'},
      items.map(item => h('button', {
        key: item.id,
        className: `tbtn ${activePage === item.id ? 'active' : ''}`,
        onClick: () => onNavigate(item.id),
        'data-page': item.id,
      }, item.label))
    );
  }

  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.SidebarOrTabs = SidebarOrTabs;
})();

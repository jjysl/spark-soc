(function () {
  const h = React.createElement;
  const NAV_ITEMS = [
    {id: 'executive', label: 'Executive Overview'},
    {id: 'incident', label: 'Incident Response'},
    {id: 'cases', label: 'Cases'},
    {id: 'threat', label: 'Threat Detection'},
    {id: 'network', label: 'Network / Endpoint'},
    {id: 'compliance', label: 'Compliance / Risk'},
  ];

  function AppShell({activePage, onNavigate, user, clock, children, onLogout}) {
    const Header = window.SparkLayout.Header;
    const SidebarOrTabs = window.SparkLayout.SidebarOrTabs;
    return h('div', {className: 'app-shell'},
      h(Header, {user, clock, onLogout}),
      h(SidebarOrTabs, {items: NAV_ITEMS, activePage, onNavigate}),
      h('main', {className: 'main page-main'}, children)
    );
  }

  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.AppShell = AppShell;
  window.SparkLayout.NAV_ITEMS = NAV_ITEMS;
})();

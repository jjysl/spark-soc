(function () {
  const h = React.createElement;
  const NAV_ITEMS = [
    ['exec', 'Executive Overview'],
    ['ir', 'Incident Response'],
    ['network', 'Network / Endpoint'],
    ['compliance', 'Compliance / Risk'],
    ['jira', 'Cases'],
    ['threat', 'Threat Detection'],
  ];

  function AppShell({children, active = 'exec', onNavigate, user, integrations, updatedAt}) {
    return h('div', {className: 'spark-app-shell'},
      h(window.SparkLayout.Header, {user, integrations, updatedAt}),
      h('div', {className: 'spark-shell-body'},
        h(window.SparkLayout.SidebarOrTabs, {items: NAV_ITEMS, active, onNavigate}),
        h('main', {className: 'spark-shell-main'}, children)
      )
    );
  }
  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.AppShell = AppShell;
  window.SparkLayout.NAV_ITEMS = NAV_ITEMS;
})();

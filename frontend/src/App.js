(function () {
  const h = React.createElement;
  const api = window.SparkApi;
  const C = window.SparkComponents;
  const L = window.SparkLayout;
  const P = window.SparkPages;

  function App() {
    const [activePage, setActivePage] = React.useState(window.location.hash.replace('#', '') || 'executive');
    const [user, setUser] = React.useState(null);
    const [clock, setClock] = React.useState('');

    React.useEffect(() => {
      api.auth.me().then(setUser).catch(() => { window.location.href = '/login'; });
    }, []);

    React.useEffect(() => {
      function tick() {
        setClock(`${new Date().toUTCString().split(' ')[4]} UTC`);
      }
      tick();
      const id = setInterval(tick, 1000);
      return () => clearInterval(id);
    }, []);

    React.useEffect(() => {
      window.location.hash = activePage;
    }, [activePage]);

    async function logout() {
      await api.auth.logout().catch(() => null);
      window.location.href = '/login';
    }

    const pages = {
      executive: P.ExecutiveOverview,
      incident: P.IncidentResponse,
      cases: P.Cases,
      threat: P.ThreatDetection,
      network: P.NetworkEndpoint,
      compliance: P.ComplianceRisk,
    };
    const Page = pages[activePage] || P.ExecutiveOverview;

    return h(C.ToastProvider, null,
      h(L.AppShell, {activePage, onNavigate: setActivePage, user, clock, onLogout: logout},
        h(Page)
      )
    );
  }

  window.SparkApp = window.SparkApp || {};
  window.SparkApp.App = App;
})();

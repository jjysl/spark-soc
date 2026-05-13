(function () {
  function AppShell({children}) {
    return React.createElement(React.Fragment, null, children);
  }
  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.AppShell = AppShell;
})();

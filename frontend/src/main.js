(function () {
  const root = document.getElementById('root');
  if (!root) throw new Error('SPARK root element not found');
  ReactDOM.createRoot(root).render(React.createElement(window.SparkApp.App));
})();

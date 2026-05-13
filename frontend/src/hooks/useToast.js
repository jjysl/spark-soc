(function () {
  function useToast() {
    const ctx = React.useContext(window.SparkComponents.ToastContext);
    return ctx || {pushToast: () => {}, removeToast: () => {}};
  }

  window.SparkHooks = window.SparkHooks || {};
  window.SparkHooks.useToast = useToast;
})();

(function () {
  const h = React.createElement;
  const ToastContext = React.createContext(null);

  function ToastProvider({children}) {
    const [toasts, setToasts] = React.useState([]);
    const removeToast = id => setToasts(items => items.filter(item => item.id !== id));
    const pushToast = toast => {
      const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const item = {id, tone: 'info', ...toast};
      setToasts(items => [item, ...items].slice(0, 4));
      setTimeout(() => removeToast(id), item.timeout || 5200);
      return id;
    };

    return h(ToastContext.Provider, {value: {pushToast, removeToast}},
      children,
      h('div', {className: 'toast-stack'},
        toasts.map(item => h('div', {key: item.id, className: `toast toast-${item.tone}`},
          h('div', {className: 'toast-title'}, item.title || 'SPARK SOC'),
          item.message ? h('div', {className: 'toast-message'}, item.message) : null,
          h('button', {className: 'toast-close', onClick: () => removeToast(item.id)}, 'x')
        ))
      )
    );
  }

  window.SparkComponents = window.SparkComponents || {};
  window.SparkComponents.ToastContext = ToastContext;
  window.SparkComponents.ToastProvider = ToastProvider;
})();

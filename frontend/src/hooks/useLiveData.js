(function () {
  function useLiveData(fetcher, options) {
    const opts = options || {};
    const [data, setData] = React.useState(opts.initialData || null);
    const [error, setError] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    const [updatedAt, setUpdatedAt] = React.useState(null);

    const load = React.useCallback(async () => {
      setLoading(true);
      try {
        const payload = await fetcher();
        setData(payload);
        setUpdatedAt(new Date());
        setError('');
        return payload;
      } catch (err) {
        setError(err.message || 'Request failed');
        if (opts.fallbackData) setData(typeof opts.fallbackData === 'function' ? opts.fallbackData(err) : opts.fallbackData);
        throw err;
      } finally {
        setLoading(false);
      }
    }, [fetcher]);

    React.useEffect(() => {
      let disposed = false;
      load().catch(() => {});
      const interval = opts.interval || 30000;
      if (!interval) return () => { disposed = true; };
      const timer = setInterval(() => {
        if (!disposed && (!opts.pauseWhenHidden || !document.hidden)) load().catch(() => {});
      }, interval);
      return () => {
        disposed = true;
        clearInterval(timer);
      };
    }, [load, opts.interval, opts.pauseWhenHidden]);

    return {data, error, loading, updatedAt, refresh: load, setData};
  }

  window.SparkHooks = window.SparkHooks || {};
  window.SparkHooks.useLiveData = useLiveData;
})();

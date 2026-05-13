(function () {
  function useAsyncAction(action) {
    const [state, setState] = React.useState({status: 'idle', data: null, error: ''});

    async function run(...args) {
      setState({status: 'loading', data: null, error: ''});
      try {
        const data = await action(...args);
        setState({status: 'success', data, error: ''});
        return data;
      } catch (err) {
        setState({status: 'error', data: null, error: err.message || 'Action failed'});
        throw err;
      }
    }

    function reset() {
      setState({status: 'idle', data: null, error: ''});
    }

    return {run, reset, ...state, loading: state.status === 'loading'};
  }

  window.SparkHooks = window.SparkHooks || {};
  window.SparkHooks.useAsyncAction = useAsyncAction;
})();

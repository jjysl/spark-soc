(function () {
  async function request(path, options) {
    const response = await fetch(path, {
      credentials: 'include',
      headers: {'Content-Type': 'application/json', ...(options && options.headers ? options.headers : {})},
      ...options,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = payload.message || payload.error || `HTTP ${response.status}`;
      const error = new Error(message);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  function get(path) {
    return request(path, {method: 'GET'});
  }

  function post(path, body) {
    return request(path, {method: 'POST', body: JSON.stringify(body || {})});
  }

  function put(path, body) {
    return request(path, {method: 'PUT', body: JSON.stringify(body || {})});
  }

  window.SparkApi = window.SparkApi || {};
  window.SparkApi.client = {request, get, post, put};
})();

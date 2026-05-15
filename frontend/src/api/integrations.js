(function () {
  const client = window.SparkApi.client;

  window.SparkApi.integrations = {
    getExecutiveOverview: (range, refresh) => client.get(`/spark/executive-overview?range=${encodeURIComponent(range || '24h')}${refresh ? '&refresh=1' : ''}`),
    getThreatDetection: params => client.get(`/spark/threat-detection?${params instanceof URLSearchParams ? params.toString() : String(params || '')}`),
    getNetworkEndpoint: () => client.get('/spark/network-endpoint'),
    getAiStatus: () => client.get('/spark/ai/status'),
    getJiraStatus: () => client.get('/spark/jira/status'),
  };
})();

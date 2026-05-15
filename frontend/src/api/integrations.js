(function () {
  const client = window.SparkApi.client;

  window.SparkApi.integrations = {
    getExecutiveOverview: (range, refresh) => client.get(`/spark/executive-overview?range=${encodeURIComponent(range || '24h')}${refresh ? '&refresh=1' : ''}`),
    getNetworkEndpoint: () => client.get('/spark/network-endpoint'),
    getAiStatus: () => client.get('/spark/ai/status'),
    getJiraStatus: () => client.get('/spark/jira/status'),
  };
})();

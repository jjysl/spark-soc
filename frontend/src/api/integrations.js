(function () {
  const client = window.SparkApi.client;

  window.SparkApi.integrations = {
    getExecutiveOverview: (range, refresh) => client.get(`/spark/executive-overview?range=${encodeURIComponent(range || '24h')}${refresh ? '&refresh=1' : ''}`),
    getThreatDetection: (range, severity, techniques) => {
      const params = new URLSearchParams({range: range || '24h'});
      if (severity) params.set('severity', severity);
      (techniques || []).forEach(item => params.append('technique', item));
      return client.get(`/spark/threat-detection?${params.toString()}`);
    },
    getNetworkEndpoint: () => client.get('/spark/network-endpoint'),
    getAiStatus: () => client.get('/spark/ai/status'),
    getJiraStatus: () => client.get('/spark/jira/status'),
  };
})();

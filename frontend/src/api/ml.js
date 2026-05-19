(function () {
  const client = window.SparkApi.client;

  window.SparkApi.ml = {
    getStatus: () => client.get('/spark/ml/status'),
    getInsights: limit => client.get(`/spark/ml/insights?limit=${encodeURIComponent(limit || 25)}`),
    scoreIncident: payload => client.post('/spark/ml/score-incident', payload),
    exportJsonUrl: '/spark/ml/export?format=json',
    exportCsvUrl: '/spark/ml/export?format=csv',
  };
})();

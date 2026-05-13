(function () {
  const client = window.SparkApi.client;

  window.SparkApi.incidents = {
    getIncidentResponse: range => client.get(`/spark/incident-response?range=${encodeURIComponent(range || '24h')}`),
    createCase: payload => client.post('/spark/incident-cases', payload),
    runCaseAction: (caseId, payload) => client.post(`/spark/incident-cases/${encodeURIComponent(caseId)}/action`, payload),
    listCases: () => client.get('/spark/incident-cases'),
    listActions: (limit = 25) => client.get(`/spark/action-events?limit=${encodeURIComponent(limit)}`),
  };
})();

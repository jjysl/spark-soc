(function () {
  const client = window.SparkApi.client;

  window.SparkApi.incidents = {
    getIncidentResponse: range => client.get(`/spark/incident-response?range=${encodeURIComponent(range || '24h')}`),
    createCase: payload => client.post('/spark/incident-cases', payload),
    runCaseAction: (caseId, payload) => client.post(`/spark/incident-cases/${encodeURIComponent(caseId)}/action`, payload),
    listCases: () => client.get('/spark/incident-cases'),
    listActions: (limit = 25) => client.get(`/spark/action-events?limit=${encodeURIComponent(limit)}`),
    listActionsForCase: (caseId, limit = 25) => client.get(`/spark/action-events?limit=${encodeURIComponent(limit)}&case_id=${encodeURIComponent(caseId || '')}`),
    getFortiAnalyzerEvidence: (ip, limit = 10) => client.get(`/spark/fortianalyzer/evidence?ip=${encodeURIComponent(ip || '')}&limit=${encodeURIComponent(limit)}`),
    getRecommendation: payload => client.post('/spark/response/recommendation', payload),
    executeRecommendation: payload => client.post('/spark/response/execute', payload),
    dispatchSoarEvidence: payload => client.post('/spark/soar/dispatch-evidence', payload),
    notifyAnalyst: payload => client.post('/spark/soar/notify-analyst', payload),
    enrichIoc: payload => client.post('/spark/soar/enrich-ioc', payload),
    getAiStatus: () => client.get('/spark/ai/status'),
    generateIncidentBriefing: payload => client.post('/spark/ai/incident-briefing', payload),
  };
})();

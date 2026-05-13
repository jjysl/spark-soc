(function () {
  const client = window.SparkApi.client;

  window.SparkApi.compliance = {
    getComplianceRisk: range => client.get(`/spark/compliance-risk?range=${encodeURIComponent(range || '7d')}`),
  };
})();

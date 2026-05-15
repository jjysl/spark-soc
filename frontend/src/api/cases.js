(function () {
  const client = window.SparkApi.client;

  window.SparkApi.cases = {
    getDashboardData: () => Promise.all([
      client.get('/spark/tickets').catch(() => []),
      client.get('/spark/ip-block-log').catch(() => []),
      client.get('/spark/action-events?limit=20').catch(() => []),
      client.get('/spark/escalation-log').catch(() => []),
      client.get('/spark/jira/status').catch(err => ({configured: false, connected: false, message: err.message})),
    ]),
    saveTicket: (ticket, editing) => {
      const path = editing?.id ? `/spark/tickets/${encodeURIComponent(editing.id)}` : '/spark/tickets';
      return client.request(path, {method: editing?.id ? 'PUT' : 'POST', body: JSON.stringify(ticket)});
    },
    blockIp: payload => client.post('/spark/fortigate/block-ip', payload),
    escalate: payload => client.post('/spark/escalate', payload),
    createJiraIssue: ticketId => client.post(`/spark/tickets/${encodeURIComponent(ticketId)}/jira`, {}),
  };
})();

(function () {
  const client = window.SparkApi.client;

  window.SparkApi.fortigate = {
    getStatus: () => client.get('/spark/fortigate-status'),
    blockIp: payload => client.post('/spark/fortigate/block-ip', payload),
    unblockIp: payload => client.post('/spark/fortigate/unblock-ip', payload),
    getBlocklist: () => client.get('/spark/fortigate/blocklist'),
  };
})();

(function () {
  const h = React.createElement;
  const C = window.SparkComponents;
  const L = window.SparkLayout;
  const api = window.SparkApi;

  function IncidentResponse() {
    const toast = window.SparkHooks.useToast();
    const [range, setRange] = React.useState('24h');
    const [data, setData] = React.useState(null);
    const [blocklist, setBlocklist] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState('');
    const [busy, setBusy] = React.useState('');
    const [lastEvidence, setLastEvidence] = React.useState(null);

    async function load() {
      setLoading(true);
      try {
        const [response, fg] = await Promise.all([api.incidents.getIncidentResponse(range), api.fortigate.getBlocklist()]);
        setData(response);
        setBlocklist(fg.items || []);
        setError('');
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    React.useEffect(() => { load(); }, [range]);

    async function blockItem(item) {
      const ip = item.src_ip || item.agent_ip || item.ip;
      if (!ip) return;
      setBusy(`block:${ip}`);
      try {
        const result = await api.fortigate.blockIp({
          ip,
          reason: item.title || item.reason || 'Manual SOC containment from Incident Response',
          source: 'manual',
          severity: item.priority === 'P1' ? 'critical' : 'high',
          duration_minutes: 60,
          incident_id: item.case_id || item.document_id || item.rule_id || '',
        });
        setLastEvidence(result);
        toast.pushToast({tone: 'success', title: 'FortiGate block applied', message: `${result.ip} | evidence ${result.evidence_id || '--'}`});
        await load();
      } catch (err) {
        toast.pushToast({tone: 'error', title: 'Block failed', message: err.message});
      } finally {
        setBusy('');
      }
    }

    async function unblockItem(item) {
      const ip = item.ip;
      setBusy(`unblock:${ip}`);
      try {
        const result = await api.fortigate.unblockIp({ip, reason: 'Analyst unblock from React Incident Response'});
        setLastEvidence(result);
        toast.pushToast({tone: 'success', title: 'FortiGate unblock applied', message: ip});
        await load();
      } catch (err) {
        toast.pushToast({tone: 'error', title: 'Unblock failed', message: err.message});
      } finally {
        setBusy('');
      }
    }

    const payload = data || {};
    const candidates = payload.wazuh?.candidates || [];
    return h(L.PageContainer, {
      title: 'Incident Response',
      subtitle: 'Analyst containment, case telemetry and FortiGate evidence.',
      actions: h(React.Fragment, null,
        h('div', {className: 'tsel'}, ['1h', '6h', '24h', '7d', '30d'].map(item => h('span', {key: item, className: item === range ? 'active' : '', onClick: () => setRange(item)}, item))),
        h('button', {className: 'btn', onClick: load}, 'Refresh')
      ),
    },
      loading ? h(C.LoadingState, {title: 'Loading incident response'}) : null,
      error ? h(C.ErrorState, {detail: error}) : null,
      lastEvidence ? h(window.SparkIncident.EvidencePanel, {evidence: lastEvidence}) : null,
      h('div', {className: 'g4'},
        h(C.MetricCard, {label: 'Candidates', value: candidates.length, detail: `${payload.wazuh?.total || 0} Wazuh alerts`}),
        h(C.MetricCard, {label: 'Open Cases', value: (payload.cases || []).length, detail: 'Active SOC cases'}),
        h(C.MetricCard, {label: 'Blocklist', value: blocklist.length, detail: 'SPARK_BLOCKLIST members'}),
        h(C.MetricCard, {label: 'SOAR', value: payload.shuffle?.connected ? 'Online' : 'Offline', detail: payload.shuffle?.error || 'Shuffle status'})
      ),
      h('div', {className: 'g11'},
        h('div', {className: 'card'},
          h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Incident Candidates'), h('div', {className: 'cs'}, 'Block IP uses /spark/fortigate/block-ip'))),
          h('div', {className: 'table-scroll'}, h('table', {className: 'ftable'},
            h('thead', null, h('tr', null, ['Priority', 'Alert', 'Agent', 'Source IP', 'Action'].map(col => h('th', {key: col}, col)))),
            h('tbody', null, candidates.map(item => {
              const ip = item.src_ip || item.agent_ip || '';
              return h('tr', {key: item.document_id || `${item.rule_id}-${item.timestamp}`},
                h('td', null, h(C.StatusBadge, {status: item.priority || 'P3'})),
                h('td', null, item.title || 'Wazuh alert'),
                h('td', {className: 'mono'}, item.agent_name || 'unknown'),
                h('td', {className: 'mono'}, ip || '-'),
                h('td', null, ip ? h(C.ActionButton, {loading: busy === `block:${ip}`, onClick: () => blockItem(item)}, 'Block IP') : null)
              );
            }))
          )),
          !candidates.length ? h(C.EmptyState, {title: 'No candidates', detail: 'No eligible alerts in this range.'}) : null
        ),
        h('div', {className: 'card'},
          h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'FortiGate Blocklist'), h('div', {className: 'cs'}, 'Unblock uses /spark/fortigate/unblock-ip'))),
          h('div', {className: 'table-scroll'}, h('table', {className: 'ftable'},
            h('thead', null, h('tr', null, ['IP', 'Object', 'Reason', 'Action'].map(col => h('th', {key: col}, col)))),
            h('tbody', null, blocklist.map(item => h('tr', {key: item.ip || item.object_name},
              h('td', {className: 'mono'}, item.ip),
              h('td', {className: 'mono'}, item.object_name),
              h('td', null, item.reason || item.comment || '-'),
              h('td', null, h(C.ActionButton, {loading: busy === `unblock:${item.ip}`, onClick: () => unblockItem(item)}, 'Unblock'))
            )))
          )),
          !blocklist.length ? h(C.EmptyState, {title: 'Blocklist empty', detail: 'No FortiGate blocklist members returned.'}) : null
        )
      )
    );
  }

  window.SparkPages = window.SparkPages || {};
  window.SparkPages.IncidentResponse = IncidentResponse;
})();

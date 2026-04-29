(function () {
  const {useEffect, useMemo, useState} = React;
  const h = React.createElement;

  function fmtNum(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function sourceOk(data, key) {
    if (!data || data.source === 'loading') return false;
    if (key === 'fortigate') return data.fortigate?.source === 'fortigate-live' && !data.errors?.fortigate;
    return !data.errors?.[key];
  }

  function KpiCard({label, value, detail, critical, tone}) {
    return h('div', {className: `kpi ${critical ? 'ka' : ''}`},
      h('div', {className: 'kl'}, label),
      h('div', {className: 'kv', style: tone ? {color: `var(--${tone})`} : null}, value),
      h('div', {className: 'kd', dangerouslySetInnerHTML: {__html: detail || ''}})
    );
  }

  function SourceChip({label, ok}) {
    return h('span', {className: `source-chip ${ok ? 'ok' : 'warn'}`},
      h('span', {className: 'source-dot'}),
      `${label} ${ok ? 'Online' : 'Offline'}`
    );
  }

  function MetricTile({label, value, detail, tone}) {
    return h('div', {className: 'fstat'},
      h('div', {className: 'fsl'}, label),
      h('div', {className: 'fsv', style: tone ? {color: `var(--${tone})`} : null}, value),
      h('div', {className: 'fss'}, detail)
    );
  }

  function EmptyState({title, detail}) {
    return h('div', {className: 'cb'},
      h('div', {style: {fontSize: 12, color: 'var(--t1)', fontWeight: 600, marginBottom: 4}}, title),
      h('div', {style: {fontSize: 11, color: 'var(--tm)'}}, detail)
    );
  }

  function FortiGateMetrics({fortigate, ok}) {
    const cpu = Number(fortigate?.cpu || 0);
    const mem = Number(fortigate?.mem || 0);
    const sessions = Number(fortigate?.sessions || 0);
    const system = fortigate?.system || {};
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'FortiGate Monitor API'),
          h('div', {className: 'cs'}, '/api/v2/monitor/system/resource/usage')
        ),
        h('span', {className: `badge ${ok ? 'blive' : 'bhigh'}`}, ok ? 'Connected' : 'Unavailable')
      ),
      h('div', {className: 'cb'},
        h('div', {className: 'fgrid'},
          h(MetricTile, {label: 'CPU', value: ok ? `${cpu}%` : 'N/A', detail: ok ? 'Current utilization' : 'Waiting for FortiGate API', tone: cpu >= 80 ? 'red' : cpu >= 60 ? 'amber' : 'green'}),
          h(MetricTile, {label: 'Memory', value: ok ? `${mem}%` : 'N/A', detail: ok ? 'Current utilization' : 'Waiting for FortiGate API', tone: mem >= 80 ? 'red' : mem >= 60 ? 'amber' : 'green'}),
          h(MetricTile, {label: 'Active Sessions', value: ok ? fmtNum(sessions) : 'N/A', detail: ok ? 'Reported by resource usage endpoint' : 'Session count unavailable'}),
          h(MetricTile, {label: 'FortiOS', value: system.version || fortigate?.version || 'N/A', detail: system.serial || fortigate?.serial || 'System status endpoint'})
        )
      )
    );
  }

  function FortiGateApiEvidence({apiStatus}) {
    const rows = Object.entries(apiStatus || {});
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'FortiOS REST API Evidence'),
          h('div', {className: 'cs'}, 'Monitor APIs + CMDB APIs used by this dashboard')
        ),
        h('span', {className: 'ca'}, `${rows.filter(([, item]) => item.ok).length}/${rows.length} online`)
      ),
      rows.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['API', 'Endpoint', 'Status'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          rows.map(([key, item]) => h('tr', {key},
            h('td', null, key.replaceAll('_', ' ')),
            h('td', null, h('span', {className: 'mono'}, item.endpoint || '--')),
            h('td', null, h('span', {className: `badge ${item.ok ? 'blive' : 'bhigh'}`, title: item.error || ''}, item.ok ? 'Live' : 'Unavailable'))
          ))
        )
      ) : h(EmptyState, {title: 'No FortiOS API evidence returned', detail: 'Check the FortiGate API token and network reachability.'})
    );
  }

  function FortiGateInterfaces({interfaces}) {
    const rows = Array.isArray(interfaces) ? interfaces : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'FortiGate Interfaces'),
          h('div', {className: 'cs'}, 'Monitor system interface / CMDB system interface')
        ),
        h('span', {className: 'ca'}, `${rows.length} interfaces`)
      ),
      rows.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Name', 'IP', 'Status', 'Role', 'RX', 'TX'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          rows.slice(0, 12).map((item, idx) => h('tr', {key: `${item.name}-${idx}`},
            h('td', null, h('span', {className: 'mono'}, item.name || '--')),
            h('td', null, h('span', {className: 'mono'}, item.ip || '--')),
            h('td', null, h('span', {className: `badge ${String(item.status).toLowerCase() === 'up' || String(item.status).toLowerCase() === 'connected' ? 'blive' : 'binfo'}`}, item.status || 'unknown')),
            h('td', null, item.role || '--'),
            h('td', null, h('span', {className: 'mono'}, fmtNum(item.rx_bytes))),
            h('td', null, h('span', {className: 'mono'}, fmtNum(item.tx_bytes)))
          ))
        )
      ) : h(EmptyState, {title: 'No interface inventory returned', detail: 'The API token may not have monitor/system interface or CMDB interface permission.'})
    );
  }

  function FortiGatePolicies({policies, stats}) {
    const rows = Array.isArray(policies) ? policies : [];
    const statMap = new Map((stats || []).map(item => [String(item.policyid), item]));
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Firewall Policies'),
          h('div', {className: 'cs'}, 'CMDB firewall policy + monitor policy counters when available')
        ),
        h('span', {className: 'ca'}, `${rows.length} policies`)
      ),
      rows.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['ID', 'Name', 'Action', 'Source', 'Destination', 'Service', 'Hits'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          rows.slice(0, 12).map(policy => {
            const stat = statMap.get(String(policy.policyid)) || {};
            const hits = stat.hit_count || stat.sessions || stat.packets || 0;
            return h('tr', {key: policy.policyid || policy.name},
              h('td', null, h('span', {className: 'mono'}, policy.policyid || '--')),
              h('td', null, h('span', {className: 'edesc', title: policy.comments || policy.name}, policy.name || '--')),
              h('td', null, h('span', {className: `badge ${policy.action === 'deny' ? 'bcrit' : 'blive'}`}, policy.action || policy.status || '--')),
              h('td', null, h('span', {className: 'edesc'}, policy.srcintf || policy.srcaddr || '--')),
              h('td', null, h('span', {className: 'edesc'}, policy.dstintf || policy.dstaddr || '--')),
              h('td', null, h('span', {className: 'tpill'}, policy.service || '--')),
              h('td', null, h('span', {className: 'mono'}, fmtNum(hits)))
            );
          })
        )
      ) : h(EmptyState, {title: 'No firewall policies returned', detail: 'The CMDB firewall policy endpoint may be unavailable to this token.'})
    );
  }

  function FortiGateRoutes({routes}) {
    const rows = Array.isArray(routes) ? routes : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Static Routes'),
          h('div', {className: 'cs'}, 'CMDB router static')
        ),
        h('span', {className: 'ca'}, `${rows.length} routes`)
      ),
      rows.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Seq', 'Destination', 'Gateway', 'Device', 'Distance', 'Status'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          rows.slice(0, 10).map((route, idx) => h('tr', {key: `${route.seq_num}-${idx}`},
            h('td', null, h('span', {className: 'mono'}, route.seq_num || '--')),
            h('td', null, h('span', {className: 'mono'}, route.dst || '--')),
            h('td', null, h('span', {className: 'mono'}, route.gateway || '--')),
            h('td', null, route.device || '--'),
            h('td', null, route.distance || '--'),
            h('td', null, h('span', {className: `badge ${route.status === 'enable' ? 'blive' : 'binfo'}`}, route.status || 'unknown'))
          ))
        )
      ) : h(EmptyState, {title: 'No static routes returned', detail: 'The CMDB router/static endpoint may be unavailable or empty.'})
    );
  }

  function FortiGateCorrelation({rows}) {
    const items = Array.isArray(rows) ? rows : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Wazuh + FortiGate Correlation'),
          h('div', {className: 'cs'}, 'Wazuh alerts mapped against FortiGate interfaces, policies and SPARK block records')
        ),
        h('span', {className: 'ca'}, `${items.length} alerts`)
      ),
      items.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Time', 'Alert', 'Source', 'MITRE', 'FortiGate Signal'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          items.slice(0, 10).map((item, idx) => h('tr', {key: `${item.timestamp}-${idx}`},
            h('td', null, h('span', {className: 'mono'}, item.timestamp ? item.timestamp.substring(11, 19) : '--')),
            h('td', null, h('span', {className: 'edesc', title: item.description}, item.description || '--')),
            h('td', null, h('span', {className: 'mono'}, item.src_ip || item.agent || '--')),
            h('td', null, h('span', {className: 'tpill'}, item.mitre_tactic || 'Detection')),
            h('td', null, h('span', {className: `badge ${item.fortigate_signal === 'blocked' ? 'bcrit' : item.fortigate_signal === 'policy match' ? 'blive' : 'binfo'}`}, item.fortigate_signal || 'unmapped'))
          ))
        )
      ) : h(EmptyState, {title: 'No Wazuh alerts available for correlation', detail: 'Generate endpoint/network alerts, then refresh this page to see cross-source correlation.'})
    );
  }

  function EndpointInventory({wazuh, ok}) {
    const agents = wazuh?.agents || [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Wazuh Endpoint Inventory'),
          h('div', {className: 'cs'}, 'Manager API /agents')
        ),
        h('span', {className: `badge ${ok ? 'blive' : 'bhigh'}`}, ok ? `${fmtNum(wazuh?.total)} agents` : 'Unavailable')
      ),
      agents.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['ID', 'Name', 'IP', 'Status', 'Version'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          agents.map(agent => h('tr', {key: agent.id || agent.name},
            h('td', null, h('span', {className: 'mono'}, agent.id || '--')),
            h('td', null, h('span', {className: 'edesc'}, agent.name || 'unknown')),
            h('td', null, h('span', {className: 'mono'}, agent.ip || '--')),
            h('td', null, h('span', {className: `badge ${agent.status === 'active' ? 'blow' : agent.status === 'disconnected' ? 'bhigh' : 'bmed'}`}, agent.status || 'unknown')),
            h('td', null, h('span', {className: 'mono'}, agent.version || '--'))
          ))
        )
      ) : h(EmptyState, {
        title: ok ? 'No endpoint agents returned' : 'Wazuh Manager API unavailable',
        detail: ok ? 'Only real Wazuh agents will appear here. The manager-only lab may show zero or one manager record.' : 'Check WAZUH_BASE, WAZUH_USER and WAZUH_PASS on the lab machine.',
      })
    );
  }

  function BlockedIps({items}) {
    const rows = Array.isArray(items) ? items : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'SPARK Blocked IPs'),
          h('div', {className: 'cs'}, 'Local case records and FortiGate action log')
        ),
        h('span', {className: 'ca'}, `${rows.length} entries`)
      ),
      rows.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['IP', 'Country', 'Reason', 'Analyst', 'Time'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          rows.map((item, idx) => h('tr', {key: `${item.ip || item.src_ip}-${idx}`},
            h('td', null, h('span', {className: 'mono'}, item.ip || item.src_ip || '--')),
            h('td', null, item.country || item.country_code || '--'),
            h('td', null, h('span', {className: 'edesc'}, item.reason || '--')),
            h('td', null, item.analyst || '--'),
            h('td', null, h('span', {className: 'mono'}, item.timestamp || item.created_at || '--'))
          ))
        )
      ) : h(EmptyState, {title: 'No blocked IP records', detail: 'This list is intentionally empty until SPARK creates or imports real block actions.'})
    );
  }

  function TopologySummary({data}) {
    const fgOk = sourceOk(data, 'fortigate');
    const wzOk = sourceOk(data, 'wazuh_api');
    const agents = data?.wazuh?.agents || [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Live Source Topology'),
          h('div', {className: 'cs'}, 'Built only from configured telemetry sources')
        )
      ),
      h('div', {className: 'cb'},
        h('div', {className: 'apirow'}, h('span', {className: `adot ${fgOk ? 'ok' : 'err'}`}), h('span', null, 'FortiGate Monitor API'), h('span', {style: {marginLeft: 'auto', color: fgOk ? 'var(--green)' : 'var(--amber)'}}, fgOk ? 'online' : 'offline')),
        h('div', {className: 'apirow'}, h('span', {className: `adot ${wzOk ? 'ok' : 'err'}`}), h('span', null, 'Wazuh Manager API'), h('span', {style: {marginLeft: 'auto', color: wzOk ? 'var(--green)' : 'var(--amber)'}}, wzOk ? 'online' : 'offline')),
        h('div', {className: 'apirow'}, h('span', {className: `adot ${agents.length ? 'ok' : 'warn'}`}), h('span', null, 'Registered endpoint agents'), h('span', {style: {marginLeft: 'auto'}}, fmtNum(agents.length))),
        h('div', {style: {fontSize: 11, color: 'var(--tm)', marginTop: 10}}, 'Protocol distribution, anomalous links and UEBA will remain unavailable until validated telemetry exists. No simulated topology is rendered.')
      )
    );
  }

  function NetworkEndpointApp() {
    const [data, setData] = useState(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [updatedAt, setUpdatedAt] = useState(null);

    async function load() {
      setLoading(true);
      try {
        const response = await fetch('/spark/network-endpoint', {credentials: 'include'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        setData(payload);
        setUpdatedAt(new Date());
        setError('');
      } catch (err) {
        setError(err.message);
        setData({
          source: 'offline',
          errors: {network_endpoint: err.message},
          fortigate: {source: 'offline', cpu: 0, mem: 0, sessions: 0},
          wazuh: {total: 0, active: 0, disconnected: 0, pending: 0, agents: []},
          wazuh_alerts: {total: 0, alerts: []},
          correlations: [],
          blocked_ips: [],
          notes: {},
        });
      } finally {
        setLoading(false);
      }
    }

    useEffect(() => {
      load();
      const timer = setInterval(load, 30000);
      return () => clearInterval(timer);
    }, []);

    const payload = data || {
      source: 'loading',
      errors: {},
      fortigate: {source: 'offline', cpu: 0, mem: 0, sessions: 0},
      wazuh: {total: 0, active: 0, disconnected: 0, pending: 0, agents: []},
      wazuh_alerts: {total: 0, alerts: []},
      correlations: [],
      blocked_ips: [],
    };
    const fgOk = sourceOk(payload, 'fortigate');
    const wzOk = sourceOk(payload, 'wazuh_api');
    const disconnected = Number(payload.wazuh?.disconnected || 0);
    const pending = Number(payload.wazuh?.pending || 0);
    const atRisk = disconnected + pending;

    const statusText = useMemo(() => {
      if (loading) return 'Updating FortiGate and Wazuh telemetry...';
      if (updatedAt) return `Live source check - updated ${updatedAt.toLocaleTimeString('en-US')}`;
      return 'Waiting for live source status.';
    }, [loading, updatedAt]);

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'Network & Endpoint Monitoring'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), statusText)
        ),
        h('div', {className: 'ha'}, h('button', {className: 'btn'}, 'Export Topology'), h('button', {className: 'btn btnp'}, 'Quarantine Host'))
      ),
      h('div', {className: `aibox ${error ? 'loading' : ''}`},
        h('strong', null, 'Network telemetry: '),
        error ? `API unavailable (${error}). No simulated network data is shown.` : 'Rendering only FortiGate Monitor API, Wazuh Manager API and SPARK-owned records.'
      ),
      h('div', {className: 'source-strip'},
        h(SourceChip, {label: 'FortiGate', ok: fgOk}),
        h(SourceChip, {label: 'Wazuh Agents', ok: wzOk})
      ),
      h('div', {className: 'g4'},
        h(KpiCard, {label: 'Active Sessions', value: fgOk ? fmtNum(payload.fortigate?.sessions) : 'N/A', detail: fgOk ? '<span class="dn">FortiGate resource usage</span>' : '<span class="up">FortiGate offline</span>'}),
        h(KpiCard, {label: 'FortiGate CPU', value: fgOk ? `${payload.fortigate?.cpu || 0}%` : 'N/A', detail: fgOk ? 'Current utilization' : 'Waiting for Monitor API'}),
        h(KpiCard, {label: 'Firewall Policies', value: fgOk ? fmtNum(payload.fortigate?.policies?.length) : 'N/A', detail: fgOk ? '<span class="dn">FortiOS CMDB</span>' : '<span class="up">Policy API offline</span>'}),
        h(KpiCard, {label: 'Monitored Agents', value: wzOk ? fmtNum(payload.wazuh?.total) : 'N/A', detail: wzOk ? `<span class="dn">${fmtNum(payload.wazuh?.active)} active</span>` : '<span class="up">Wazuh API offline</span>'})
      ),
      h('div', {className: 'g11'},
        h(FortiGateMetrics, {fortigate: payload.fortigate, ok: fgOk}),
        h(FortiGateApiEvidence, {apiStatus: payload.fortigate?.api_status})
      ),
      h('div', {className: 'g11'},
        h(FortiGateInterfaces, {interfaces: payload.fortigate?.interfaces}),
        h(FortiGateRoutes, {routes: payload.fortigate?.routes})
      ),
      h('div', {className: 'g11'},
        h(FortiGatePolicies, {policies: payload.fortigate?.policies, stats: payload.fortigate?.policy_stats}),
        h(FortiGateCorrelation, {rows: payload.correlations})
      ),
      h('div', {className: 'g11'},
        h(EndpointInventory, {wazuh: payload.wazuh, ok: wzOk}),
        h(BlockedIps, {items: payload.blocked_ips})
      )
    );
  }

  const root = document.getElementById('network-root');
  if (root) ReactDOM.createRoot(root).render(h(NetworkEndpointApp));
})();

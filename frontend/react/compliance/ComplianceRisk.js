(function () {
  const {useEffect, useMemo, useState} = React;
  const h = React.createElement;
  const RANGES = ['24h', '7d', '30d'];

  function fmtNum(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function fmtTime(value) {
    return value && value.length >= 19 ? value.substring(0, 19).replace('T', ' ') : '--';
  }

  function KpiCard({label, value, detail, critical, tone}) {
    return h('div', {className: `kpi ${critical ? 'ka' : ''}`},
      h('div', {className: 'kl'}, label),
      h('div', {className: 'kv', style: tone ? {color: `var(--${tone})`} : null}, value),
      h('div', {className: 'kd', dangerouslySetInnerHTML: {__html: detail || ''}})
    );
  }

  function RangeControl({value, onChange}) {
    return h('div', {className: 'wq-filter'},
      RANGES.map(range => h('button', {
        key: range,
        className: range === value ? 'active' : '',
        onClick: () => onChange(range),
      }, range))
    );
  }

  function SourceChip({label, ok}) {
    return h('span', {className: `source-chip ${ok ? 'ok' : 'warn'}`},
      h('span', {className: 'source-dot'}),
      `${label} ${ok ? 'Online' : 'Offline'}`
    );
  }

  function EmptyState({title, detail}) {
    return h('div', {className: 'cb'},
      h('div', {style: {fontSize: 12, color: 'var(--t1)', fontWeight: 600, marginBottom: 4}}, title),
      h('div', {style: {fontSize: 11, color: 'var(--tm)'}}, detail)
    );
  }

  function ControlCoverage({controls}) {
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Wazuh Compliance Modules'),
          h('div', {className: 'cs'}, 'Counts from Wazuh rule groups, not framework percentages')
        )
      ),
      h('div', {className: 'cb'},
        controls.map(control => {
          const count = Number(control.count || 0);
          const width = Math.min(100, count ? Math.max(8, count * 8) : 0);
          const color = count ? '#1a56db' : '#e2e5ea';
          return h('div', {className: 'cbar', key: control.module},
            h('div', {className: 'chead'},
              h('span', null, control.name),
              h('span', {className: 'cval'}, count ? `${fmtNum(count)} findings` : 'No data')
            ),
            h('div', {className: 'ctrack'}, h('div', {className: 'cfill', style: {width: `${width}%`, background: color}}))
          );
        })
      )
    );
  }

  function FindingTable({items}) {
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Recent Compliance Findings'),
          h('div', {className: 'cs'}, 'SCA, FIM, rootcheck, vulnerability and audit alerts')
        ),
        h('span', {className: 'ca'}, `${fmtNum(items.length)} shown`)
      ),
      items.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Detected', 'Module', 'Finding', 'Agent', 'Level', 'Rule'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          items.map(item => {
            const groups = Array.isArray(item.groups) ? item.groups.join(', ') : '';
            return h('tr', {key: item.document_id || `${item.rule_id}-${item.timestamp}`},
              h('td', null, h('span', {className: 'mono'}, fmtTime(item.timestamp))),
              h('td', null, h('span', {className: 'tpill'}, groups || 'wazuh')),
              h('td', null, h('span', {className: 'edesc', title: item.description}, item.description || 'Wazuh finding')),
              h('td', null, h('span', {className: 'mono'}, item.agent_name || 'unknown')),
              h('td', null, h('span', {className: `badge ${item.severity_class || 'binfo'}`}, item.level || 0)),
              h('td', null, h('span', {className: 'mono'}, item.rule_id || '--'))
            );
          })
        )
      ) : h(EmptyState, {
        title: 'No compliance findings returned',
        detail: 'This is expected until Wazuh SCA/FIM/rootcheck/vulnerability modules produce events for real endpoint agents.',
      })
    );
  }

  function AgentReadiness({agents, notes}) {
    const items = agents?.items || [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Endpoint Readiness'),
          h('div', {className: 'cs'}, 'Compliance telemetry depends on Wazuh endpoint agents')
        ),
        h('span', {className: 'badge binfo'}, `${fmtNum(agents?.total)} agents`)
      ),
      h('div', {className: 'cb'},
        h('div', {className: 'apirow'}, h('span', {className: `adot ${agents?.active ? 'ok' : 'warn'}`}), h('span', null, 'Active agents'), h('span', {style: {marginLeft: 'auto'}}, fmtNum(agents?.active))),
        h('div', {className: 'apirow'}, h('span', {className: `adot ${agents?.disconnected ? 'err' : 'ok'}`}), h('span', null, 'Disconnected agents'), h('span', {style: {marginLeft: 'auto'}}, fmtNum(agents?.disconnected))),
        h('div', {className: 'apirow'}, h('span', {className: `adot ${agents?.pending ? 'warn' : 'ok'}`}), h('span', null, 'Pending agents'), h('span', {style: {marginLeft: 'auto'}}, fmtNum(agents?.pending))),
        h('div', {style: {fontSize: 11, color: 'var(--tm)', marginTop: 10}}, notes?.agents || 'Install endpoint agents to populate SCA, FIM, rootcheck and vulnerability events.'),
        items.length ? h('div', {style: {fontSize: 11, color: 'var(--tm)', marginTop: 8}}, `First agent: ${items[0].name || items[0].id || 'unknown'}`) : null
      )
    );
  }

  function MissingMappings({notes}) {
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Framework Mapping Status'),
          h('div', {className: 'cs'}, 'No fake ISO/PCI/LGPD/NIST scores are rendered')
        )
      ),
      h('div', {className: 'cb'},
        [
          ['Framework scores', notes?.frameworks],
          ['FortiGate policy posture', notes?.fortigate],
          ['Evidence collection', 'Persist evidence snapshots and case links before generating audit-ready reports.'],
        ].map(row => h('div', {className: 'pbstep', key: row[0]},
          h('div', {className: 'pbicon pend'}, '!'),
          h('div', null, h('div', {className: 'kct'}, row[0]), h('div', {className: 'kcs'}, row[1]))
        ))
      )
    );
  }

  function ComplianceRiskApp() {
    const [range, setRange] = useState('7d');
    const [data, setData] = useState(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [updatedAt, setUpdatedAt] = useState(null);

    async function load() {
      setLoading(true);
      try {
        const response = await fetch(`/spark/compliance-risk?range=${encodeURIComponent(range)}`, {credentials: 'include'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        setData(payload);
        setUpdatedAt(new Date());
        setError('');
      } catch (err) {
        setError(err.message);
        setData({
          source: 'offline',
          errors: {compliance: err.message},
          total_findings: 0,
          returned: 0,
          modules: {},
          controls: [],
          findings: [],
          agents: {total: 0, active: 0, disconnected: 0, pending: 0, items: []},
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
    }, [range]);

    const payload = data || {
      source: 'loading',
      errors: {},
      total_findings: 0,
      returned: 0,
      modules: {},
      controls: [],
      findings: [],
      agents: {total: 0, active: 0, disconnected: 0, pending: 0, items: []},
      notes: {},
    };
    const indexerOk = !payload.errors?.wazuh_indexer && payload.source !== 'loading';
    const apiOk = !payload.errors?.wazuh_api && payload.source !== 'loading';
    const modules = payload.modules || {};
    const status = useMemo(() => {
      if (loading) return `Updating ${range} compliance telemetry...`;
      if (updatedAt) return `Live source check - updated ${updatedAt.toLocaleTimeString('en-US')}`;
      return 'Waiting for Wazuh compliance modules.';
    }, [loading, updatedAt, range]);

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'Compliance & Risk Management'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), status)
        ),
        h('div', {className: 'ha'}, h(RangeControl, {value: range, onChange: setRange}), h('button', {className: 'btn'}, 'Schedule Report'), h('button', {className: 'btn btnp'}, 'Generate Compliance Report'))
      ),
      h('div', {className: `aibox ${error ? 'loading' : ''}`},
        h('strong', null, 'Compliance telemetry: '),
        error ? `API unavailable (${error}). No simulated compliance score is shown.` : 'Showing Wazuh module evidence only. Framework compliance scores require real control mappings.'
      ),
      h('div', {className: 'source-strip'},
        h(SourceChip, {label: 'Wazuh Indexer', ok: indexerOk}),
        h(SourceChip, {label: 'Wazuh Manager', ok: apiOk})
      ),
      h('div', {className: 'g4'},
        h(KpiCard, {label: 'Compliance Findings', value: fmtNum(payload.total_findings), detail: `<span class="dn">${fmtNum(payload.returned)}</span> recent findings shown`, critical: Number(payload.total_findings) > 0}),
        h(KpiCard, {label: 'SCA Events', value: fmtNum(modules.sca), detail: 'Wazuh SCA rule groups'}),
        h(KpiCard, {label: 'FIM Events', value: fmtNum(modules.fim), detail: 'Wazuh syscheck rule groups'}),
        h(KpiCard, {label: 'Vuln / Audit Events', value: fmtNum((modules.vulnerability || 0) + (modules.audit || 0)), detail: 'Detector + policy/audit groups'})
      ),
      h('div', {className: 'g11'},
        h(ControlCoverage, {controls: payload.controls || []}),
        h(AgentReadiness, {agents: payload.agents, notes: payload.notes})
      ),
      h('div', {className: 'g11'},
        h(FindingTable, {items: payload.findings || []}),
        h(MissingMappings, {notes: payload.notes || {}})
      )
    );
  }

  const root = document.getElementById('compliance-root');
  if (root) ReactDOM.createRoot(root).render(h(ComplianceRiskApp));
})();

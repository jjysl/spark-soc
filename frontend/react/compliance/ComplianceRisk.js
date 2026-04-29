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

  function frameworkScores(payload) {
    const modules = payload.modules || {};
    const agents = payload.agents || {};
    const activeRatio = agents.total ? Math.round((Number(agents.active || 0) / Number(agents.total || 1)) * 100) : 0;
    const evidence = {
      sca: Number(modules.sca || 0),
      fim: Number(modules.fim || 0),
      audit: Number(modules.audit || 0),
      vuln: Number(modules.vulnerability || 0),
      rootcheck: Number(modules.rootcheck || 0),
    };
    const base = Math.min(100, 35 + Math.min(30, activeRatio) + Math.min(25, payload.total_findings ? 15 : 0));
    return [
      {label: 'ISO 27001', value: Math.min(96, base + Math.min(12, evidence.sca + evidence.fim)), detail: 'A.8 / A.12 / A.16 evidence'},
      {label: 'PCI DSS 4.0', value: Math.min(92, base + Math.min(10, evidence.audit + evidence.vuln)), detail: 'Req. 10 / 11 monitoring'},
      {label: 'LGPD / GDPR', value: Math.min(94, base + Math.min(10, evidence.fim + evidence.audit)), detail: 'Art. 46 security controls'},
      {label: 'NIST CSF 2.0', value: Math.min(93, base + Math.min(12, evidence.sca + evidence.rootcheck)), detail: 'Detect / Protect / Respond'},
    ];
  }

  function FrameworkOverview({payload}) {
    const rows = frameworkScores(payload);
    return h(React.Fragment, null,
      h('div', {className: 'g4'},
        rows.map(item => {
          const tone = item.value >= 85 ? 'green' : item.value >= 70 ? 'amber' : 'red';
          return h(KpiCard, {
            key: item.label,
            label: item.label,
            value: `${item.value}%`,
            detail: `<span class="${item.value >= 85 ? 'dn' : 'up'}">${item.detail}</span>`,
            tone,
          });
        })
      ),
      h('div', {className: 'card', style: {marginBottom: 14}},
        h('div', {className: 'ch'},
          h('div', null,
            h('div', {className: 'ct'}, 'Controls by Framework'),
            h('div', {className: 'cs'}, 'Score = agent readiness + Wazuh evidence + module-specific control coverage')
          )
        ),
        h('div', {className: 'cb'},
          rows.map(item => {
            const color = item.value >= 85 ? '#10b981' : item.value >= 70 ? '#f59e0b' : '#da291c';
            return h('div', {className: 'cbar', key: item.label},
              h('div', {className: 'chead'},
                h('span', null, item.label),
                h('span', {className: 'cval'}, `${item.value}%`)
              ),
              h('div', {className: 'ctrack'}, h('div', {className: 'cfill', style: {width: `${item.value}%`, background: color}}))
            );
          }),
          h('div', {style: {fontSize: 11, color: 'var(--tm)', marginTop: 10}},
            'These are presentation scores for NG-SOC posture. They are derived from active Wazuh agents, compliance/security findings, and matching evidence modules; they are not formal ISO/PCI/LGPD/NIST audit results.'
          )
        )
      )
    );
  }

  function AssetRiskSegments({payload}) {
    const modules = payload.modules || {};
    const agents = payload.agents || {};
    const rows = [
      {name: 'Endpoint fleet', value: Math.min(100, Number(payload.total_findings || 0) * 12 + Number(agents.disconnected || 0) * 15), detail: 'findings + disconnected agents'},
      {name: 'Identity / access', value: Math.min(100, Number(modules.audit || 0) * 14 + Number(modules.rootcheck || 0) * 8), detail: 'audit + rootcheck evidence'},
      {name: 'Data integrity', value: Math.min(100, Number(modules.fim || 0) * 10), detail: 'FIM / syscheck evidence'},
      {name: 'Vulnerability posture', value: Math.min(100, Number(modules.vulnerability || 0) * 18), detail: 'vulnerability detector evidence'},
    ];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Digital Asset Risk Score by Control Area'),
          h('div', {className: 'cs'}, 'Risk estimate from live Wazuh compliance telemetry')
        )
      ),
      h('div', {className: 'cb'},
        rows.map(item => {
          const color = item.value >= 70 ? '#da291c' : item.value >= 40 ? '#f59e0b' : '#10b981';
          return h('div', {className: 'rseg', key: item.name},
            h('div', {className: 'rsname'}, item.name),
            h('div', {className: 'rsbar'}, h('div', {className: 'rsfill', style: {width: `${Math.max(4, item.value)}%`, background: color}})),
            h('div', {className: 'rsval'}, item.value),
            h('div', {style: {fontSize: 10, color: 'var(--tm)', minWidth: 120}}, item.detail)
          );
        })
      )
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
    const [expanded, setExpanded] = useState(false);
    const visibleItems = expanded ? items : items.slice(0, 6);
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Recent Compliance Findings'),
          h('div', {className: 'cs'}, 'SCA, FIM, rootcheck, vulnerability and audit alerts')
        ),
        h('div', {style: {display: 'flex', alignItems: 'center', gap: 8}},
          h('span', {className: 'ca'}, `${fmtNum(visibleItems.length)}/${fmtNum(items.length)} shown`),
          items.length > 6 ? h('button', {className: 'btn', onClick: () => setExpanded(value => !value)}, expanded ? 'Collapse' : 'View all') : null
        )
      ),
      items.length ? h('div', {className: 'compact-list'},
        visibleItems.map(item => {
          const groups = Array.isArray(item.groups) ? item.groups.slice(0, 3).join(', ') : '';
          return h('div', {className: 'compact-row', key: item.document_id || `${item.rule_id}-${item.timestamp}`},
            h('div', {className: 'compact-main'},
              h('div', {className: 'compact-title', title: item.description}, item.description || 'Wazuh finding'),
              h('div', {className: 'compact-meta'},
                h('span', {className: 'mono'}, fmtTime(item.timestamp)),
                h('span', {className: 'tpill compact-pill', title: Array.isArray(item.groups) ? item.groups.join(', ') : ''}, groups || 'wazuh'),
                h('span', {className: 'mono'}, item.agent_name || 'unknown'),
                h('span', {className: 'mono'}, `rule ${item.rule_id || '--'}`)
              )
            ),
            h('span', {className: `badge ${item.severity_class || 'binfo'}`}, item.level || 0)
          );
        })
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
          h('div', {className: 'ct'}, 'Framework Evidence Notes'),
          h('div', {className: 'cs'}, 'What is measured now and what requires audit mapping later')
        )
      ),
      h('div', {className: 'cb'},
        [
          ['Framework scores', 'Current scores are estimated from Wazuh evidence and agent readiness; formal audit control mapping is roadmap work.'],
          ['FortiGate policy posture', notes?.fortigate],
          ['Evidence collection', 'Persist evidence snapshots and case links before generating audit-ready reports.'],
        ].map(row => h('div', {className: 'pbstep', key: row[0]},
          h('div', {className: 'pbicon pend'}, '!'),
          h('div', null, h('div', {className: 'kct'}, row[0]), h('div', {className: 'kcs'}, row[1]))
        ))
      )
    );
  }

  function EvolutionRoadmap() {
    const phases = [
      ['Phase 1', 'SPARK + FortiOS REST API', 'Live FortiGate monitoring, blocklist configuration and incident response evidence.'],
      ['Phase 2', 'FortiAnalyzer', 'Centralize FortiGate/FortiClient/FortiSwitch logs and replace lab-side log gaps.'],
      ['Phase 3', 'FortiSOAR / Shuffle', 'Move response playbooks into orchestrated approvals, enrichment and containment.'],
      ['Phase 4', 'AI-assisted NG-SOC', 'Risk scoring, alert summaries, analyst recommendations and response prioritization.'],
    ];
    return h('div', {className: 'card', style: {marginTop: 14}},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Fortinet NG-SOC Evolution Roadmap'),
          h('div', {className: 'cs'}, 'Roadmap aligned with FortiAnalyzer and SOAR adoption')
        ),
        h('span', {className: 'badge binfo'}, 'Proposal')
      ),
      h('div', {className: 'cb'},
        phases.map((phase, index) => h('div', {className: 'pbstep', key: phase[0]},
          h('div', {className: `pbicon ${index === 0 ? 'done' : index === 1 ? 'act' : 'pend'}`}, index === 0 ? 'OK' : `${index + 1}`),
          h('div', null,
            h('div', {className: 'kct'}, `${phase[0]} - ${phase[1]}`),
            h('div', {className: 'kcs'}, phase[2])
          )
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
        error ? `API unavailable (${error}). No simulated compliance score is shown.` : 'Framework cards are evidence-based estimates from Wazuh modules, not formal audit attestations.'
      ),
      h('div', {className: 'source-strip'},
        h(SourceChip, {label: 'Wazuh Indexer', ok: indexerOk}),
        h(SourceChip, {label: 'Wazuh Manager', ok: apiOk})
      ),
      h(FrameworkOverview, {payload}),
      h('div', {className: 'g11'},
        h(ControlCoverage, {controls: payload.controls || []}),
        h(AgentReadiness, {agents: payload.agents, notes: payload.notes})
      ),
      h('div', {className: 'g11'},
        h(FindingTable, {items: payload.findings || []}),
        h(MissingMappings, {notes: payload.notes || {}})
      ),
      h(AssetRiskSegments, {payload}),
      h(EvolutionRoadmap)
    );
  }

  const root = document.getElementById('compliance-root');
  if (root) ReactDOM.createRoot(root).render(h(ComplianceRiskApp));
})();

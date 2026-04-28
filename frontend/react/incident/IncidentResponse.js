(function () {
  const {useEffect, useMemo, useState} = React;
  const h = React.createElement;
  const RANGES = ['1h', '6h', '24h', '7d', '30d'];

  function fmtNum(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function fmtTime(value) {
    return value && value.length >= 19 ? value.substring(11, 19) : '--:--:--';
  }

  function priorityClass(priority) {
    return {P1: 'bp1', P2: 'bp2', P3: 'bp3', P4: 'bp4'}[priority] || 'bp3';
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

  function CandidateTable({items}) {
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Incident Candidates'),
          h('div', {className: 'cs'}, 'High-severity Wazuh alerts ready for case creation')
        ),
        h('span', {className: 'ca'}, `${fmtNum(items.length)} candidates`)
      ),
      items.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Time', 'Priority', 'Alert', 'Agent', 'Source IP', 'MITRE', 'Rule'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          items.map(item => h('tr', {key: item.document_id || `${item.rule_id}-${item.timestamp}`},
            h('td', null, h('span', {className: 'mono'}, fmtTime(item.timestamp))),
            h('td', null, h('span', {className: `badge ${priorityClass(item.priority)}`}, item.priority || 'P3')),
            h('td', null, h('span', {className: 'edesc', title: item.title}, item.title || 'Wazuh alert')),
            h('td', null, h('span', {className: 'mono'}, item.agent_name || 'unknown')),
            h('td', null, h('span', {className: 'mono'}, item.src_ip || item.agent_ip || '--')),
            h('td', null, h('span', {className: 'tpill'}, item.mitre_technique || item.mitre_tactic || 'Detection')),
            h('td', null, h('span', {className: 'mono'}, item.rule_id || '--'))
          ))
        )
      ) : h(EmptyState, {
        title: 'No high-severity candidates in this range',
        detail: 'This table only shows Wazuh alerts with level 7 or higher. No fallback incidents are rendered.',
      })
    );
  }

  function ShuffleStatus({shuffle}) {
    const ok = Boolean(shuffle?.connected);
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Shuffle SOAR Status'),
          h('div', {className: 'cs'}, 'Connectivity and basic endpoint discovery')
        ),
        h('span', {className: `badge ${ok ? 'blive' : 'bhigh'}`}, ok ? 'Connected' : 'Unavailable')
      ),
      h('div', {className: 'cb'},
        h('div', {className: 'apirow'},
          h('span', {className: `adot ${ok ? 'ok' : 'err'}`}),
          h('span', null, 'Status source'),
          h('span', {style: {marginLeft: 'auto', color: 'var(--t2)'}}, shuffle?.source || 'shuffle')
        ),
        h('div', {className: 'apirow'},
          h('span', {className: `adot ${ok ? 'ok' : 'warn'}`}),
          h('span', null, 'HTTP status'),
          h('span', {style: {marginLeft: 'auto', color: 'var(--t2)'}}, shuffle?.status_code || 'N/A')
        ),
        h('div', {className: 'apirow'},
          h('span', {className: `adot ${ok && shuffle?.items ? 'ok' : 'warn'}`}),
          h('span', null, 'Items discovered'),
          h('span', {style: {marginLeft: 'auto', color: 'var(--t2)'}}, fmtNum(shuffle?.items))
        ),
        !ok ? h('div', {style: {fontSize: 11, color: 'var(--amber)', marginTop: 10}}, shuffle?.error || 'Configure SHUFFLE_BASE_URL and SHUFFLE_API_KEY on the lab machine.') : null
      )
    );
  }

  function ReadinessPanel({notes}) {
    const rows = [
      ['Playbook catalog', 'Unavailable', notes?.playbooks || 'Workflow listing endpoint not validated.'],
      ['Incident timeline', 'Unavailable', notes?.timeline || 'Lifecycle persistence not implemented.'],
      ['Action execution log', 'Unavailable', notes?.actions || 'SOAR/FortiGate action log persistence not implemented.'],
    ];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Automation Readiness'),
          h('div', {className: 'cs'}, 'Only validated data surfaces are enabled')
        )
      ),
      h('div', {className: 'cb'},
        rows.map(row => h('div', {className: 'pbstep', key: row[0]},
          h('div', {className: 'pbicon pend'}, '!'),
          h('div', null,
            h('div', {className: 'kct'}, row[0]),
            h('div', {className: 'kcs'}, `${row[1]} - ${row[2]}`)
          )
        ))
      )
    );
  }

  function EmptyLogCard({title, subtitle, detail}) {
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null, h('div', {className: 'ct'}, title), h('div', {className: 'cs'}, subtitle)),
        h('span', {className: 'badge binfo'}, 'No live records')
      ),
      h(EmptyState, {title: 'No records available', detail})
    );
  }

  function IncidentResponseApp() {
    const [range, setRange] = useState('24h');
    const [data, setData] = useState(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [updatedAt, setUpdatedAt] = useState(null);

    async function load() {
      setLoading(true);
      try {
        const response = await fetch(`/spark/incident-response?range=${encodeURIComponent(range)}`, {credentials: 'include'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        setData(payload);
        setUpdatedAt(new Date());
        setError('');
      } catch (err) {
        setError(err.message);
        setData({
          source: 'offline',
          range,
          errors: {incident_response: err.message},
          shuffle: {connected: false, source: 'shuffle', error: err.message},
          wazuh: {total: 0, counts: {}, candidate_count: 0, candidates: []},
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
      range,
      errors: {},
      shuffle: {connected: false, source: 'shuffle'},
      wazuh: {total: 0, counts: {}, candidate_count: 0, candidates: []},
      notes: {},
    };
    const shuffleOk = Boolean(payload.shuffle?.connected);
    const wazuhOk = !payload.errors?.wazuh_indexer && payload.source !== 'loading';
    const candidates = payload.wazuh?.candidates || [];
    const counts = payload.wazuh?.counts || {};
    const status = useMemo(() => {
      if (loading) return `Updating ${range} response telemetry...`;
      if (updatedAt) return `Live source check - updated ${updatedAt.toLocaleTimeString('en-US')}`;
      return 'Waiting for live source status.';
    }, [loading, updatedAt, range]);

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'Incident Response & SOAR Automation'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), status)
        ),
        h('div', {className: 'ha'}, h(RangeControl, {value: range, onChange: setRange}), h('button', {className: 'btn'}, 'Forensic Report'), h('button', {className: 'btn btnp'}, 'Isolate Host via API'))
      ),
      h('div', {className: `aibox ${error ? 'loading' : ''}`},
        h('strong', null, 'Incident Response: '),
        error ? `API unavailable (${error}). No simulated playbook data is shown.` : 'Showing Wazuh alert candidates and Shuffle connectivity only. Playbook execution remains disabled until endpoints are validated.'
      ),
      h('div', {className: 'source-strip'},
        h(SourceChip, {label: 'Wazuh Indexer', ok: wazuhOk}),
        h(SourceChip, {label: 'Shuffle', ok: shuffleOk})
      ),
      h('div', {className: 'g4'},
        h(KpiCard, {label: 'Incident Candidates', value: fmtNum(candidates.length), detail: `<span class="up">${fmtNum(payload.wazuh?.total)}</span> Wazuh alerts in range`, critical: candidates.length > 0}),
        h(KpiCard, {label: 'P1 Candidates', value: fmtNum(counts.p1), detail: 'Wazuh level >= 12'}),
        h(KpiCard, {label: 'P2 Candidates', value: fmtNum(counts.p2), detail: 'Wazuh level 7-11'}),
        h(KpiCard, {label: 'Shuffle Workflows', value: shuffleOk ? fmtNum(payload.shuffle?.items) : 'N/A', detail: shuffleOk ? `<span class="dn">${payload.shuffle?.source || 'connected'}</span>` : '<span class="up">Endpoint not validated</span>'})
      ),
      h('div', {className: 'g11'},
        h(ShuffleStatus, {shuffle: payload.shuffle}),
        h(ReadinessPanel, {notes: payload.notes})
      ),
      h(CandidateTable, {items: candidates}),
      h('div', {className: 'g11', style: {marginTop: 14}},
        h(EmptyLogCard, {title: 'Incident Timeline', subtitle: 'Requires persisted lifecycle events', detail: payload.notes?.timeline || 'No incident lifecycle table exists yet, so no timeline is rendered.'}),
        h(EmptyLogCard, {title: 'SOAR Action Log', subtitle: 'Requires persisted Shuffle/FortiGate action results', detail: payload.notes?.actions || 'No validated playbook execution log exists yet.'})
      )
    );
  }

  const root = document.getElementById('incident-root');
  if (root) ReactDOM.createRoot(root).render(h(IncidentResponseApp));
})();

(function () {
  const {useEffect, useMemo, useRef, useState} = React;
  const h = React.createElement;

  const RANGES = ['1h', '6h', '24h', '7d', '30d'];
  const MITRE_TACTICS = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion',
    'Credential Access', 'Discovery', 'Lateral Movement',
    'Command and Control', 'Exfiltration', 'Impact',
  ];

  function fmtNum(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function clsPriority(priority) {
    return {P1: 'bp1', P2: 'bp2', P3: 'bp3', P4: 'bp4'}[priority] || 'bp3';
  }

  function fmtTime(value) {
    return value && value.length >= 19 ? value.substring(11, 19) : '--:--:--';
  }

  function shortTactic(value) {
    return String(value || 'Detection').replace('Command and Control', 'Command & Control');
  }

  function TimeRange({value, onChange, disabled}) {
    return h('div', {className: 'wq-filter'},
      RANGES.map(range => h('button', {
        key: range,
        className: value === range ? 'active' : '',
        disabled,
        onClick: () => onChange(range),
      }, range))
    );
  }

  function FilterButton({field, value, label, onFilter}) {
    if (!value) return h('span', {className: 'detail-value'}, '--');
    return h('button', {
      className: 'detail-filter',
      onClick: event => {
        event.stopPropagation();
        onFilter(field, value);
      },
    }, label || value);
  }

  function ActiveAlertSummary({chain, alert, onFilter}) {
    if (!chain && !alert) {
      return h('div', {style: {fontSize: 12, color: 'var(--tm)'}}, 'No active alert in the selected range.');
    }
    const stages = chain?.stages || [];
    return h(React.Fragment, null,
      h('div', {style: {display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 12}},
        h('div', null,
          h('div', {style: {fontSize: 15, fontWeight: 700, color: 'var(--t1)'}}, chain?.title || 'Kill Chain - Active Detection'),
          h('div', {style: {fontSize: 11, color: 'var(--tm)', marginTop: 3}}, chain?.subtitle || 'Latest normalized Wazuh detection')
        ),
        h('span', {className: `badge ${clsPriority(chain?.priority || alert?.priority)}`}, chain?.priority || alert?.priority || 'P3')
      ),
      stages.map((stage, idx) => h('div', {className: 'kcstep', key: stage.name},
        h('div', {className: `kcicon ${stage.state === 'active' ? 'act' : stage.state === 'done' ? 'done' : ''}`}, stage.state === 'pending' ? '...' : '✓'),
        h('div', null,
          h('div', {className: 'kct'}, stage.name),
          h('div', {className: 'kcs'}, stage.detail),
          stage.document_id ? h(FilterButton, {field: stage.src_ip ? 'src_ip' : 'agent.name', value: stage.src_ip || stage.agent_name, label: 'filter', onFilter}) : null
        )
      ))
    );
  }

  function MitreHeatmap({facets, onFilter}) {
    const buckets = facets?.tactics || [];
    const counts = new Map(buckets.map(item => [String(item.key), item.doc_count]));
    const max = Math.max(1, ...buckets.map(item => item.doc_count || 0));
    const colors = ['#f1f5f9', '#fee2e2', '#fca5a5', '#f87171', '#ef4444', '#b91c1c'];
    return h(React.Fragment, null,
      h('div', {style: {display: 'grid', gridTemplateColumns: 'repeat(13,1fr)', gap: 2, marginBottom: 5}},
        MITRE_TACTICS.map(tactic => h('div', {
          key: tactic,
          style: {fontSize: 8.5, fontWeight: 600, color: 'var(--tm)', textAlign: 'center', lineHeight: 1.2, paddingBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'},
        }, tactic.replace('Resource Development', 'Resource Dev').replace('Privilege Escalation', 'Priv Esc').replace('Defense Evasion', 'Def. Evasion').replace('Command and Control', 'C2')))
      ),
      h('div', {style: {display: 'grid', gridTemplateColumns: 'repeat(13,1fr)', gap: 2}},
        MITRE_TACTICS.map(tactic => {
          const count = counts.get(tactic) || 0;
          const idx = count ? Math.max(1, Math.min(5, Math.ceil((count / max) * 5))) : 0;
          return h('div', {
            key: tactic,
            title: tactic,
            onClick: () => onFilter('mitre.tactic', tactic),
            style: {aspectRatio: '1', borderRadius: 3, background: colors[idx], cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, fontWeight: 600, color: idx >= 3 ? '#fff' : '#991b1b'},
          }, count || '');
        })
      ),
      h('div', {style: {display: 'flex', alignItems: 'center', gap: 6, marginTop: 10}},
        h('span', {style: {fontSize: 10, color: 'var(--tm)'}}, 'Low'),
        colors.map(color => h('div', {key: color, style: {width: 14, height: 10, borderRadius: 2, background: color}})),
        h('span', {style: {fontSize: 10, color: 'var(--tm)'}}, 'High')
      )
    );
  }

  function DetailCell({label, value, field, onFilter}) {
    return h('div', {className: 'detail-cell'},
      h('div', {className: 'detail-label'}, label),
      h('div', {className: 'detail-value'}, value || '--'),
      field && value ? h(FilterButton, {field, value, label: 'filter', onFilter}) : null
    );
  }

  function AlertDetail({alert, tab, setTab, onFilter}) {
    const groups = Array.isArray(alert.groups) ? alert.groups.join(', ') : '';
    const tabs = ['summary', 'rule', 'json'];
    let content;
    if (tab === 'json') {
      content = h('pre', {className: 'detail-log'}, JSON.stringify(alert.raw || {}, null, 2));
    } else if (tab === 'rule') {
      content = h('div', {className: 'alert-detail'},
        h(DetailCell, {label: 'Rule ID', value: alert.rule_id, field: 'rule.id', onFilter}),
        h(DetailCell, {label: 'Level', value: alert.level, field: 'rule.level', onFilter}),
        h(DetailCell, {label: 'Priority', value: alert.priority}),
        h(DetailCell, {label: 'Manager', value: alert.manager_name, field: 'manager.name', onFilter}),
        h(DetailCell, {label: 'Description', value: alert.description}),
        h(DetailCell, {label: 'MITRE Tactic', value: alert.mitre_tactic, field: 'mitre.tactic', onFilter}),
        h(DetailCell, {label: 'MITRE Technique', value: alert.mitre_technique, field: 'mitre.technique', onFilter})
      );
    } else {
      content = h('div', {className: 'alert-detail'},
        h(DetailCell, {label: 'Agent', value: alert.agent_name, field: 'agent.name', onFilter}),
        h(DetailCell, {label: 'Source IP', value: alert.src_ip, field: 'src_ip', onFilter}),
        h(DetailCell, {label: 'Destination IP', value: alert.dst_ip, field: 'dst_ip', onFilter}),
        h(DetailCell, {label: 'Decoder', value: alert.decoder_name, field: 'decoder.name', onFilter}),
        h(DetailCell, {label: 'Location', value: alert.location, field: 'location', onFilter}),
        h(DetailCell, {label: 'Rule Groups', value: groups, field: Array.isArray(alert.groups) && alert.groups[0] ? 'rule.groups' : '', onFilter}),
        h(DetailCell, {label: 'Document', value: alert.document_id}),
        h(DetailCell, {label: 'Index', value: alert.index}),
        h('pre', {className: 'detail-log'}, alert.full_log || alert.summary || 'No full_log field available.')
      );
    }
    return h('tr', {className: 'detail-row'},
      h('td', {colSpan: 7},
        h('div', {className: 'detail-tabs'},
          tabs.map(item => h('button', {
            key: item,
            className: tab === item ? 'active' : '',
            onClick: event => {
              event.stopPropagation();
              setTab(item);
            },
          }, item.toUpperCase()))
        ),
        content
      )
    );
  }

  function AlertFeed({alerts, total, filters, setFilters, search, setSearch, range, setRange}) {
    const [openId, setOpenId] = useState('');
    const [detailTab, setDetailTab] = useState('summary');

    function addFilter(field, value) {
      if (!value) return;
      setOpenId('');
      setFilters(items => items.some(item => item.field === field && item.value === String(value)) ? items : [...items, {field, value: String(value)}]);
    }

    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Correlated Alert Feed'),
          h('div', {className: 'cs'}, 'Wazuh Indexer - normalized analyst view - click values to filter')
        ),
        h('span', {className: 'ca'}, `${fmtNum(total)} alerts`)
      ),
      h('div', {className: 'wq-tools'},
        h('input', {
          className: 'wq-search',
          value: search,
          onChange: event => setSearch(event.target.value),
          placeholder: 'Search rule, agent, IP, decoder, raw log',
        }),
        h(TimeRange, {value: range, onChange: setRange})
      ),
      h('div', {className: 'filter-tokens'},
        filters.length ? filters.map((filter, idx) => h('span', {className: 'filter-token', key: `${filter.field}-${filter.value}`},
          `${filter.field}:${filter.value}`,
          h('button', {onClick: () => setFilters(items => items.filter((_, index) => index !== idx))}, 'x')
        )) : h('span', {style: {fontSize: 11, color: 'var(--tm)'}}, 'No active field filters')
      ),
      h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Time', 'Source IP', 'Agent', 'Rule', 'MITRE', 'Priority', 'Status'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          alerts.length ? alerts.flatMap(alert => {
            const id = String(alert.document_id || `${alert.rule_id}-${alert.timestamp}`);
            const isOpen = openId === id;
            return [
              h('tr', {key: id, onClick: () => setOpenId(isOpen ? '' : id)},
                h('td', null, h('span', {className: 'mono'}, fmtTime(alert.timestamp))),
                h('td', null, h(FilterButton, {field: 'src_ip', value: alert.src_ip, label: alert.src_ip || alert.agent_ip || '--', onFilter: addFilter})),
                h('td', null, h(FilterButton, {field: 'agent.name', value: alert.agent_name, label: alert.agent_name || 'unknown', onFilter: addFilter})),
                h('td', null,
                  h('div', {className: 'edesc', title: alert.description}, alert.description || 'Wazuh alert'),
                  h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, `Rule ${alert.rule_id || '-'} - level ${alert.level || 0}`)
                ),
                h('td', null, h(FilterButton, {field: 'mitre.tactic', value: alert.mitre_tactic, label: shortTactic(alert.mitre_tactic), onFilter: addFilter})),
                h('td', null, h('span', {className: `badge ${clsPriority(alert.priority)}`}, alert.priority || 'P4')),
                h('td', null, h('span', {className: `badge ${alert.status_class || 'bnew'}`}, alert.status || 'New'))
              ),
              isOpen ? h(AlertDetail, {key: `${id}-detail`, alert, tab: detailTab, setTab: setDetailTab, onFilter: addFilter}) : null,
            ].filter(Boolean);
          }) : h('tr', null, h('td', {colSpan: 7, style: {color: 'var(--tm)', fontSize: 12}}, 'No Wazuh alerts matched the current query.'))
        )
      )
    );
  }

  function SeverityTrend({data}) {
    const canvasRef = useRef(null);
    const chartRef = useRef(null);
    const timeline = data?.timeline || [];

    useEffect(() => {
      if (!canvasRef.current || !window.Chart) return;
      const rows = timeline.slice(-24);
      const labels = rows.map(row => row.time && row.time.length >= 13 ? row.time.substring(11, 16) : '--');
      const chartData = {
        labels,
        datasets: [
          {label: 'Critical', data: rows.map(row => row.critical || 0), borderColor: '#da291c', backgroundColor: 'rgba(218,41,28,0.06)', borderWidth: 1.5, pointRadius: 2, tension: .3, fill: true},
          {label: 'High', data: rows.map(row => row.high || 0), borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.05)', borderWidth: 1.5, pointRadius: 2, tension: .3, fill: true},
          {label: 'Medium/Low', data: rows.map(row => (row.medium || 0) + (row.low || 0)), borderColor: '#1a56db', backgroundColor: 'rgba(26,86,219,0.05)', borderWidth: 1.5, pointRadius: 2, tension: .3, fill: true},
        ],
      };
      if (chartRef.current) {
        chartRef.current.data = chartData;
        chartRef.current.update();
        return;
      }
      chartRef.current = new Chart(canvasRef.current.getContext('2d'), {
        type: 'line',
        data: chartData,
        options: {responsive: true, maintainAspectRatio: true, animation: {duration: 400}, plugins: {legend: {position: 'top', align: 'end', labels: {boxWidth: 10, boxHeight: 10, font: {size: 10, family: 'Inter'}, padding: 10}}}, scales: {x: {grid: {display: false}, ticks: {font: {size: 10, family: 'Inter'}, color: '#8a95a3'}}, y: {grid: {color: '#e2e5ea', lineWidth: .5}, ticks: {font: {size: 10}, color: '#8a95a3'}, border: {display: false}}}},
      });
      return () => {
        if (chartRef.current) {
          chartRef.current.destroy();
          chartRef.current = null;
        }
      };
    }, [timeline]);

    const counts = data?.counts || {};
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Detection Severity Trend'),
          h('div', {className: 'cs'}, 'Wazuh alert volume by severity over selected range')
        ),
        h('span', {className: `badge ${data?.source === 'opensearch-live' ? 'blive' : 'bhigh'}`}, data?.source === 'opensearch-live' ? 'Live' : 'Offline')
      ),
      h('div', {className: 'cb'},
        h('div', {className: 'cwrap', style: {padding: '0 0 14px'}}, h('canvas', {ref: canvasRef})),
        h('div', {style: {display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', textAlign: 'center', borderTop: '1px solid var(--border)', paddingTop: 12}},
          h('div', {style: {borderRight: '1px solid var(--border)', padding: '0 8px'}}, h('div', {style: {fontSize: 16, fontWeight: 600, color: 'var(--red)'}}, fmtNum(counts.p1)), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'P1 Critical')),
          h('div', {style: {borderRight: '1px solid var(--border)', padding: '0 8px'}}, h('div', {style: {fontSize: 16, fontWeight: 600, color: 'var(--amber)'}}, fmtNum(counts.p2)), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'P2 High')),
          h('div', {style: {borderRight: '1px solid var(--border)', padding: '0 8px'}}, h('div', {style: {fontSize: 16, fontWeight: 600, color: 'var(--blue)'}}, fmtNum(data?.facets?.tactics?.length)), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'MITRE Tactics')),
          h('div', {style: {padding: '0 8px'}}, h('div', {style: {fontSize: 16, fontWeight: 600, color: 'var(--t2)'}}, fmtNum(data?.facets?.decoders?.length)), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'Decoders'))
        )
      )
    );
  }

  function ThreatDetectionApp() {
    const [range, setRange] = useState('24h');
    const [searchInput, setSearchInput] = useState('');
    const [query, setQuery] = useState('');
    const [filters, setFilters] = useState([]);
    const [data, setData] = useState(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
      const timer = setTimeout(() => setQuery(searchInput.trim()), 300);
      return () => clearTimeout(timer);
    }, [searchInput]);

    function addFilter(field, value) {
      if (!value) return;
      setFilters(items => items.some(item => item.field === field && item.value === String(value)) ? items : [...items, {field, value: String(value)}]);
    }

    async function load() {
      setLoading(true);
      const params = new URLSearchParams({range, size: '100'});
      if (query) params.set('q', query);
      filters.forEach(filter => params.append('filter', `${filter.field}:${filter.value}`));
      try {
        const response = await fetch(`/spark/threat-detection?${params.toString()}`, {credentials: 'include'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        setData(payload);
        setError('');
      } catch (err) {
        setError(err.message);
        setData({
          source: 'offline',
          total: 0,
          counts: {},
          facets: {tactics: [], decoders: []},
          timeline: [],
          alerts: [],
          triage: `Threat Detection API unavailable: ${err.message}`,
        });
      } finally {
        setLoading(false);
      }
    }

    useEffect(() => {
      load();
      const timer = setInterval(load, 30000);
      return () => clearInterval(timer);
    }, [range, query, JSON.stringify(filters)]);

    const payload = data || {source: 'loading', total: 0, counts: {}, facets: {tactics: [], decoders: []}, timeline: [], alerts: [], triage: 'Loading Wazuh Indexer alerts.'};
    const live = payload.source === 'opensearch-live';

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'Threat Detection & Intelligence'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), loading ? `Updating ${range} detections...` : 'Wazuh Indexer - normalized detections - live filters')
        ),
        h('div', {className: 'ha'}, h('button', {className: 'btn'}, 'Threat Hunting'), h('button', {className: 'btn btnp'}, 'New Triage Rule'))
      ),
      h('div', {className: `aibox ${live ? '' : 'loading'}`},
        h('strong', null, 'SPARK Threat Triage: '),
        error ? `${payload.triage} Keeping the page free of fallback mock data.` : payload.triage
      ),
      h('div', {className: 'g12'},
        h('div', {className: 'card'},
          h('div', {className: 'ch'},
            h('div', null, h('div', {className: 'ct'}, 'Active Alert Summary'), h('div', {className: 'cs'}, 'Kill Chain - active incident correlation')),
            h('span', {className: `badge ${live ? 'blive' : 'binfo'}`}, live ? 'Live' : 'Loading')
          ),
          h('div', {className: 'cb'}, h(ActiveAlertSummary, {chain: payload.kill_chain, alert: payload.alerts?.[0], onFilter: addFilter}))
        ),
        h('div', {className: 'card'},
          h('div', {className: 'ch'},
            h('div', null, h('div', {className: 'ct'}, 'MITRE ATT&CK Heatmap'), h('div', {className: 'cs'}, 'Detection activity from Wazuh rule MITRE fields')),
            h('span', {className: 'ca'}, 'Full matrix')
          ),
          h('div', {className: 'cb'}, h(MitreHeatmap, {facets: payload.facets, onFilter: addFilter}))
        )
      ),
      h('div', {className: 'g11'},
        h(AlertFeed, {alerts: payload.alerts || [], total: payload.total || 0, filters, setFilters, search: searchInput, setSearch: setSearchInput, range, setRange}),
        h(SeverityTrend, {data: payload})
      )
    );
  }

  const root = document.getElementById('threat-root');
  if (root) ReactDOM.createRoot(root).render(h(ThreatDetectionApp));
})();

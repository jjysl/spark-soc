(function () {
  const {useEffect, useMemo, useRef, useState} = React;

  const h = React.createElement;

  function clsPriority(priority) {
    return {P1: 'bp1', P2: 'bp2', P3: 'bp3', P4: 'bp4'}[priority] || 'bp3';
  }

  function fmtNum(value) {
    if (value === undefined || value === null) return '...';
    return Number(value).toLocaleString('en-US');
  }

  function KpiCard({label, value, detail, critical, tone}) {
    const style = tone ? {color: `var(--${tone})`} : null;
    return h('div', {className: `kpi ${critical ? 'ka' : ''}`},
      h('div', {className: 'kl'}, label),
      h('div', {className: 'kv', style}, value),
      h('div', {className: 'kd', dangerouslySetInnerHTML: {__html: detail || ''}})
    );
  }

  const RANGES = ['1h', '6h', '24h', '7d', '30d'];

  function TimeSelector({value, onChange, disabled}) {
    return h('div', {className: 'tsel'},
      RANGES.map(item =>
        h('span', {
          key: item,
          className: item === value ? 'active' : '',
          onClick: disabled ? undefined : () => onChange(item),
          title: `Query ${item} in Wazuh Indexer`,
        }, item)
      )
    );
  }

  function SourceBadge({label, ok, loading}) {
    const state = loading ? 'loading' : (ok ? 'ok' : 'warn');
    const suffix = loading ? 'Syncing' : (ok ? 'Online' : 'Partial');
    return h('span', {className: `source-chip ${state}`},
      h('span', {className: 'source-dot'}),
      `${label} ${suffix}`
    );
  }

  function LoadingOverview({error}) {
    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'Executive Overview'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), 'Syncing Wazuh, FortiGate and Shuffle telemetry...')
        ),
        h('div', {className: 'ha'}, h(TimeSelector, {value: '24h', disabled: true}), h('button', {className: 'btn', disabled: true}, 'Export Report'), h('button', {className: 'btn btnp', disabled: true}, 'Open Service Request'))
      ),
      h('div', {className: 'krow'},
        ['P1 - Critical Incidents', 'MTTD', 'MTTR', 'SLA Compliance', 'Monitored Assets'].map((label, idx) =>
          h('div', {className: `kpi ${idx === 0 ? 'ka' : ''}`, key: label},
            h('div', {className: 'kl'}, label),
            h('div', {className: 'kv skel', style: {width: idx === 0 ? 42 : 72, height: 28}}, '...'),
            h('div', {className: 'kd skel', style: {width: idx === 4 ? 110 : 92, height: 12}}, '...')
          )
        )
      ),
      h('div', {className: 'aibox loading'},
        h('strong', null, 'SPARK Live Triage: '),
        error ? `Failed to fetch /spark/executive-overview (${error}).` : 'Collecting live telemetry. The view will populate when the first snapshot is ready.'
      ),
      h('div', {className: 'source-strip'},
        h(SourceBadge, {label: 'Wazuh', loading: true}),
        h(SourceBadge, {label: 'FortiGate', loading: true}),
        h(SourceBadge, {label: 'Shuffle', loading: true})
      ),
      h('div', {className: 'g21'},
        h('div', {className: 'card'}, h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Security Posture Score'), h('div', {className: 'cs'}, 'Waiting for live snapshot'))), h('div', {className: 'cb'}, h('div', {className: 'skel', style: {height: 140}}, '...'))),
        h('div', {className: 'card'}, h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Alert Volume - Last 24h'), h('div', {className: 'cs'}, 'Waiting for Wazuh Indexer'))), h('div', {className: 'cb'}, h('div', {className: 'skel', style: {height: 140}}, '...')))
      )
    );
  }

  function syncDashboardChrome(data) {
    const errors = data?.errors || {};
    const p1 = data?.kpis?.critical_incidents ?? 0;
    const alerts = data?.kpis?.events_24h ?? 0;
    const hasErrors = Object.keys(errors).length > 0;
    const systemStatus = document.getElementById('globalSystemStatus');
    const p1Status = document.getElementById('globalP1Status');
    const alertBadge = document.getElementById('globalAlertBadge');

    if (systemStatus) {
      systemStatus.innerHTML = `<div class="sdot ${hasErrors ? 'sr' : 'sg'}"></div>${hasErrors ? 'Live sources degraded' : 'All live sources operational'}`;
    }
    if (p1Status) {
      p1Status.innerHTML = '<div class="sdot sr"></div>' + p1 + ' P1 open';
    }
    if (alertBadge) {
      alertBadge.textContent = alerts;
    }
  }

  function DetailCell({label, value, onFilter}) {
    return h('div', {className: 'detail-cell'},
      h('div', {className: 'detail-label'}, label),
      h('div', {className: 'detail-value'}, value || '-'),
      value && onFilter ? h('button', {
        className: 'detail-filter',
        onClick: event => {
          event.stopPropagation();
          onFilter(label, value);
        },
      }, 'Filter') : null
    );
  }

  function WorkqueueTable({items, onCaseUpdate}) {
    const [openId, setOpenId] = useState(null);
    const [query, setQuery] = useState('');
    const [priority, setPriority] = useState('all');
    const [detailTab, setDetailTab] = useState('table');
    const [fieldFilters, setFieldFilters] = useState([]);
    const [actionState, setActionState] = useState('');
    const normalizedQuery = query.trim().toLowerCase();
    const filteredItems = items.filter(item => {
      const matchesPriority = priority === 'all' || item.priority === priority;
      const haystack = [
        item.id,
        item.description,
        item.agentName,
        item.agentIp,
        item.srcIp,
        item.dstIp,
        item.tactic,
        item.technique,
        item.status,
        item.documentId,
        item.index,
        item.level,
        Array.isArray(item.groups) ? item.groups.join(' ') : item.groups,
        item.decoderName,
        item.location,
      ].join(' ').toLowerCase();
      const matchesQuery = !normalizedQuery || haystack.includes(normalizedQuery);
      const matchesFieldFilters = fieldFilters.every(filter => haystack.includes(String(filter.value).toLowerCase()));
      return matchesPriority && matchesQuery && matchesFieldFilters;
    });
    const priorities = ['all', 'P1', 'P2', 'P3', 'P4'];

    function addFieldFilter(label, value) {
      if (!value) return;
      const next = {label, value: String(value)};
      setFieldFilters(filters => {
        if (filters.some(filter => filter.label === next.label && filter.value === next.value)) return filters;
        return [...filters, next];
      });
    }

    function removeFieldFilter(index) {
      setFieldFilters(filters => filters.filter((_, idx) => idx !== index));
    }

    function renderDetails(item) {
      function updateCase(patch) {
        if (!item.caseId) return;
        setActionState(`Updating ${item.caseId}...`);
        fetch(`/spark/incident-cases/${encodeURIComponent(item.caseId)}`, {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          credentials: 'include',
          body: JSON.stringify(patch),
        }).then(response => {
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          return response.json();
        }).then(updated => {
          setActionState(`${updated.case_id || item.caseId} updated`);
          onCaseUpdate && onCaseUpdate();
        }).catch(error => {
          setActionState(`Update failed: ${error.message}`);
          console.error(error);
        });
      }
      const actions = h('div', {style: {display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12}},
        h('button', {className: 'btn', onClick: event => { event.stopPropagation(); updateCase({status: 'investigating'}); }}, 'Start Investigation'),
        h('button', {className: 'btn', onClick: event => { event.stopPropagation(); updateCase({owner: 'SOC Analyst'}); }}, 'Assign Owner'),
        h('button', {className: 'btn btnp', onClick: event => { event.stopPropagation(); updateCase({status: 'closed'}); }}, 'Close Case'),
        actionState ? h('span', {style: {fontSize: 11, color: 'var(--tm)'}}, actionState) : null
      );
      if (detailTab === 'json') {
        return h(React.Fragment, null, actions, h('pre', {className: 'detail-log'}, JSON.stringify(item, null, 2)));
      }
      if (detailTab === 'rule') {
        return h(React.Fragment, null, actions, h('div', {className: 'alert-detail'},
          h(DetailCell, {label: 'Rule ID', value: item.id, onFilter: addFieldFilter}),
          h(DetailCell, {label: 'Rule Level', value: item.level, onFilter: addFieldFilter}),
          h(DetailCell, {label: 'Groups', value: Array.isArray(item.groups) ? item.groups.join(', ') : item.groups, onFilter: addFieldFilter}),
          h(DetailCell, {label: 'Decoder', value: item.decoderName, onFilter: addFieldFilter}),
          h(DetailCell, {label: 'Description', value: item.description}),
          h(DetailCell, {label: 'SOCaaS Priority', value: item.priority, onFilter: addFieldFilter}),
          h(DetailCell, {label: 'SLA Policy', value: item.slaPolicy}),
          h(DetailCell, {label: 'Current State', value: item.status, onFilter: addFieldFilter}),
          item.fullLog ? h('pre', {className: 'detail-log'}, item.fullLog) : null
        ));
      }
      return h(React.Fragment, null, actions, h('div', {className: 'alert-detail'},
        h(DetailCell, {label: 'Rule / Level', value: `${item.id} / level ${item.level}`, onFilter: () => addFieldFilter('Rule', item.id)}),
        h(DetailCell, {label: 'Agent', value: `${item.agentName || '-'} (${item.agentIp || item.agentId || '-'})`, onFilter: () => addFieldFilter('Agent', item.agentName || item.agentIp || item.agentId)}),
        h(DetailCell, {label: 'Source -> Destination', value: `${item.srcIp || '-'}${item.srcPort ? ':' + item.srcPort : ''} -> ${item.dstIp || '-'}${item.dstPort ? ':' + item.dstPort : ''}`}),
        h(DetailCell, {label: 'MITRE', value: `${item.tactic || '-'} ${item.technique || ''}`.trim(), onFilter: () => addFieldFilter('MITRE', item.technique || item.tactic)}),
        h(DetailCell, {label: 'Decoder / Location', value: `${item.decoderName || '-'} / ${item.location || '-'}`, onFilter: () => addFieldFilter('Decoder', item.decoderName || item.location)}),
        h(DetailCell, {label: 'Index', value: item.index, onFilter: addFieldFilter}),
        h(DetailCell, {label: 'Document ID', value: item.documentId, onFilter: addFieldFilter}),
        h(DetailCell, {label: 'SLA Policy', value: `${item.slaPolicy || '-'} (${item.slaState || 'unknown'})`}),
        h(DetailCell, {label: 'Case Created', value: item.createdAt}),
        h(DetailCell, {label: 'SLA Due', value: item.dueAt}),
        h(DetailCell, {label: 'Source Alert Time', value: item.alertTimestamp}),
        item.fullLog ? h('pre', {className: 'detail-log'}, item.fullLog) : null
      ));
    }

    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Open Incidents - Service Workqueue'),
          h('div', {className: 'cs'}, 'SLA thresholds: P1 15 min · P2 45 min · P3 90 min · P4 6h · per Fortinet SOCaaS escalation policy')
        ),
        h('span', {className: 'ca'}, `${filteredItems.length}/${items.length} items`)
      ),
      h('div', {className: 'wq-tools'},
        h('input', {
          className: 'wq-search',
          value: query,
          onChange: event => setQuery(event.target.value),
          placeholder: 'Search rule, agent, IP, MITRE, status or document...',
        }),
        h('div', {className: 'wq-filter'},
          priorities.map(value =>
            h('button', {
              key: value,
              className: priority === value ? 'active' : '',
              onClick: () => setPriority(value),
            }, value === 'all' ? 'All' : value)
          )
        )
      ),
      fieldFilters.length ? h('div', {className: 'filter-tokens'},
        fieldFilters.map((filter, index) =>
          h('span', {className: 'filter-token', key: `${filter.label}-${filter.value}`},
            `${filter.label}: ${filter.value}`,
            h('button', {onClick: () => removeFieldFilter(index)}, 'x')
          )
        ),
        h('button', {className: 'detail-filter', onClick: () => setFieldFilters([])}, 'Clear filters')
      ) : null,
      h('table', {className: 'ftable'},
        h('thead', null,
          h('tr', null,
            ['Incident ID', 'Time', 'Description', 'MITRE Tactic', 'Priority', 'Analyst', 'SLA Remaining', 'Status']
              .map(col => h('th', {key: col}, col))
          )
        ),
        h('tbody', null,
          filteredItems.length ? filteredItems.flatMap(item => {
            const rowKey = `${item.id}-${item.documentId || item.time}`;
            const isOpen = openId === rowKey;
            return [
              h('tr', {key: rowKey, onClick: () => setOpenId(isOpen ? null : rowKey)},
                h('td', null, h('span', {className: 'mono'}, item.id || 'WAZUH')),
                h('td', null, h('span', {className: 'mono'}, item.time || '--:--')),
                h('td', null, h('span', {className: 'edesc', title: item.description}, item.description || 'Wazuh alert')),
                h('td', null, h('span', {className: 'tpill'}, item.tactic || 'Detection')),
                h('td', null, h('span', {className: `badge ${item.badge || clsPriority(item.priority)}`}, item.priority || 'P3')),
                h('td', {style: {fontSize: 12, color: 'var(--t2)'}}, item.analyst || 'Unassigned'),
                h('td', null,
                  h('div', {className: 'slaw'},
                    h('span', {className: `slat ${item.slaClass || 'slok'}`}, item.sla || '-'),
                    h('div', {className: 'slbar'},
                      h('div', {className: `slbf ${item.fillClass || 'fok'}`, style: {width: `${item.slaPct || 0}%`}})
                    )
                  )
                ),
                h('td', null, h('span', {className: `badge ${item.statusBadge || 'bnew'}`}, item.status || 'New'))
              ),
              isOpen && h('tr', {key: `${rowKey}-detail`, className: 'detail-row'},
                h('td', {colSpan: 8},
                  h('div', null,
                    h('div', {className: 'detail-tabs'},
                      ['table', 'json', 'rule'].map(tab =>
                        h('button', {
                          key: tab,
                          className: detailTab === tab ? 'active' : '',
                          onClick: event => {
                            event.stopPropagation();
                            setDetailTab(tab);
                          },
                        }, tab.toUpperCase())
                      )
                    ),
                    renderDetails(item)
                  )
                )
              )
            ].filter(Boolean);
          }) : h('tr', null,
            h('td', {colSpan: 8, style: {color: 'var(--tm)', textAlign: 'center'}}, 'No alerts match the selected filters')
          )
        )
      )
    );
  }

  function AlertVolumeChart({timeline, total, range}) {
    const canvasRef = useRef(null);
    const chartRef = useRef(null);

    useEffect(() => {
      if (!canvasRef.current || !window.Chart) return;
      const rows = Array.isArray(timeline) ? timeline.slice(-24) : [];
      const labels = rows.length ? rows.map(row => {
        const hour = row.hour || '';
        return hour.length >= 13 ? `${hour.substring(11, 13)}:00` : '--:--';
      }) : Array.from({length: 24}, (_, idx) => `${String(idx).padStart(2, '0')}:00`);
      const datasets = [
        {label: 'P1 Critical', data: rows.map(row => row.p1 || 0), backgroundColor: '#da291c', stack: 'a', barPercentage: .75},
        {label: 'P2 High', data: rows.map(row => row.p2 || 0), backgroundColor: '#f59e0b', stack: 'a', barPercentage: .75},
        {label: 'P3 / P4', data: rows.map(row => row.p3 || 0), backgroundColor: '#e2e5ea', stack: 'a', barPercentage: .75},
      ];

      if (chartRef.current) chartRef.current.destroy();
      chartRef.current = new Chart(canvasRef.current.getContext('2d'), {
        type: 'bar',
        data: {labels, datasets},
        options: {
          responsive: true,
          maintainAspectRatio: true,
          animation: {duration: 250},
          plugins: {legend: {position: 'top', align: 'end', labels: {boxWidth: 10, boxHeight: 10, font: {size: 10, family: 'Inter'}, padding: 10}}},
          scales: {
            x: {stacked: true, grid: {display: false}, ticks: {font: {size: 9, family: 'JetBrains Mono'}, color: '#8a95a3', maxTicksLimit: 8, maxRotation: 0}},
            y: {stacked: true, grid: {color: '#e2e5ea', lineWidth: .5}, ticks: {font: {size: 10}, color: '#8a95a3'}, border: {display: false}},
          },
        },
      });
      return () => {
        if (chartRef.current) chartRef.current.destroy();
      };
    }, [timeline]);

    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, `Alert Volume - ${range}`),
          h('div', {className: 'cs'}, `Wazuh Indexer - range ${range}`)
        )
      ),
      h('div', {className: 'cwrap'}, h('canvas', {ref: canvasRef})),
      h('div', {style: {borderTop: '1px solid var(--border)', display: 'grid', gridTemplateColumns: '1fr 1fr', textAlign: 'center'}},
        h('div', {style: {padding: '10px 8px', borderRight: '1px solid var(--border)'}},
          h('div', {style: {fontSize: 16, fontWeight: 600}}, fmtNum(total)),
          h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'Events processed')
        ),
        h('div', {style: {padding: '10px 8px'}},
          h('div', {style: {fontSize: 16, fontWeight: 600}}, `${timeline?.length || 0}h`),
          h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'Timeline buckets')
        )
      )
    );
  }

  function PostureScore({data}) {
    const p1 = data?.kpis?.critical_incidents || 0;
    const fg = data?.fortigate || {};
    const posture = data?.posture || {score: 0, rows: []};
    const score = posture.score || 0;
    const offset = 289 - (289 * score / 100);
    const rows = posture.rows || [];

    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Security Posture Score'),
          h('div', {className: 'cs'}, 'Fortinet SOCaaS composite score from Wazuh, FortiGate and Shuffle')
        ),
        h('span', {className: 'badge bexp'}, 'Live')
      ),
      h('div', {className: 'sring'},
        h('svg', {width: 115, height: 115, viewBox: '0 0 115 115', style: {flexShrink: 0}},
          h('circle', {cx: 57, cy: 57, r: 46, fill: 'none', stroke: '#e2e5ea', strokeWidth: 6}),
          h('circle', {cx: 57, cy: 57, r: 46, fill: 'none', stroke: score >= 80 ? '#10b981' : '#f59e0b', strokeWidth: 6, strokeLinecap: 'round', strokeDasharray: 289, strokeDashoffset: offset, transform: 'rotate(-90 57 57)'}),
          h('text', {x: 57, y: 53, textAnchor: 'middle', fontSize: 26, fontWeight: 600, fill: '#0d1421', fontFamily: 'Inter,sans-serif'}, score),
          h('text', {x: 57, y: 67, textAnchor: 'middle', fontSize: 10, fill: '#8a95a3', fontFamily: 'Inter,sans-serif'}, '/ 100'),
          h('text', {x: 57, y: 80, textAnchor: 'middle', fontSize: 9, fill: score >= 80 ? '#047857' : '#b45309', fontFamily: 'Inter,sans-serif', fontWeight: 600}, score >= 80 ? 'HEALTHY' : 'MODERATE')
        ),
        h('div', {className: 'sbk'},
          h('div', {style: {fontSize: 10, fontWeight: 600, color: 'var(--tm)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6}}, 'Score Breakdown'),
          rows.map(({name, value}) => {
            const color = value >= 80 ? '#10b981' : value >= 60 ? '#f59e0b' : '#da291c';
            return (
            h('div', {className: 'sci', key: name},
              h('span', {className: 'scl'}, name),
              h('div', {className: 'scbg'}, h('div', {className: 'scf', style: {width: `${value}%`, background: color}})),
              h('span', {className: 'scv'}, value)
            )
            );
          })
        )
      ),
      h('div', {style: {borderTop: '1px solid var(--border)', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', textAlign: 'center'}},
        h('div', {style: {padding: '11px 8px', borderRight: '1px solid var(--border)'}}, h('div', {style: {fontSize: 18, fontWeight: 600, color: 'var(--red)'}}, p1), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'P1 Alerts')),
        h('div', {style: {padding: '11px 8px', borderRight: '1px solid var(--border)'}}, h('div', {style: {fontSize: 18, fontWeight: 600, color: 'var(--amber)'}}, data?.wazuh?.alerts?.length || 0), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'Recent Alerts')),
        h('div', {style: {padding: '11px 8px'}}, h('div', {style: {fontSize: 18, fontWeight: 600, color: 'var(--green)'}}, `${fg.mem ?? 0}%`), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'FG Memory'))
      )
    );
  }

  function ExecutiveOverviewApp() {
    const [data, setData] = useState(null);
    const [error, setError] = useState('');
    const [updatedAt, setUpdatedAt] = useState(null);
    const [range, setRange] = useState('24h');
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState('');

    async function load(selectedRange = range, refresh = false) {
      setLoading(true);
      try {
        const response = await fetch(`/spark/executive-overview?range=${encodeURIComponent(selectedRange)}${refresh ? '&refresh=1' : ''}`, {credentials: 'include'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        setData(payload);
        syncDashboardChrome(payload);
        setUpdatedAt(new Date());
        setError('');
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    useEffect(() => {
      load();
      const timer = setInterval(load, 30000);
      return () => clearInterval(timer);
    }, [range]);

    function exportReport() {
      const report = {
        generated_at: new Date().toISOString(),
        range,
        kpis: data?.kpis || {},
        case_lifecycle: data?.case_lifecycle || {},
        source_status: data?.errors || {},
        workqueue: data?.workqueue || [],
      };
      const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `spark-soc-executive-${range}-${Date.now()}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setMessage('Executive report exported as JSON.');
    }

    async function openServiceRequest() {
      const topCase = workqueue[0];
      if (!topCase) {
        setMessage('No open case available for service request.');
        return;
      }
      setMessage('Creating service request...');
      try {
        const response = await fetch('/spark/tickets', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          credentials: 'include',
          body: JSON.stringify({
            title: `Service request for ${topCase.id}: ${topCase.description}`,
            priority: String(topCase.priority || 'P3').toLowerCase(),
            type: 'incident',
            assignee: topCase.analyst === 'Unassigned' ? 'SOC' : topCase.analyst,
            incidentLink: topCase.id,
            mitre: topCase.tactic || '',
            ip: topCase.srcIp || topCase.agentIp || '',
            desc: `Opened from Executive Overview workqueue case ${topCase.id}. SLA: ${topCase.sla}. Status: ${topCase.status}.`,
          }),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const ticket = await response.json();
        setMessage(`Service request ${ticket.id} created.`);
      } catch (error) {
        setMessage(`Service request failed: ${error.message}`);
      }
    }

    const kpis = data?.kpis || {};
    const fortigate = data?.fortigate || {};
    const workqueue = data?.workqueue || [];
    const timeline = data?.wazuh?.timeline || [];
    const status = useMemo(() => ({
      wazuh: Boolean(data?.wazuh),
      fortigate: fortigate.source === 'fortigate-live',
      shuffle: Boolean(data?.shuffle?.connected),
    }), [data]);

    if (!data) {
      return h(LoadingOverview, {error});
    }

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'Executive Overview'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), loading ? `Updating ${range} telemetry...` : updatedAt ? `Live - updated ${updatedAt.toLocaleTimeString('en-US')}` : 'Syncing live sources...')
        ),
        h('div', {className: 'ha'},
          h(TimeSelector, {value: range, onChange: setRange}),
          h('button', {className: 'btn', onClick: exportReport}, 'Export Report'),
          h('button', {className: 'btn btnp', onClick: openServiceRequest}, 'Open Service Request')
        )
      ),
      h('div', {className: 'krow'},
        h(KpiCard, {label: 'P1 - Critical Incidents', value: fmtNum(kpis.critical_incidents), detail: `<span class="up">${fmtNum(kpis.events ?? kpis.events_24h)}</span> alerts ${data?.range || range}`, critical: true}),
        h(KpiCard, {label: 'MTTD', value: kpis.mttd || 'N/A', detail: `<span class="dn">${kpis.mttd_detail || 'Incident lifecycle unavailable'}</span>`}),
        h(KpiCard, {label: 'MTTR', value: kpis.mttr || 'N/A', detail: status.shuffle ? `<span class="dn">${kpis.mttr_detail || 'Waiting for resolved tickets'}</span>` : '<span class="up">Shuffle partial</span>'}),
        h(KpiCard, {label: 'SLA Compliance', value: kpis.sla_compliance == null ? 'N/A' : `${kpis.sla_compliance}%`, detail: `<span class="dn">${kpis.sla_detail || 'No measurable alerts'} - target ${kpis.sla_target || 95}%</span>`, tone: 'green'}),
        h(KpiCard, {label: 'Monitored Assets', value: fmtNum(kpis.monitored_assets), detail: `<span class="up">${fmtNum(kpis.assets_alerting)}</span> in alert state`})
      ),
      h('div', {className: 'aibox'},
        h('strong', null, 'SPARK Live Triage: '),
        message ? message : error ? `update error (${error}). Keeping last state.` : (data?.triage || 'Loading live telemetry...')
      ),
      h('div', {className: 'source-strip'},
        h(SourceBadge, {label: 'Wazuh', ok: status.wazuh}),
        h(SourceBadge, {label: 'FortiGate', ok: status.fortigate}),
        h(SourceBadge, {label: 'Shuffle', ok: status.shuffle})
      ),
      h('div', {className: 'g21'}, h(PostureScore, {data}), h(AlertVolumeChart, {timeline, total: (kpis.events ?? kpis.events_24h) || 0, range: data?.range || range})),
      h(WorkqueueTable, {items: workqueue, onCaseUpdate: () => load(range, true)})
    );
  }

  const root = document.getElementById('executive-root');
  if (root) ReactDOM.createRoot(root).render(h(ExecutiveOverviewApp));
})();

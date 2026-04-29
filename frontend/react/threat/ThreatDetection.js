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
  const MITRE_HEATMAP_COLUMNS = [
    ['Recon', 'Reconnaissance'],
    ['Resource Dev', 'Resource Development'],
    ['Initial Access', 'Initial Access'],
    ['Execution', 'Execution'],
    ['Persistence', 'Persistence'],
    ['Priv Esc', 'Privilege Escalation'],
    ['Def. Evasion', 'Defense Evasion'],
    ['Cred. Access', 'Credential Access'],
    ['Discovery', 'Discovery'],
    ['Lateral Move', 'Lateral Movement'],
    ['Exfiltration', 'Exfiltration'],
  ];

  function fmtNum(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function clsPriority(priority) {
    return {P1: 'bp1', P2: 'bp2', P3: 'bp3', P4: 'bp4'}[priority] || 'bp3';
  }

  function fmtTime(value) {
    if (!value) return '--:--:--';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value.length >= 19 ? value.substring(11, 19) : '--:--:--';
    return date.toLocaleTimeString('en-US', {hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'});
  }

  function fmtDateTime(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString('en-US', {
      month: 'short',
      day: '2-digit',
      year: 'numeric',
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }

  function shortTactic(value) {
    return String(value || 'Detection')
      .replace('Command and Control', 'Command & Control');
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
    const stages = chain?.stages?.length ? chain.stages : [
      {
        name: alert?.mitre_tactic || 'Detection',
        detail: `${alert?.description || 'Wazuh detection'} - ${alert?.agent_name || alert?.location || 'observed asset'} - ${alert?.mitre_technique || 'no MITRE technique'}`,
        state: 'active',
        document_id: alert?.document_id || '',
        src_ip: alert?.src_ip || '',
        agent_name: alert?.agent_name || '',
      },
    ];
    return h(React.Fragment, null,
      h('div', {style: {display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 12}},
        h('div', null,
          h('div', {style: {fontSize: 15, fontWeight: 700, color: 'var(--t1)'}}, chain?.title || 'Kill Chain - Active Detection'),
          h('div', {style: {fontSize: 11, color: 'var(--tm)', marginTop: 3}}, chain?.subtitle || 'Latest normalized Wazuh detection')
        ),
        h('span', {className: `badge ${clsPriority(chain?.priority || alert?.priority)}`}, chain?.priority || alert?.priority || 'P3')
      ),
      stages.map(stage => h('div', {className: 'kcstep', key: `${stage.name}-${stage.document_id || stage.state}`},
        h('div', {className: `kcicon ${stage.state === 'active' ? 'act' : stage.state === 'done' ? 'done' : 'pend'}`}, stage.state === 'pending' ? '...' : stage.state === 'active' ? '>' : 'OK'),
        h('div', null,
          h('div', {className: 'kct'}, stage.name),
          h('div', {className: 'kcs'}, stage.detail),
          stage.document_id ? h(FilterButton, {field: stage.src_ip ? 'src_ip' : 'agent.name', value: stage.src_ip || stage.agent_name, label: 'filter', onFilter}) : null
        )
      ))
    );
  }

  function matchesFilter(alert, filter) {
    const value = String(filter.value || '').toLowerCase();
    if (!value) return true;
    const groups = Array.isArray(alert.groups) ? alert.groups.map(item => String(item).toLowerCase()) : [];
    const fieldMap = {
      'rule.id': alert.rule_id,
      'rule.level': alert.level,
      'rule.groups': groups.join(' '),
      'agent.id': alert.agent_id,
      'agent.name': alert.agent_name,
      'agent.ip': alert.agent_ip,
      'manager.name': alert.manager_name,
      'decoder.name': alert.decoder_name,
      location: alert.location,
      src_ip: alert.src_ip || alert.agent_ip,
      dst_ip: alert.dst_ip,
      'mitre.tactic': alert.mitre_tactic,
      'mitre.technique': alert.mitre_technique,
      priority: alert.priority,
      status: alert.status,
    };
    return String(fieldMap[filter.field] ?? '').toLowerCase().includes(value);
  }

  function alertHaystack(alert) {
    return [
      alert.timestamp,
      alert.description,
      alert.rule_id,
      alert.level,
      alert.agent_name,
      alert.agent_ip,
      alert.src_ip,
      alert.dst_ip,
      alert.decoder_name,
      alert.location,
      alert.mitre_tactic,
      alert.mitre_technique,
      alert.priority,
      alert.status,
      alert.full_log,
      Array.isArray(alert.groups) ? alert.groups.join(' ') : '',
    ].join(' ').toLowerCase();
  }

  function applyLocalAlertFilters(alerts, filters, query) {
    const needle = String(query || '').trim().toLowerCase();
    return (alerts || []).filter(alert =>
      (!needle || alertHaystack(alert).includes(needle)) &&
      (filters || []).every(filter => matchesFilter(alert, filter))
    );
  }

  function MitreHeatmap({alerts, onFilter}) {
    const rows = 4;
    const matrix = Array.from({length: rows}, () => MITRE_HEATMAP_COLUMNS.map(() => 0));
    (alerts || []).forEach(alert => {
      const priority = alert.priority || 'P4';
      const row = Math.max(0, Math.min(rows - 1, Number(priority.replace('P', '')) - 1 || rows - 1));
      const tactic = alert.mitre_tactic || '';
      let col = MITRE_HEATMAP_COLUMNS.findIndex(([, full]) => full === tactic);
      if (col === -1 && tactic === 'Command and Control') col = MITRE_HEATMAP_COLUMNS.findIndex(([, full]) => full === 'Exfiltration');
      if (col === -1 && tactic === 'Impact') col = MITRE_HEATMAP_COLUMNS.findIndex(([, full]) => full === 'Defense Evasion');
      if (col === -1) col = MITRE_HEATMAP_COLUMNS.findIndex(([, full]) => full === 'Discovery');
      matrix[row][col] += 1;
    });
    const max = Math.max(1, ...matrix.flat());
    const colors = ['#f1f5f9', '#fee2e2', '#fca5a5', '#f87171', '#ef4444', '#b91c1c'];
    return h(React.Fragment, null,
      h('div', {style: {display: 'grid', gridTemplateColumns: 'repeat(11,1fr)', gap: 2, marginBottom: 5}},
        MITRE_HEATMAP_COLUMNS.map(([label, full]) => h('div', {
          key: full,
          title: full,
          style: {fontSize: 8.5, fontWeight: 600, color: 'var(--tm)', textAlign: 'center', lineHeight: 1.2, paddingBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'},
        }, label))
      ),
      h('div', {style: {display: 'grid', gridTemplateColumns: 'repeat(11,1fr)', gap: 2}},
        matrix.flatMap((row, rowIndex) => row.map((count, colIndex) => {
          const score = count ? Math.max(1, Math.min(5, Math.ceil((count / max) * 5))) : 0;
          const [label, tactic] = MITRE_HEATMAP_COLUMNS[colIndex];
          const color = colors[score];
          return h('div', {
            key: `${rowIndex}-${tactic}`,
            title: `${label} - ${count} real alert${count === 1 ? '' : 's'}`,
            onClick: () => count && onFilter('mitre.tactic', tactic),
            onMouseOver: event => { event.currentTarget.style.opacity = '.7'; },
            onMouseOut: event => { event.currentTarget.style.opacity = '1'; },
            style: {aspectRatio: '1', borderRadius: 3, background: color, cursor: count ? 'pointer' : 'default', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, fontWeight: 600, color: score >= 3 ? '#fff' : '#991b1b', transition: 'opacity .15s'},
          }, score ? score : '');
        }))
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
      h('td', {colSpan: 6},
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

  function AlertFeed({alerts, total, filters, setFilters, search, range}) {
    const [openId, setOpenId] = useState('');
    const [detailTab, setDetailTab] = useState('summary');
    const [rowsPerPage, setRowsPerPage] = useState(10);
    const [page, setPage] = useState(1);
    const locallyFilteredAlerts = useMemo(() => applyLocalAlertFilters(alerts, filters, search), [alerts, filters, search]);
    const sortedAlerts = useMemo(() => [...locallyFilteredAlerts].sort((a, b) => {
      const left = new Date(a.timestamp || 0).getTime() || 0;
      const right = new Date(b.timestamp || 0).getTime() || 0;
      return right - left;
    }), [locallyFilteredAlerts]);
    const totalPages = Math.max(1, Math.ceil(sortedAlerts.length / rowsPerPage));
    const currentPage = Math.min(page, totalPages);
    const visibleAlerts = sortedAlerts.slice((currentPage - 1) * rowsPerPage, currentPage * rowsPerPage);

    function addFilter(field, value) {
      if (!value) return;
      setOpenId('');
      setFilters(items => items.some(item => item.field === field && item.value === String(value)) ? items : [...items, {field, value: String(value)}]);
    }

    useEffect(() => {
      setPage(1);
      setOpenId('');
    }, [rowsPerPage, range, search, JSON.stringify(filters), alerts.length]);

    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Correlated Alert Feed'),
          h('div', {className: 'cs'}, 'Wazuh + FortiGate - AI-enriched - Fabric Monitoring')
        ),
        h('div', {style: {display: 'flex', alignItems: 'center', gap: 12}},
          h('a', {href: '#', onClick: event => { event.preventDefault(); setRowsPerPage(50); setPage(1); }, className: 'ca'}, 'View all')
        )
      ),
      filters.length ? h('div', {className: 'filter-tokens'},
        filters.map((filter, idx) => h('span', {className: 'filter-token', key: `${filter.field}-${filter.value}`},
          `${filter.field}:${filter.value}`,
          h('button', {onClick: () => setFilters(items => items.filter((_, index) => index !== idx))}, 'x')
        ))
      ) : null,
      h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Time', 'Description', 'Source IP', 'MITRE', 'Severity', 'Status'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          visibleAlerts.length ? visibleAlerts.flatMap(alert => {
            const id = String(alert.document_id || `${alert.rule_id}-${alert.timestamp}`);
            const isOpen = openId === id;
            return [
              h('tr', {key: id, onClick: () => setOpenId(isOpen ? '' : id)},
                h('td', null, h('span', {className: 'mono', title: fmtDateTime(alert.timestamp)}, fmtTime(alert.timestamp))),
                h('td', null,
                  h('span', {className: 'edesc', title: `${alert.description || 'Wazuh alert'} - ${alert.agent_name || 'unknown'} - Rule ${alert.rule_id || '-'}`}, alert.description || 'Wazuh alert')
                ),
                h('td', null, h(FilterButton, {field: 'src_ip', value: alert.src_ip || alert.agent_ip, label: alert.src_ip || alert.agent_ip || '--', onFilter: addFilter})),
                h('td', null, h('span', {className: 'tpill', onClick: event => { event.stopPropagation(); addFilter('mitre.tactic', alert.mitre_tactic); }, style: {cursor: alert.mitre_tactic ? 'pointer' : 'default'}}, shortTactic(alert.mitre_tactic))),
                h('td', null, h('span', {className: `badge ${alert.severity_class || 'binfo'}`}, alert.severity || 'Info')),
                h('td', null, h('span', {className: `badge ${alert.status_class || 'bnew'}`}, alert.status || 'New'))
              ),
              isOpen ? h(AlertDetail, {key: `${id}-detail`, alert, tab: detailTab, setTab: setDetailTab, onFilter: addFilter}) : null,
            ].filter(Boolean);
          }) : h('tr', null, h('td', {colSpan: 6, style: {color: 'var(--tm)', fontSize: 12}}, 'No Wazuh alerts matched the current query.'))
        )
      ),
      h('div', {style: {display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', borderTop: '1px solid var(--border)'}},
        h('div', {style: {display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--tm)'}},
          h('span', null, 'Rows per page:'),
          h('select', {
            className: 'jm-select',
            style: {width: 86, padding: '5px 8px', fontSize: 11},
            value: rowsPerPage,
            onChange: event => setRowsPerPage(Number(event.target.value)),
          }, [10, 25, 50].map(value => h('option', {key: value, value}, `${value} rows`)))
        ),
        h('div', {style: {display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--tm)'}},
          h('span', null, `${sortedAlerts.length ? ((currentPage - 1) * rowsPerPage) + 1 : 0}-${Math.min(currentPage * rowsPerPage, sortedAlerts.length)} of ${sortedAlerts.length}`),
          h('button', {className: 'btn', disabled: currentPage <= 1, onClick: () => setPage(value => Math.max(1, value - 1))}, 'Prev'),
          h('button', {className: 'btn', disabled: currentPage >= totalPages, onClick: () => setPage(value => Math.min(totalPages, value + 1))}, 'Next')
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

  function extractIndicators(alerts) {
    const privateIp = /^(10\.|127\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|169\.254\.)/;
    const ipLike = value => /^\d{1,3}(\.\d{1,3}){3}$/.test(String(value || '')) && !privateIp.test(String(value || ''));
    const domainRegex = /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|ru|cn|br|info|biz|xyz)\b/gi;
    const hashRegex = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g;
    const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/gi;
    const ips = new Set();
    const domains = new Set();
    const hashes = new Set();
    const cves = new Set();

    (alerts || []).forEach(alert => {
      [alert.src_ip, alert.dst_ip].forEach(ip => {
        if (ipLike(ip)) ips.add(ip);
      });
      const text = `${alert.description || ''} ${alert.full_log || ''} ${JSON.stringify(alert.raw || {})}`;
      (text.match(domainRegex) || []).forEach(domain => {
        const clean = domain.toLowerCase();
        if (!clean.includes('wazuh.com') && !clean.includes('opensearch.org')) domains.add(clean);
      });
      (text.match(hashRegex) || []).forEach(hash => hashes.add(hash.toLowerCase()));
      (text.match(cveRegex) || []).forEach(cve => cves.add(cve.toUpperCase()));
    });

    return {ips: [...ips], domains: [...domains], hashes: [...hashes], cves: [...cves]};
  }

  function ThreatIntelFeed({data}) {
    const canvasRef = useRef(null);
    const chartRef = useRef(null);
    const alerts = data?.alerts || [];
    const indicators = useMemo(() => extractIndicators(alerts), [alerts]);
    const timeline = data?.timeline || [];

    useEffect(() => {
      if (!canvasRef.current || !window.Chart) return;
      const rows = timeline.slice(-24);
      const labels = rows.map(row => row.time && row.time.length >= 13 ? row.time.substring(11, 16) : '--');
      const chartData = {
        labels,
        datasets: [
          {label: 'Malicious IPs', data: rows.map(row => (row.critical || 0) + (row.high || 0)), borderColor: '#da291c', backgroundColor: 'rgba(218,41,28,0.08)', borderWidth: 1.5, pointRadius: 2, tension: .3, fill: true},
          {label: 'Malicious Domains', data: rows.map(row => (row.medium || 0) + (row.low || 0)), borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.07)', borderWidth: 1.5, pointRadius: 2, tension: .3, fill: true},
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

    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'FortiGuard Threat Intelligence Feed'),
          h('div', {className: 'cs'}, 'IOC enrichment - outbreak alerts - FortiGuard Labs')
        ),
        h('span', {className: `badge ${data?.source === 'opensearch-live' ? 'blive' : 'bhigh'}`}, data?.source === 'opensearch-live' ? 'Live' : 'Offline')
      ),
      h('div', {className: 'cb'},
        h('div', {className: 'cwrap', style: {padding: '0 0 14px'}}, h('canvas', {ref: canvasRef})),
        h('div', {style: {display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', textAlign: 'center', borderTop: '1px solid var(--border)', paddingTop: 12}},
          h('div', {style: {borderRight: '1px solid var(--border)', padding: '0 8px'}}, h('div', {style: {fontSize: 16, fontWeight: 600, color: 'var(--red)'}}, fmtNum(indicators.ips.length)), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'Malicious IPs')),
          h('div', {style: {borderRight: '1px solid var(--border)', padding: '0 8px'}}, h('div', {style: {fontSize: 16, fontWeight: 600, color: 'var(--amber)'}}, fmtNum(indicators.domains.length)), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'Malicious Domains')),
          h('div', {style: {borderRight: '1px solid var(--border)', padding: '0 8px'}}, h('div', {style: {fontSize: 16, fontWeight: 600, color: 'var(--blue)'}}, fmtNum(indicators.hashes.length)), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'File Hashes')),
          h('div', {style: {padding: '0 8px'}}, h('div', {style: {fontSize: 16, fontWeight: 600, color: 'var(--t2)'}}, fmtNum(indicators.cves.length)), h('div', {style: {fontSize: 10, color: 'var(--tm)', marginTop: 2}}, 'Active CVEs'))
        )
      )
    );
  }

  function ThreatHuntingPanel({alerts, onFilter}) {
    const externalCount = alerts.filter(alert => alert.src_ip && !/^(10\.|127\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.)/.test(alert.src_ip)).length;
    const hunts = [
      {title: 'High-priority detections', detail: 'P1/P2 alerts in the selected window', field: 'priority', value: 'P2', count: alerts.filter(alert => ['P1', 'P2'].includes(alert.priority)).length},
      {title: 'Rootcheck / host anomaly', detail: 'Endpoint integrity and anomaly alerts', field: 'decoder.name', value: 'rootcheck', count: alerts.filter(alert => alert.decoder_name === 'rootcheck').length},
      {title: 'External source indicators', detail: 'Public source IPs observed in alerts', field: 'src_ip', value: alerts.find(alert => alert.src_ip)?.src_ip || '', count: externalCount},
      {title: 'MITRE-mapped detections', detail: 'Alerts with mapped tactic or technique fields', field: 'mitre.tactic', value: alerts.find(alert => alert.mitre_tactic)?.mitre_tactic || '', count: alerts.filter(alert => alert.mitre_tactic || alert.mitre_technique).length},
    ];
    return h('div', {className: 'card', style: {marginBottom: 14}},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Threat Hunting Workspace'),
          h('div', {className: 'cs'}, 'Quick hunts built from the current Wazuh result set')
        ),
        h('span', {className: 'badge binfo'}, `${fmtNum(alerts.length)} scoped alerts`)
      ),
      h('div', {className: 'cb', style: {display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10}},
        hunts.map(hunt => h('button', {
          key: hunt.title,
          className: 'detail-cell',
          style: {textAlign: 'left', cursor: hunt.value ? 'pointer' : 'default'},
          onClick: () => hunt.value && onFilter(hunt.field, hunt.value),
        },
          h('div', {className: 'detail-label'}, hunt.title),
          h('div', {className: 'detail-value'}, hunt.detail),
          h('div', {style: {fontSize: 18, fontWeight: 700, color: 'var(--red)', marginTop: 8}}, fmtNum(hunt.count))
        ))
      )
    );
  }

  function TriageRulePanel({filters, rules, setRules}) {
    const [name, setName] = useState('');
    const [priority, setPriority] = useState('P2');
    const condition = filters.length ? filters.map(filter => `${filter.field}:${filter.value}`).join(' AND ') : 'current visible detections';

    function saveRule() {
      const rule = {
        id: `TRIAGE-${Date.now()}`,
        name: name.trim() || `Rule ${rules.length + 1}`,
        priority,
        condition,
        action: 'Promote matching alerts to analyst review',
        created: new Date().toISOString(),
      };
      const next = [rule, ...rules].slice(0, 8);
      setRules(next);
      localStorage.setItem('sparkThreatTriageRules', JSON.stringify(next));
      setName('');
    }

    return h('div', {className: 'card', style: {marginBottom: 14}},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'New Triage Rule'),
          h('div', {className: 'cs'}, 'Local analyst rule draft from current filters')
        ),
        h('span', {className: 'badge binfo'}, `${rules.length} saved`)
      ),
      h('div', {className: 'cb'},
        h('div', {style: {display: 'grid', gridTemplateColumns: '2fr 120px auto', gap: 10, alignItems: 'end'}},
          h('div', null,
            h('div', {className: 'jm-label'}, 'Rule name'),
            h('input', {className: 'wq-search', value: name, onChange: event => setName(event.target.value), placeholder: 'Example: Rootcheck P2 anomaly triage'})
          ),
          h('div', null,
            h('div', {className: 'jm-label'}, 'Priority'),
            h('select', {className: 'jm-select', value: priority, onChange: event => setPriority(event.target.value)}, ['P1', 'P2', 'P3', 'P4'].map(item => h('option', {key: item, value: item}, item)))
          ),
          h('button', {className: 'btn btnp', onClick: saveRule}, 'Save Rule')
        ),
        h('div', {style: {fontSize: 11, color: 'var(--tm)', marginTop: 8}}, `Condition: ${condition}`),
        rules.length ? h('table', {className: 'ftable', style: {marginTop: 12}},
          h('thead', null, h('tr', null, ['Rule', 'Priority', 'Condition', 'Action'].map(col => h('th', {key: col}, col)))),
          h('tbody', null, rules.map(rule => h('tr', {key: rule.id},
            h('td', null, rule.name),
            h('td', null, h('span', {className: `badge ${clsPriority(rule.priority)}`}, rule.priority)),
            h('td', null, rule.condition),
            h('td', null, rule.action)
          )))
        ) : null
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
    const [toolPanel, setToolPanel] = useState('');
    const [triageRules, setTriageRules] = useState(() => {
      try {
        return JSON.parse(localStorage.getItem('sparkThreatTriageRules') || '[]');
      } catch {
        return [];
      }
    });

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
    }, [range, query]);

    const payload = data || {source: 'loading', total: 0, counts: {}, facets: {tactics: [], decoders: []}, timeline: [], alerts: [], triage: 'Loading Wazuh Indexer alerts.'};
    const live = payload.source === 'opensearch-live';
    const scopedAlerts = useMemo(() => applyLocalAlertFilters(payload.alerts || [], filters, searchInput), [payload.alerts, filters, searchInput]);

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'Threat Detection & Intelligence'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), loading ? `Updating ${range} detections...` : 'Wazuh Indexer - normalized detections - live filters')
        ),
        h('div', {className: 'ha'},
          h(TimeRange, {value: range, onChange: setRange}),
          h('button', {className: 'btn', onClick: () => setToolPanel(toolPanel === 'hunt' ? '' : 'hunt')}, 'Threat Hunting'),
          h('button', {className: 'btn btnp', onClick: () => setToolPanel(toolPanel === 'rule' ? '' : 'rule')}, 'New Triage Rule')
        )
      ),
      toolPanel === 'hunt' ? h(ThreatHuntingPanel, {alerts: scopedAlerts, onFilter: addFilter}) : null,
      toolPanel === 'rule' ? h(TriageRulePanel, {filters, rules: triageRules, setRules: setTriageRules}) : null,
      h('div', {className: `aibox ${live ? '' : 'loading'}`},
        h('strong', null, 'SPARK Threat Triage: '),
        error ? `${payload.triage} Keeping the page free of fallback mock data.` : payload.triage
      ),
      h('div', {className: 'g12', style: {alignItems: 'start'}},
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
          h('div', {className: 'cb'}, h(MitreHeatmap, {alerts: scopedAlerts, onFilter: addFilter}))
        )
      ),
      h('div', {className: 'g11'},
        h(AlertFeed, {alerts: payload.alerts || [], total: payload.total || 0, filters, setFilters, search: searchInput, range}),
        h(ThreatIntelFeed, {data: payload})
      )
    );
  }

  const root = document.getElementById('threat-root');
  if (root) ReactDOM.createRoot(root).render(h(ThreatDetectionApp));
})();

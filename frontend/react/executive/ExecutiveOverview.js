(function () {
  const {useEffect, useMemo, useRef, useState} = React;

  const h = React.createElement;

  function clsPriority(priority) {
    return {P1: 'bp1', P2: 'bp2', P3: 'bp3', P4: 'bp4'}[priority] || 'bp3';
  }

  function fmtNum(value) {
    if (value === undefined || value === null) return '...';
    return Number(value).toLocaleString('pt-BR');
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
          title: `Consultar ${item} no Wazuh Indexer`,
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
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), 'Sincronizando Wazuh, FortiGate e Shuffle...')
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
        error ? `falha ao buscar /spark/executive-overview (${error}).` : 'coletando telemetria das fontes live. A tela sera preenchida quando o primeiro snapshot chegar.'
      ),
      h('div', {className: 'source-strip'},
        h(SourceBadge, {label: 'Wazuh', loading: true}),
        h(SourceBadge, {label: 'FortiGate', loading: true}),
        h(SourceBadge, {label: 'Shuffle', loading: true})
      ),
      h('div', {className: 'g21'},
        h('div', {className: 'card'}, h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Security Posture Score'), h('div', {className: 'cs'}, 'Aguardando snapshot live'))), h('div', {className: 'cb'}, h('div', {className: 'skel', style: {height: 140}}, '...'))),
        h('div', {className: 'card'}, h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Alert Volume - Last 24h'), h('div', {className: 'cs'}, 'Aguardando Wazuh Indexer'))), h('div', {className: 'cb'}, h('div', {className: 'skel', style: {height: 140}}, '...')))
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

  function DetailCell({label, value}) {
    return h('div', {className: 'detail-cell'},
      h('div', {className: 'detail-label'}, label),
      h('div', {className: 'detail-value'}, value || '-')
    );
  }

  function WorkqueueTable({items}) {
    const [openId, setOpenId] = useState(null);
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Wazuh Alert Investigation Queue'),
          h('div', {className: 'cs'}, 'Clique em uma linha para expandir os campos originais do Wazuh')
        ),
        h('span', {className: 'ca'}, `${items.length} itens`)
      ),
      h('table', {className: 'ftable'},
        h('thead', null,
          h('tr', null,
            ['Incident ID', 'Time', 'Description', 'MITRE Tactic', 'Priority', 'Analyst', 'SLA Remaining', 'Status']
              .map(col => h('th', {key: col}, col))
          )
        ),
        h('tbody', null,
          items.length ? items.flatMap(item => {
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
                  h('div', {className: 'alert-detail'},
                    h(DetailCell, {label: 'Rule / Level', value: `${item.id} / level ${item.level}`}),
                    h(DetailCell, {label: 'Agent', value: `${item.agentName || '-'} (${item.agentIp || item.agentId || '-'})`}),
                    h(DetailCell, {label: 'Source -> Destination', value: `${item.srcIp || '-'}${item.srcPort ? ':' + item.srcPort : ''} -> ${item.dstIp || '-'}${item.dstPort ? ':' + item.dstPort : ''}`}),
                    h(DetailCell, {label: 'MITRE', value: `${item.tactic || '-'} ${item.technique || ''}`.trim()}),
                    h(DetailCell, {label: 'Decoder / Location', value: `${item.decoderName || '-'} / ${item.location || '-'}`}),
                    h(DetailCell, {label: 'Index', value: item.index}),
                    h(DetailCell, {label: 'Document ID', value: item.documentId}),
                    h(DetailCell, {label: 'SLA Policy', value: `${item.slaPolicy || '-'} (${item.slaState || 'unknown'})`}),
                    item.fullLog ? h('pre', {className: 'detail-log'}, item.fullLog) : null
                  )
                )
              )
            ].filter(Boolean);
          }) : h('tr', null,
            h('td', {colSpan: 8, style: {color: 'var(--tm)', textAlign: 'center'}}, 'Nenhum alerta no periodo selecionado')
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
          h('div', {className: 'cs'}, `Wazuh Indexer - intervalo ${range}`)
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
          h('div', {className: 'cs'}, 'Score composto por Wazuh, FortiGate e Shuffle')
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

    async function load(selectedRange = range) {
      try {
        const response = await fetch(`/spark/executive-overview?range=${encodeURIComponent(selectedRange)}`, {credentials: 'include'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        setData(payload);
        syncDashboardChrome(payload);
        setUpdatedAt(new Date());
        setError('');
      } catch (err) {
        setError(err.message);
      }
    }

    useEffect(() => {
      load();
      const timer = setInterval(load, 30000);
      return () => clearInterval(timer);
    }, [range]);

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
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), updatedAt ? `Live - atualizado ${updatedAt.toLocaleTimeString('pt-BR')}` : 'Sincronizando fontes live...')
        ),
        h('div', {className: 'ha'}, h(TimeSelector, {value: range, onChange: setRange}), h('button', {className: 'btn'}, 'Export Report'), h('button', {className: 'btn btnp'}, 'Open Service Request'))
      ),
      h('div', {className: 'krow'},
        h(KpiCard, {label: 'P1 - Critical Incidents', value: fmtNum(kpis.critical_incidents), detail: `<span class="up">${fmtNum(kpis.events ?? kpis.events_24h)}</span> alertas ${data?.range || range}`, critical: true}),
        h(KpiCard, {label: 'MTTD', value: kpis.mttd || 'N/A', detail: `<span class="dn">${kpis.mttd_detail || 'Sem lifecycle de incidente'}</span>`}),
        h(KpiCard, {label: 'MTTR', value: kpis.mttr || 'N/A', detail: status.shuffle ? `<span class="dn">${kpis.mttr_detail || 'Aguardando tickets resolvidos'}</span>` : '<span class="up">Shuffle parcial</span>'}),
        h(KpiCard, {label: 'SLA Compliance', value: kpis.sla_compliance == null ? 'N/A' : `${kpis.sla_compliance}%`, detail: `<span class="dn">${kpis.sla_detail || 'Sem alertas mensuraveis'} - target ${kpis.sla_target || 95}%</span>`, tone: 'green'}),
        h(KpiCard, {label: 'Monitored Assets', value: fmtNum(kpis.monitored_assets), detail: `<span class="up">${fmtNum(kpis.assets_alerting)}</span> em alerta`})
      ),
      h('div', {className: 'aibox'},
        h('strong', null, 'SPARK Live Triage: '),
        error ? `erro ao atualizar (${error}). Mantendo ultimo estado.` : (data?.triage || 'Carregando telemetria real...')
      ),
      h('div', {className: 'source-strip'},
        h(SourceBadge, {label: 'Wazuh', ok: status.wazuh}),
        h(SourceBadge, {label: 'FortiGate', ok: status.fortigate}),
        h(SourceBadge, {label: 'Shuffle', ok: status.shuffle})
      ),
      h('div', {className: 'g21'}, h(PostureScore, {data}), h(AlertVolumeChart, {timeline, total: (kpis.events ?? kpis.events_24h) || 0, range: data?.range || range})),
      h(WorkqueueTable, {items: workqueue})
    );
  }

  const root = document.getElementById('executive-root');
  if (root) ReactDOM.createRoot(root).render(h(ExecutiveOverviewApp));
})();

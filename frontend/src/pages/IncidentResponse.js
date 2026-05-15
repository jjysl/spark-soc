(function () {
  const {useEffect, useMemo, useState} = React;
  const h = React.createElement;
  const RANGES = ['1h', '6h', '24h', '7d', '30d'];
  const api = window.SparkApi || {};
  const components = window.SparkComponents || {};
  const hooks = window.SparkHooks || {};

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
    if (components.MetricCard) return h(components.MetricCard, {label, value, detail, critical, tone});
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
    if (components.SourceChip) return h(components.SourceChip, {label, ok});
    return h('span', {className: `source-chip ${ok ? 'ok' : 'warn'}`},
      h('span', {className: 'source-dot'}),
      `${label} ${ok ? 'Online' : 'Offline'}`
    );
  }

  function EmptyState({title, detail}) {
    if (components.EmptyState) return h(components.EmptyState, {title, detail});
    return h('div', {className: 'cb'},
      h('div', {style: {fontSize: 12, color: 'var(--t1)', fontWeight: 600, marginBottom: 4}}, title),
      h('div', {style: {fontSize: 11, color: 'var(--tm)'}}, detail)
    );
  }

  function caseIp(item) {
    return item?.src_ip || item?.agent_ip || '';
  }

  function caseTitle(item) {
    return item?.title || item?.description || 'Wazuh alert';
  }

  function CandidateTable({items, onCreateCase, onBlock, actionState}) {
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Incident Candidates'),
          h('div', {className: 'cs'}, 'High-severity Wazuh alerts ready for case creation')
        ),
        h('span', {className: 'ca'}, `${fmtNum(items.length)} candidates`)
      ),
      items.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Time', 'Priority', 'Alert', 'Agent', 'Source IP', 'MITRE', 'Rule', 'Response'].map(col => h('th', {key: col}, col)))),
        h('tbody', null,
          items.map(item => h('tr', {key: item.document_id || `${item.rule_id}-${item.timestamp}`},
            h('td', null, h('span', {className: 'mono'}, fmtTime(item.timestamp))),
            h('td', null, h('span', {className: `badge ${priorityClass(item.priority)}`}, item.priority || 'P3')),
            h('td', null, h('span', {className: 'edesc', title: item.title}, item.title || 'Wazuh alert')),
            h('td', null, h('span', {className: 'mono'}, item.agent_name || 'unknown')),
            h('td', null, h('span', {className: 'mono'}, item.src_ip || item.agent_ip || '--')),
            h('td', null, h('span', {className: 'tpill'}, item.mitre_technique || item.mitre_tactic || 'Detection')),
            h('td', null, h('span', {className: 'mono'}, item.rule_id || '--')),
            h('td', null,
              h('div', {className: 'row-actions'},
                h('button', {
                  className: 'btn',
                  disabled: actionState === `case:${item.document_id || item.rule_id}`,
                  onClick: () => onCreateCase(item),
                }, actionState === `case:${item.document_id || item.rule_id}` ? 'Creating...' : 'Create Case'),
                caseIp(item) ? h(components.ActionButton || 'button', {
                  className: 'btn',
                  loading: actionState === `block:${caseIp(item)}`,
                  disabled: actionState === `block:${caseIp(item)}`,
                  onClick: () => onBlock(item),
                }, 'Block IP') : null
              )
            )
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
      ['Shuffle playbook dispatch', 'Enabled', notes?.playbooks || 'Webhook dispatch runs after FortiGate block actions.'],
      ['Incident timeline', 'Enabled', notes?.timeline || 'Lifecycle actions are persisted as case evidence.'],
      ['Action execution log', 'Enabled', notes?.actions || 'FortiGate and SOAR evidence is persisted.'],
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
          h('div', {className: 'pbicon done'}, 'OK'),
          h('div', null,
            h('div', {className: 'kct'}, row[0]),
            h('div', {className: 'kcs'}, `${row[1]} - ${row[2]}`)
          )
        ))
      )
    );
  }

  function CaseQueue({cases, onCaseAction, onBlock, actionState}) {
    const rows = Array.isArray(cases) ? cases : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Incident Case Queue'),
          h('div', {className: 'cs'}, 'Operational lifecycle: assign, investigate, respond, escalate, close')
        ),
        h('span', {className: 'ca'}, `${fmtNum(rows.length)} open cases`)
      ),
      rows.length ? h('div', {className: 'compact-list'},
        rows.map(item => {
          const ip = caseIp(item);
          const id = item.case_id || item.caseId || item.id;
          const busy = actionState && actionState.endsWith(`:${id}`);
          return h('div', {className: 'compact-row', key: id},
            h('div', {className: 'compact-main'},
              h('div', {className: 'compact-title'},
                h('span', {className: `badge ${priorityClass(item.priority)}`}, item.priority || 'P3'),
                h('span', {className: 'mono'}, id),
                h('span', null, item.title || 'Incident case')
              ),
              h('div', {className: 'compact-meta'},
                `Status: ${item.status || 'new'} | Owner: ${item.owner || 'Unassigned'} | Agent: ${item.agent_name || 'unknown'} | IP: ${ip || '--'}`
              )
            ),
            h('div', {className: 'row-actions'},
              h('button', {className: 'btn', disabled: busy, onClick: () => onCaseAction(item, 'assign')}, 'Assign to Me'),
              h('button', {className: 'btn', disabled: busy, onClick: () => onCaseAction(item, 'start')}, 'Start Investigation'),
              ip ? h(components.ActionButton || 'button', {className: 'btn', loading: actionState === `block:${id}`, disabled: actionState === `block:${id}`, onClick: () => onBlock(item)}, 'Block IP') : null,
              h('button', {className: 'btn', disabled: busy, onClick: () => onCaseAction(item, 'escalate')}, 'Escalate'),
              h('button', {className: 'btn btnp', disabled: busy, onClick: () => onCaseAction(item, 'close')}, 'Close Case')
            )
          );
        })
      ) : h(EmptyState, {
        title: 'No open cases',
        detail: 'Create a case from a detection candidate to start the response workflow.',
      })
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

  function TimelineCard({events}) {
    const rows = Array.isArray(events) ? events.slice(0, 8) : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Incident Timeline'),
          h('div', {className: 'cs'}, 'Latest case and response milestones')
        ),
        h('span', {className: 'badge binfo'}, `${fmtNum(rows.length)} events`)
      ),
      rows.length ? h('div', {className: 'cb'},
        rows.map(row => h('div', {className: 'tlitem', key: `tl-${row.id || row.created_at}`},
          h('div', {className: 'tltime'}, fmtTime(row.created_at)),
          h('span', {className: `tldot ${row.status === 'success' ? 'ok' : 'err'}`}),
          h('div', {className: 'tltext'},
            h('span', {className: 'mono'}, row.case_id || row.ticket_id || '--'),
            ` ${row.action || 'action'} - ${row.message || row.payload?.message || row.status || ''}`
          )
        ))
      ) : h(EmptyState, {
        title: 'No lifecycle events yet',
        detail: 'Create a case or run a response action to populate the timeline.',
      })
    );
  }

  function ActionLogCard({actions}) {
    const rows = Array.isArray(actions) ? actions : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Response Action Log'),
          h('div', {className: 'cs'}, 'Case lifecycle, FortiGate REST API and Shuffle evidence')
        ),
        h('span', {className: 'badge binfo'}, `${fmtNum(rows.length)} records`)
      ),
      rows.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Time', 'Action', 'Case', 'IP', 'Status', 'Evidence'].map(col => h('th', {key: col}, col)))),
        h('tbody', null, rows.map(row => h('tr', {key: row.id || `${row.ip}-${row.created_at}`},
          h('td', null, h('span', {className: 'mono'}, fmtTime(row.created_at))),
          h('td', null, h('span', {className: 'mono'}, row.action || '--')),
          h('td', null, h('span', {className: 'mono'}, row.case_id || row.ticket_id || '--')),
          h('td', null, h('span', {className: 'mono'}, row.ip || '--')),
          h('td', null, h('span', {className: `badge ${row.status === 'success' ? 'blive' : 'bcrit'}`}, row.status || '--')),
          h('td', null, h('span', {className: 'edesc', title: row.message || row.enforcement_path || ''},
            row.message || row.payload?.shuffle_message || row.object_name || row.enforcement_path || '--'
          ))
        )))
      ) : h(EmptyState, {
        title: 'No response actions yet',
        detail: 'Case actions, FortiGate blocklist updates and Shuffle dispatches write evidence here.',
      })
    );
  }

  function IncidentResponseApp() {
    const [range, setRange] = useState('24h');
    const [data, setData] = useState(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [actionState, setActionState] = useState('');
    const [updatedAt, setUpdatedAt] = useState(null);
    const [lastEvidence, setLastEvidence] = useState(null);
    const [blocklist, setBlocklist] = useState([]);
    const toast = hooks.useToast ? hooks.useToast() : {pushToast: () => {}};

    async function load() {
      setLoading(true);
      try {
        const [payload, fgBlocklist] = await Promise.all([
          api.incidents.getIncidentResponse(range),
          api.fortigate.getBlocklist().catch(err => ({items: [], status: 'error', message: err.message})),
        ]);
        setData(payload);
        setBlocklist(fgBlocklist.items || []);
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

    async function createCase(item) {
      const key = item.document_id || item.rule_id || item.timestamp || 'manual';
      setActionState(`case:${key}`);
      try {
        await api.incidents.createCase(item);
        toast.pushToast({tone: 'success', title: 'Case created', message: caseTitle(item)});
        await load();
      } catch (err) {
        setError(`Case creation failed: ${err.message}`);
        toast.pushToast({tone: 'error', title: 'Case creation failed', message: err.message});
      } finally {
        setActionState('');
      }
    }

    async function runCaseAction(item, action) {
      const id = item.case_id || item.caseId || item.id;
      if (!id) return;
      setActionState(`${action}:${id}`);
      try {
        await api.incidents.runCaseAction(id, {
          action,
          analyst: 'SOC Analyst',
          to: 'SOC Manager',
          reason: `${item.priority || 'P3'} case requires manager review`,
        });
        toast.pushToast({tone: 'success', title: 'Case updated', message: `${id} - ${action}`});
        await load();
      } catch (err) {
        setError(`Case action failed: ${err.message}`);
        toast.pushToast({tone: 'error', title: 'Case action failed', message: err.message});
      } finally {
        setActionState('');
      }
    }

    async function blockCandidateIp(item) {
      const ip = caseIp(item);
      if (!ip) return;
      const caseId = item.case_id || item.caseId || item.id || '';
      setActionState(`block:${caseId || ip}`);
      try {
        const payload = await api.fortigate.blockIp({
          ip,
          reason: caseTitle(item) || item.rule_id || 'Incident candidate',
          source: 'manual',
          severity: String(item.priority || '').toUpperCase() === 'P1' ? 'critical' : 'high',
          duration_minutes: 60,
          incident_id: caseId || item.document_id || item.rule_id || '',
        });
        setLastEvidence(payload);
        toast.pushToast({
          tone: 'success',
          title: 'FortiGate block applied',
          message: `${payload.ip} -> ${payload.object_name || 'SPARK_BLOCK object'} | evidence ${payload.evidence_id || '--'}`,
        });
        await load();
      } catch (err) {
        setError(`FortiGate blocklist update failed: ${err.message}`);
        toast.pushToast({tone: 'error', title: 'FortiGate block failed', message: err.message});
      } finally {
        setActionState('');
      }
    }

    async function unblockIp(item) {
      const ip = item?.ip;
      if (!ip) return;
      setActionState(`unblock:${ip}`);
      try {
        const payload = await api.fortigate.unblockIp({
          ip,
          reason: 'Analyst unblock from Incident Response',
          incident_id: item.incident_id || '',
        });
        setLastEvidence(payload);
        toast.pushToast({
          tone: 'success',
          title: 'FortiGate unblock applied',
          message: `${ip} removed from ${payload.group_name || 'SPARK_BLOCKLIST'} | evidence ${payload.evidence_id || '--'}`,
        });
        await load();
      } catch (err) {
        setError(`FortiGate unblock failed: ${err.message}`);
        toast.pushToast({tone: 'error', title: 'FortiGate unblock failed', message: err.message});
      } finally {
        setActionState('');
      }
    }

    function FortiGateBlocklistCard({items}) {
      const rows = Array.isArray(items) ? items : [];
      return h('div', {className: 'card'},
        h('div', {className: 'ch'},
          h('div', null,
            h('div', {className: 'ct'}, 'FortiGate SPARK Blocklist'),
            h('div', {className: 'cs'}, 'Live SPARK_BLOCKLIST members with unblock action')
          ),
          h('span', {className: 'badge binfo'}, `${fmtNum(rows.length)} IPs`)
        ),
        rows.length ? h('table', {className: 'ftable'},
          h('thead', null, h('tr', null, ['IP', 'Object', 'Reason', 'Status', 'Action'].map(col => h('th', {key: col}, col)))),
          h('tbody', null, rows.map(row => h('tr', {key: row.object_name || row.ip},
            h('td', null, h('span', {className: 'mono'}, row.ip || '--')),
            h('td', null, h('span', {className: 'mono'}, row.object_name || '--')),
            h('td', null, h('span', {className: 'edesc', title: row.reason || row.comment || ''}, row.reason || row.comment || '--')),
            h('td', null, h('span', {className: `badge ${row.present === false ? 'bhigh' : 'blive'}`}, row.present === false ? 'missing' : row.evidence_status || 'present')),
            h('td', null, h(components.ActionButton || 'button', {
              className: 'btn',
              loading: actionState === `unblock:${row.ip}`,
              disabled: actionState === `unblock:${row.ip}`,
              onClick: () => unblockIp(row),
            }, 'Unblock'))
          )))
        ) : h(EmptyState, {
          title: 'No blocklist entries returned',
          detail: 'Block an IP from a candidate or case to populate FortiGate SPARK_BLOCKLIST evidence.',
        })
      );
    }

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
    const cases = payload.cases || [];
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
        h('div', {className: 'ha'},
          h(RangeControl, {value: range, onChange: setRange}),
          h('button', {className: 'btn', onClick: load, disabled: loading}, loading ? 'Refreshing...' : 'Refresh'),
          h('button', {className: 'btn btnp', onClick: () => document.querySelector('button[onclick*="jira"]')?.click()}, 'Cases & Response')
        )
      ),
      h('div', {className: `aibox ${error ? 'loading' : ''}`},
        h('strong', null, 'Incident Response: '),
        error ? `API unavailable (${error}). No simulated playbook data is shown.` : 'Showing Wazuh candidates with FortiGate blocklist response evidence. Runtime enforcement remains pending network routing validation.'
      ),
      h('div', {className: 'source-strip'},
        h(SourceChip, {label: 'Wazuh Indexer', ok: wazuhOk}),
        h(SourceChip, {label: 'Shuffle', ok: shuffleOk})
      ),
      h(components.LoadingState && loading && !data ? components.LoadingState : React.Fragment, loading && !data ? {title: 'Loading response telemetry', detail: 'Collecting candidates, cases, and action evidence.'} : null),
      lastEvidence && window.SparkIncident?.EvidencePanel ? h(window.SparkIncident.EvidencePanel, {evidence: lastEvidence}) : null,
      h('div', {className: 'g4'},
        h(KpiCard, {label: 'Incident Candidates', value: fmtNum(candidates.length), detail: `<span class="up">${fmtNum(payload.wazuh?.total)}</span> Wazuh alerts in range`, critical: candidates.length > 0}),
        h(KpiCard, {label: 'P1 Candidates', value: fmtNum(counts.p1), detail: 'Wazuh level >= 12'}),
        h(KpiCard, {label: 'P2 Candidates', value: fmtNum(counts.p2), detail: 'Wazuh level 7-11'}),
        h(KpiCard, {label: 'Open Cases', value: fmtNum(cases.length), detail: 'Lifecycle queue'}),
        h(KpiCard, {label: 'Shuffle Workflows', value: shuffleOk ? fmtNum(payload.shuffle?.items) : 'N/A', detail: shuffleOk ? `<span class="dn">${payload.shuffle?.source || 'connected'}</span>` : '<span class="up">Endpoint not validated</span>'})
      ),
      h('div', {className: 'g11'},
        h(ShuffleStatus, {shuffle: payload.shuffle}),
        h(ReadinessPanel, {notes: payload.notes})
      ),
      h(CandidateTable, {items: candidates, onCreateCase: createCase, onBlock: blockCandidateIp, actionState}),
      h(CaseQueue, {cases, onCaseAction: runCaseAction, onBlock: blockCandidateIp, actionState}),
      h(FortiGateBlocklistCard, {items: blocklist}),
      h('div', {className: 'g11', style: {marginTop: 14}},
        h(TimelineCard, {events: payload.timeline}),
        h(ActionLogCard, {actions: payload.actions})
      )
    );
  }

  const root = document.getElementById('incident-root');
  if (root) {
    const ToastProvider = components.ToastProvider || React.Fragment;
    ReactDOM.createRoot(root).render(h(ToastProvider, null, h(IncidentResponseApp)));
  }
})();

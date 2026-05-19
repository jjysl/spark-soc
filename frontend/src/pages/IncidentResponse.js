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
    if (!value) return '--:--:--';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value.length >= 19 ? value.substring(11, 19) : '--:--:--';
    return `${date.toLocaleTimeString('pt-BR', {hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'America/Sao_Paulo'})} BRT`;
  }

  async function copyText(text) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', 'readonly');
    area.style.position = 'fixed';
    area.style.left = '-9999px';
    document.body.appendChild(area);
    area.select();
    document.execCommand('copy');
    document.body.removeChild(area);
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

  function SourceChip({label, ok, statusText}) {
    if (components.SourceChip) return h(components.SourceChip, {label, ok, status: statusText});
    return h('span', {className: `source-chip ${ok ? 'ok' : 'warn'}`},
      h('span', {className: 'source-dot'}),
      statusText || `${label} ${ok ? 'Online' : 'Offline'}`
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
    return item?.src_ip || item?.source_ip || item?.agent_ip || '';
  }

  function caseTitle(item) {
    return item?.title || item?.description || 'Wazuh alert';
  }

  function caseTarget(item) {
    return item?.target || item?.target_asset || item?.agent_name || item?.agent_ip || 'monitored asset';
  }

  function caseMitre(item) {
    return item?.mitre || item?.mitre_technique || item?.technique || '';
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
    const reachable = Boolean(shuffle?.connected);
    const authenticated = Boolean(shuffle?.api_authenticated);
    const label = authenticated ? 'Shuffle Online' : reachable ? 'Shuffle Auth Required' : 'Shuffle Offline';
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Shuffle SOAR Status'),
          h('div', {className: 'cs'}, 'Connectivity and basic endpoint discovery')
        ),
        h('span', {className: `badge ${authenticated ? 'blive' : reachable ? 'bwarn' : 'bhigh'}`}, label)
      ),
      h('div', {className: 'cb'},
        h('div', {className: 'apirow'},
          h('span', {className: `adot ${shuffle?.frontend_reachable ? 'ok' : 'warn'}`}),
          h('span', null, 'Frontend'),
          h('span', {style: {marginLeft: 'auto', color: 'var(--t2)'}}, shuffle?.frontend_reachable ? 'Reachable' : 'Awaiting telemetry')
        ),
        h('div', {className: 'apirow'},
          h('span', {className: `adot ${shuffle?.backend_reachable ? 'ok' : 'warn'}`}),
          h('span', null, 'Backend API'),
          h('span', {style: {marginLeft: 'auto', color: 'var(--t2)'}}, shuffle?.backend_reachable ? `Reachable (${shuffle?.backend_status_code || 'HTTP'})` : 'Awaiting telemetry')
        ),
        h('div', {className: 'apirow'},
          h('span', {className: `adot ${authenticated ? 'ok' : 'warn'}`}),
          h('span', null, 'API authentication'),
          h('span', {style: {marginLeft: 'auto', color: 'var(--t2)'}}, authenticated ? 'Authenticated' : 'Auth required')
        ),
        h('div', {style: {fontSize: 11, color: reachable ? 'var(--tm)' : 'var(--amber)', marginTop: 10}}, shuffle?.message || 'Awaiting telemetry from this integration.')
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
    const [blockTarget, setBlockTarget] = useState(null);
    const [unblockTarget, setUnblockTarget] = useState(null);
    const [unblockReason, setUnblockReason] = useState('');
    const [aiBriefing, setAiBriefing] = useState(null);
    const [aiBriefingLoading, setAiBriefingLoading] = useState(false);
    const [aiProvider, setAiProvider] = useState({provider: 'none', mode: 'deterministic_fallback'});
    const [evidenceHash, setEvidenceHash] = useState('');
    const [fortiAnalyzerEvidence, setFortiAnalyzerEvidence] = useState(null);
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

    useEffect(() => {
      if (!api.incidents.getAiStatus) return;
      api.incidents.getAiStatus()
        .then(status => setAiProvider(status.selected_provider || {provider: 'none', mode: 'deterministic_fallback'}))
        .catch(() => setAiProvider({provider: 'none', mode: 'deterministic_fallback'}));
    }, []);

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

    function openBlockModal(item) {
      const ip = caseIp(item);
      if (!ip) return;
      setBlockTarget({
        ...item,
        ip,
        title: caseTitle(item),
        case_id: item.case_id || item.caseId || item.id || '',
      });
    }

    async function submitBlockIp(input) {
      if (!blockTarget?.ip) return;
      const item = blockTarget;
      const ip = item.ip;
      const caseId = item.case_id || item.caseId || item.id || '';
      setActionState(`block:${caseId || ip}`);
      try {
        const payload = await api.fortigate.blockIp({
          ip,
          reason: input?.reason || caseTitle(item) || item.rule_id || 'Incident candidate',
          source: 'manual',
          severity: String(item.priority || '').toUpperCase() === 'P1' ? 'critical' : 'high',
          duration_minutes: input?.duration_minutes || 60,
          incident_id: caseId || item.document_id || item.rule_id || '',
        });
        setLastEvidence(payload);
        setBlockTarget(null);
        toast.pushToast({
          tone: 'success',
          title: 'Block confirmed via FortiGate',
          message: `${payload.object_name || 'SPARK_BLOCK object'} | ${payload.group_name || 'SPARK_BLOCKLIST'} | ${payload.policy_name || 'SPARK_AUTO_BLOCK'} | evidence ${payload.evidence_id || '--'}`,
        });
        await load();
      } catch (err) {
        setError(`FortiGate blocklist update failed: ${err.message}`);
        toast.pushToast({tone: 'error', title: 'FortiGate block failed', message: err.message});
      } finally {
        setActionState('');
      }
    }

    function SparkTrace({payload, evidence}) {
      const score = containmentScore(evidence);
      const steps = [
        ['Detect', 'Wazuh alert', `${fmtNum(payload.wazuh?.total)} alerts normalized for triage`, 'done'],
        ['Analyze', 'SPARK analysis', `${fmtNum(candidates.length)} prioritized candidates with MITRE context`, candidates.length ? 'active' : 'warn'],
        ['Respond', 'FortiGate block', evidence ? `${containmentObjectName(evidence) || 'Address object'} sent to FortiOS` : 'Ready for analyst action', evidence ? 'done' : 'active'],
        ['Contain', 'Containment confidence', evidence ? `${score}% validated response checks` : `${fmtNum(blocklist.length)} active blocklist entries`, evidence ? 'done' : 'warn'],
        ['Document', 'Evidence generated', evidence?.evidence_id ? `Evidence ${evidence.evidence_id}` : 'Awaiting response evidence', evidence ? 'done' : 'warn'],
      ];
      return h('div', {className: 'spark-trace'},
        steps.map(([label, title, detail, state]) => h('div', {className: `trace-step ${state}`, key: label},
          h('div', {className: 'trace-label'}, label),
          h('div', {className: 'trace-title'}, title),
          h('div', {className: 'trace-detail'}, detail)
        ))
      );
    }

    function containmentScore(evidence) {
      if (!evidence) return 0;
      const fg = evidence.fortigate || {};
      const status = String(evidence.status || evidence.evidence_status || '').toLowerCase();
      const checks = [
        ['blocked', 'success', 'present'].includes(status),
        Boolean(containmentObjectName(evidence) || fg.object_created_or_updated),
        Boolean(containmentGroupName(evidence) || fg.group_updated),
        Boolean(containmentPolicyName(evidence) || fg.policy_present),
        Boolean(evidence.evidence_id),
      ];
      return Math.round((checks.filter(Boolean).length / checks.length) * 100);
    }

    function containmentChecks(evidence) {
      const fg = evidence?.fortigate || {};
      return [
        {label: 'FortiGate API OK', ok: Boolean(evidence && ['blocked', 'unblocked', 'success'].includes(String(evidence.status || '').toLowerCase()))},
        {label: 'Address object present', ok: Boolean(evidence?.object_name || evidence?.fortigate_object || fg.object_created_or_updated)},
        {label: 'SPARK_BLOCKLIST updated', ok: Boolean(evidence?.group_name || evidence?.fortigate_group || fg.group_updated)},
        {label: 'Policy active', ok: Boolean(evidence?.policy_name || evidence?.fortigate_policy || fg.policy_present)},
        {label: 'Evidence recorded', ok: Boolean(evidence?.evidence_id)},
      ];
    }

    function ContainmentConfidence({evidence}) {
      const checks = containmentChecks(evidence);
      const okChecks = checks.filter(item => item.ok).length;
      const trafficPath = {label: 'Traffic-path validation', ok: false, pending: true};
      const score = checks.length ? Math.round((okChecks / checks.length) * 100) : 0;
      const label = okChecks === checks.length ? 'Verified' : okChecks > 0 ? 'Partially Verified' : 'Not Verified';
      return h('div', {className: 'card'},
        h('div', {className: 'ch'},
          h('div', null, h('div', {className: 'ct'}, 'Containment Confidence'), h('div', {className: 'cs'}, 'FortiGate response evidence and local audit record')),
          h('span', {className: `badge ${okChecks === checks.length ? 'blive' : okChecks ? 'bwarn' : 'bcrit'}`}, label)
        ),
        h('div', {className: 'cb containment-score'},
          h('div', {className: 'containment-score-main'},
            h('div', {className: 'kv'}, `${okChecks}/${checks.length}`),
            h('div', {className: 'muted'}, `${score}% evidence checks confirmed`)
          ),
          h('div', {className: 'empty-detail'}, 'Containment Confidence is based on FortiGate API response, blocklist membership, policy presence and local evidence record. Runtime traffic impact depends on traffic path validation.')
        ),
        h('div', {className: 'cb confidence-grid'},
          [...checks, trafficPath].map(item => h('div', {className: 'confidence-item', key: item.label},
            h('span', {className: `confidence-dot ${item.ok ? 'ok' : 'warn'}`}),
            h('div', null, h('div', {className: 'row-title'}, item.label), h('div', {className: 'muted'}, item.ok ? 'Validated by latest response' : item.pending ? 'Pending validation' : 'Pending latest evidence'))
          ))
        )
      );
    }

    function fortiAnalyzerStatusLabel(fa) {
      const status = String(fa?.status || '').toLowerCase();
      if (fa?.connected || status === 'online') return 'FortiAnalyzer Online';
      if (status.includes('auth')) return 'FortiAnalyzer Auth Required';
      if (['timeout', 'unavailable', 'endpoint_error'].includes(status)) return 'FortiAnalyzer Unavailable';
      return 'FortiAnalyzer Connector Ready';
    }

    function fortiAnalyzerEvidenceRef(payload, evidenceResult, sourceIp) {
      const fa = payload?.fortianalyzer || {};
      const searchedIp = evidenceResult?.ip || sourceIp || 'not available';
      if (!fa.configured) return `Status: Connector Ready | Source IP searched: ${searchedIp} | Evidence status: Awaiting connector | Log count: 0`;
      if (evidenceResult?.evidence_status === 'evidence_collected') {
        const refs = (evidenceResult.references || [])
          .slice(0, 3)
          .map(item => [item.policyid ? `policy ${item.policyid}` : '', item.logid ? `log ${item.logid}` : '', item.action || ''].filter(Boolean).join(' / '))
          .filter(Boolean)
          .join('; ');
        return `Status: ${fortiAnalyzerStatusLabel(fa)} | Source IP searched: ${searchedIp} | Evidence status: Evidence collected | Log count: ${evidenceResult.log_count || 0}${refs ? ` | References: ${refs}` : ''}`;
      }
      if (evidenceResult?.evidence_status) {
        return `Status: ${fortiAnalyzerStatusLabel(fa)} | Source IP searched: ${searchedIp} | Evidence status: ${evidenceResult.evidence_status} | Log count: ${evidenceResult.log_count || 0} | ${evidenceResult.message || 'Evidence query pending analyst review.'}`;
      }
      return `Status: ${fortiAnalyzerStatusLabel(fa)} | Source IP searched: ${searchedIp} | Evidence status: Evidence pending | Log count: 0 | FortiAnalyzer evidence is not confirmed until log records are returned by the connector.`;
    }

    function evidencePackSections(evidence, payload, candidate, faEvidence) {
      const score = containmentScore(evidence);
      const sourceIp = evidence?.ip || caseIp(candidate) || '';
      return [
        ['Executive Summary', `${caseTitle(candidate)}. Severity ${candidate?.priority || candidate?.severity || '--'} with source ${caseIp(candidate) || evidence?.ip || '--'} targeting ${caseTarget(candidate)}.`],
        ['Technical Evidence', `Wazuh alerts: ${fmtNum(payload.wazuh?.total)}. Rule: ${candidate?.rule_id || '--'}. MITRE: ${caseMitre(candidate)}.`],
        ['Response Actions', `FortiGate object ${containmentObjectName(evidence) || '--'} added to ${containmentGroupName(evidence) || 'SPARK_BLOCKLIST'} with policy ${containmentPolicyName(evidence) || 'SPARK_AUTO_BLOCK'}.`],
        ['Containment Proof', `Evidence ID ${evidence?.evidence_id || '--'}. Containment confidence ${score}%. Status ${evidence?.status || 'Awaiting response evidence'}.`],
        ['Integrity', evidenceHash ? `SHA256:${evidenceHash}` : 'SHA256 pending evidence payload generation.'],
        ['FortiAnalyzer Evidence Layer', fortiAnalyzerEvidenceRef(payload, faEvidence, sourceIp)],
        ['Compliance Evidence', 'Technical evidence is available for analyst review and auditor handoff. This is not automatic certification.'],
        ['Next Steps', 'Validate traffic-path enforcement, review related alerts, update the case owner and attach Evidence Pack to the customer workspace.'],
      ];
    }

    function stableStringify(value) {
      if (value === null || typeof value !== 'object') return JSON.stringify(value);
      if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
      return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
    }

    async function sha256Hex(text) {
      if (!window.crypto?.subtle) return '';
      const bytes = new TextEncoder().encode(text);
      const digest = await window.crypto.subtle.digest('SHA-256', bytes);
      return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    async function buildEvidencePackPayload(evidence, payload, candidate, briefing, faEvidence) {
      const actions = Array.isArray(payload?.actions) ? payload.actions.slice(0, 12) : [];
      if (evidence) {
        actions.unshift({
          action: evidence.status === 'unblocked' ? 'unblock' : 'block',
          ip: evidence.ip || '',
          reason: evidence.reason || evidence.message || 'Containment action recorded',
          status: evidence.status || '',
          evidence_id: evidence.evidence_id || '',
          object_name: containmentObjectName(evidence),
          group_name: containmentGroupName(evidence),
          policy_name: containmentPolicyName(evidence),
        });
      }
      return {
        evidence_id: evidence?.evidence_id || `EVD-PENDING-${Date.now()}`,
        timestamp: new Date().toISOString(),
        analyst: 'SOC Analyst',
        workspace: 'Production Workspace',
        incident: {
          title: caseTitle(candidate),
          severity: candidate?.priority || candidate?.severity || 'requires analyst review',
          source_ip: caseIp(candidate) || evidence?.ip || 'not available',
          target: caseTarget(candidate),
          mitre: caseMitre(candidate) || 'not available',
          wazuh_rule: candidate?.rule_id || evidence?.wazuh_rule || 'not available',
          alert_count: payload?.wazuh?.total || evidence?.alert_count || 'not available',
        },
        fortigate: {
          object: containmentObjectName(evidence) || 'not available',
          group: containmentGroupName(evidence) || 'not available',
          policy: containmentPolicyName(evidence) || 'not available',
        },
        containment_confidence: `${containmentChecks(evidence).filter(item => item.ok).length}/${containmentChecks(evidence).length}`,
        response_actions: actions.map(sanitizeOperationalObject),
        ai_briefing_summary: briefing?.sections?.find(([title]) => title === 'Analysis')?.[1] || 'not available',
        compliance_evidence_refs: ['NIST CSF 2.0 Detect', 'NIST CSF 2.0 Respond', 'ISO 27001:2022 evidence review'],
        fortianalyzer: {
          status: fortiAnalyzerStatusLabel(payload?.fortianalyzer),
          source_ip_searched: faEvidence?.ip || caseIp(candidate) || evidence?.ip || 'not available',
          evidence_status: faEvidence?.evidence_status || 'evidence_pending',
          log_count: faEvidence?.log_count || 0,
          references: faEvidence?.references || [],
          message: faEvidence?.message || 'FortiAnalyzer evidence is pending until connector logs are returned.',
        },
      };
    }

    async function buildEvidencePackText(evidence, payload, candidate, briefing, faEvidence) {
      const pack = await buildEvidencePackPayload(evidence, payload, candidate, briefing, faEvidence);
      const hash = await sha256Hex(stableStringify(pack));
      return `${JSON.stringify({...pack, integrity: {algorithm: 'SHA-256', hash}}, null, 2)}\n`;
    }

    function EvidencePack({evidence, payload, candidate, fortiAnalyzerEvidence, onCopy, onExport, onCopyHash, hash}) {
      const sections = evidencePackSections(evidence, payload, candidate, fortiAnalyzerEvidence);
      return h('div', {className: 'card'},
        h('div', {className: 'ch'},
          h('div', null, h('div', {className: 'ct'}, 'Evidence Pack'), h('div', {className: 'cs'}, 'Audit-ready response summary for MDR handoff')),
          h('div', {className: 'row-actions'},
            h('button', {className: 'btn', onClick: onCopy}, 'Copy Evidence Pack'),
            h('button', {className: 'btn', onClick: onExport}, 'Export Evidence Pack (.json)'),
            h('button', {className: 'btn', onClick: onCopyHash, disabled: !hash}, 'Copy SHA256')
          )
        ),
        h('div', {className: 'integrity-row'}, h('span', null, 'Integrity'), h('strong', {className: 'mono'}, hash ? `SHA256:${hash}` : 'SHA256 pending')),
        h('div', {className: 'cb evidence-pack'},
          sections.map(([title, body]) => h('div', {className: `response-evidence ${title === 'Containment Proof' && evidence ? 'ok' : ''}`, key: title},
            h('div', {className: 'response-title'}, title),
            h('p', {className: 'evidence-copy'}, body)
          ))
        )
      );
    }

    function openUnblockModal(item) {
      if (!item?.ip) return;
      setUnblockReason('');
      setUnblockTarget(item);
    }

    async function unblockIp() {
      const item = unblockTarget;
      const ip = item?.ip;
      if (!ip) return;
      if (unblockReason.trim().length < 10) {
        toast.pushToast({tone: 'warn', title: 'Unblock justification required', message: 'Enter at least 10 characters before removing containment.'});
        return;
      }
      setActionState(`unblock:${ip}`);
      try {
        const payload = await api.fortigate.unblockIp({
          ip,
          reason: unblockReason.trim(),
          incident_id: item.incident_id || '',
        });
        setLastEvidence(payload);
        setUnblockTarget(null);
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
              onClick: () => openUnblockModal(row),
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
    const briefingCandidate = candidates[0] || cases[0] || {};

    useEffect(() => {
      let active = true;
      buildEvidencePackPayload(lastEvidence, payload, briefingCandidate, aiBriefing, fortiAnalyzerEvidence)
        .then(pack => sha256Hex(stableStringify(pack)))
        .then(hash => { if (active) setEvidenceHash(hash); })
        .catch(() => { if (active) setEvidenceHash(''); });
      return () => { active = false; };
    }, [lastEvidence, data, aiBriefing, fortiAnalyzerEvidence]);

    useEffect(() => {
      const fa = payload?.fortianalyzer || {};
      const targetIp = lastEvidence?.ip || caseIp(briefingCandidate);
      if (!targetIp || !fa.configured || !api.incidents.getFortiAnalyzerEvidence) {
        setFortiAnalyzerEvidence(null);
        return;
      }
      let active = true;
      api.incidents.getFortiAnalyzerEvidence(targetIp, 10)
        .then(result => { if (active) setFortiAnalyzerEvidence(result); })
        .catch(err => {
          if (active) {
            setFortiAnalyzerEvidence({
              configured: true,
              connected: Boolean(fa.connected),
              status: 'evidence_pending',
              evidence_status: 'evidence_pending',
              ip: targetIp,
              log_count: 0,
              references: [],
              message: `FortiAnalyzer evidence query pending analyst review: ${err.message}`,
            });
          }
        });
      return () => { active = false; };
    }, [lastEvidence?.ip, briefingCandidate?.src_ip, briefingCandidate?.source_ip, briefingCandidate?.agent_ip, payload?.fortianalyzer?.configured, payload?.fortianalyzer?.connected]);

    function sanitizeOperationalText(value) {
      if (value === undefined || value === null) return '';
      let text = String(value);
      const hasFortiGateVariable = /FORTIGATE_(API_KEY|BASE_URL)/i.test(text);
      const hasAiVariable = /GROQ_API_KEY|ANTHROPIC_API_KEY|AI_PROVIDER/i.test(text);
      if (hasFortiGateVariable) return 'FortiGate connector is unavailable in this workspace.';
      if (hasAiVariable) return 'AI briefing connector is unavailable in this workspace.';
      return text
        .replace(/\.env/gi, 'workspace configuration')
        .replace(/localhost/gi, 'local connector endpoint')
        .replace(/127\.0\.0\.1/g, 'local connector endpoint');
    }

    function sanitizeOperationalObject(value) {
      if (Array.isArray(value)) return value.map(sanitizeOperationalObject);
      if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizeOperationalObject(item)]));
      }
      return typeof value === 'string' ? sanitizeOperationalText(value) : value;
    }

    function containmentObjectName(evidence) {
      return evidence?.object_name || evidence?.fortigate_object || evidence?.object || '';
    }

    function containmentGroupName(evidence) {
      return evidence?.group_name || evidence?.fortigate_group || evidence?.group || '';
    }

    function containmentPolicyName(evidence) {
      return evidence?.policy_name || evidence?.fortigate_policy || evidence?.policy || '';
    }

    function isBlockEvidence(item) {
      if (!item) return false;
      const status = String(item.status || item.evidence_status || '').toLowerCase();
      const action = String(item.action || item.type || '').toLowerCase();
      const hasFortiGateEvidence = Boolean(containmentObjectName(item) || containmentGroupName(item) || containmentPolicyName(item) || item.evidence_id);
      return hasFortiGateEvidence && (status === 'blocked' || status === 'success' || action.includes('block')) && !action.includes('unblock');
    }

    function normalizeContainmentEvidence(item, source) {
      if (!item) return null;
      const ip = item.ip || item.source_ip || item.src_ip || caseIp(item);
      const objectName = containmentObjectName(item);
      const groupName = containmentGroupName(item) || 'SPARK_BLOCKLIST';
      const policyName = containmentPolicyName(item) || 'SPARK_AUTO_BLOCK';
      return sanitizeOperationalObject({
        ...item,
        ip,
        source_context: source,
        status: item.status || 'blocked',
        reason: item.reason || item.message || item.title || 'Analyst containment action',
        object_name: objectName,
        fortigate_object: objectName,
        group_name: groupName,
        fortigate_group: groupName,
        policy_name: policyName,
        fortigate_policy: policyName,
        evidence_id: item.evidence_id || '',
      });
    }

    function latestContainmentEvidence(forceLatestContainment) {
      if (isBlockEvidence(lastEvidence)) return normalizeContainmentEvidence(lastEvidence, 'latest_block_result');
      const actions = Array.isArray(payload.actions) ? payload.actions : [];
      const action = actions.find(isBlockEvidence);
      if (action) return normalizeContainmentEvidence(action, 'response_action_log');
      if (forceLatestContainment && blocklist.length) return normalizeContainmentEvidence(blocklist[0], 'fortigate_blocklist');
      return null;
    }

    function buildBriefingContext(forceLatestContainment) {
      const containmentEvidence = latestContainmentEvidence(forceLatestContainment);
      const fallbackIncident = {
        title: containmentEvidence?.ip ? `Containment action for ${containmentEvidence.ip}` : 'Security event requires analyst review',
        severity: containmentEvidence ? (containmentEvidence.severity || 'high') : 'Requires analyst review',
        source_ip: containmentEvidence?.ip || '',
        target: 'monitored asset',
        mitre: '',
      };
      const incident = containmentEvidence
        ? {
          ...fallbackIncident,
          incident_id: containmentEvidence.incident_id || containmentEvidence.case_id || containmentEvidence.evidence_id || '',
          title: containmentEvidence.reason || fallbackIncident.title,
          severity: containmentEvidence.severity || fallbackIncident.severity,
          source_ip: containmentEvidence.ip || fallbackIncident.source_ip,
          target: containmentEvidence.target || containmentEvidence.target_asset || caseTarget(briefingCandidate) || fallbackIncident.target,
          mitre: caseMitre(containmentEvidence) || '',
          rule_id: containmentEvidence.rule_id || containmentEvidence.wazuh_rule || '',
          alert_count: containmentEvidence.alert_count || '',
        }
        : (briefingCandidate && Object.keys(briefingCandidate).length ? briefingCandidate : fallbackIncident);
      const evidence = containmentEvidence || {};
      const checks = containmentChecks(containmentEvidence);
      const okChecks = checks.filter(item => item.ok).length;
      const hasContainment = Boolean(containmentEvidence);
      const confidence = hasContainment
        ? `${okChecks}/${checks.length}`
        : 'Containment has not been verified yet.';
      const actionLog = (payload.actions || []).slice(0, 5).map(item => sanitizeOperationalObject({
        action: item.action || '',
        status: item.status || '',
        ip: item.ip || item.source_ip || '',
        object_name: containmentObjectName(item),
        group_name: containmentGroupName(item),
        policy_name: containmentPolicyName(item),
        evidence_id: item.evidence_id || '',
        message: item.message || item.enforcement_path || '',
        timestamp: item.timestamp || item.time || '',
      }));
      if (containmentEvidence && !actionLog.find(item => item.evidence_id && item.evidence_id === containmentEvidence.evidence_id)) {
        actionLog.unshift({
          action: 'block_ip',
          status: containmentEvidence.status || 'blocked',
          ip: containmentEvidence.ip || '',
          object_name: containmentObjectName(containmentEvidence),
          group_name: containmentGroupName(containmentEvidence),
          policy_name: containmentPolicyName(containmentEvidence),
          evidence_id: containmentEvidence.evidence_id || '',
          message: containmentEvidence.reason || 'FortiGate containment evidence recorded.',
          timestamp: containmentEvidence.timestamp || containmentEvidence.created_at || '',
        });
      }
      const timelineEvents = (payload.timeline || []).slice(0, 6).map(item => sanitizeOperationalObject({
        stage: item.stage || item.title || item.action || '',
        status: item.status || '',
        detail: item.detail || item.message || item.description || '',
        timestamp: item.timestamp || item.time || '',
      }));
      if (containmentEvidence) {
        timelineEvents.unshift({
          stage: 'Contain',
          status: containmentEvidence.status || 'blocked',
          detail: `FortiGate object ${containmentObjectName(containmentEvidence) || '--'} added to ${containmentGroupName(containmentEvidence) || 'SPARK_BLOCKLIST'}.`,
          timestamp: containmentEvidence.timestamp || containmentEvidence.created_at || '',
        });
      }
      return {
        incident: sanitizeOperationalObject(incident),
        evidence: sanitizeOperationalObject(evidence),
        checks,
        okChecks,
        confidence,
        hasContainment,
        actionLog,
        timelineEvents,
      };
    }

    function briefingSectionsFromPayload(briefing) {
      const value = briefing || {};
      return [
        ['Incident', value.incident || value.title || value.executive_summary || 'Incident requires analyst review.'],
        ['Severity', value.severity || 'Requires analyst review'],
        ['MITRE ATT&CK', value.mitre_attack || value.mitre || 'not available'],
        ['Source IP', value.source_ip || 'not available'],
        ['Target', value.target || 'not available'],
        ['Wazuh Rule', value.wazuh_rule || 'not available'],
        ['Alert Count', value.alert_count || 'not available'],
        ['FortiGate Object', value.fortigate_object || 'not available'],
        ['FortiGate Policy', value.fortigate_policy || 'not available'],
        ['Evidence ID', value.evidence_id || 'not available'],
        ['Analysis', value.analysis || value.containment_status || value.response_taken || 'Analysis requires analyst review.'],
        ['Recommended Next Steps', Array.isArray(value.recommended_next_steps) ? value.recommended_next_steps.join(' ') : 'Review correlated alerts, validate containment and attach evidence to the case.'],
      ];
    }

    function deterministicBriefingPayload(context) {
      const selected = context || buildBriefingContext(false);
      const evidence = selected.evidence || {};
      const incident = selected.incident || {};
      const rule = incident.rule_id || incident.wazuh_rule || evidence.wazuh_rule || '--';
      const alerts = incident.alert_count || evidence.alert_count || (selected.hasContainment ? '' : (payload.wazuh?.total || payload.wazuh?.candidate_count || 0));
      const containmentPhrase = selected.hasContainment
        ? `Containment confidence is ${selected.confidence} based on FortiGate object, blocklist, policy and evidence confirmation.`
        : 'No containment action has been executed for this incident yet. Containment has not been verified yet.';
      return {
        provider: aiProvider.provider || 'none',
        model: aiProvider.model || 'provider-default',
        source: 'fallback',
        briefing: {
          incident: caseTitle(incident),
          severity: incident.priority || incident.severity || 'Requires analyst review',
          mitre_attack: caseMitre(incident) || 'not available',
          source_ip: caseIp(incident) || evidence.ip || 'not available',
          target: caseTarget(incident),
          wazuh_rule: rule !== '--' ? rule : 'not available',
          alert_count: alerts !== '' ? fmtNum(alerts) : 'not available',
          fortigate_object: containmentObjectName(evidence) || 'not available',
          fortigate_policy: containmentPolicyName(evidence) || 'not available',
          evidence_id: evidence.evidence_id || 'not available',
          analysis: selected.hasContainment
            ? `${caseTitle(incident)} is prioritized as ${incident.priority || incident.severity || 'analyst review'}. FortiGate object ${containmentObjectName(evidence) || '--'} is associated with ${containmentGroupName(evidence) || 'SPARK_BLOCKLIST'} and policy ${containmentPolicyName(evidence) || 'SPARK_AUTO_BLOCK'}. ${containmentPhrase}`
            : `${caseTitle(incident)} requires analyst review. No containment action has been executed for this incident yet. Containment has not been verified yet.`,
          recommended_next_steps: selected.hasContainment
            ? ['Validate traffic-path enforcement.', rule !== '--' ? `Review Wazuh rule ${rule} and correlated alerts.` : 'Review correlated alerts.', 'Attach Evidence Pack to the case.', 'Assign case owner.']
            : ['Review correlated alerts.', 'Decide whether containment is required.', 'Configure or validate the FortiGate connector for this workspace.', 'Attach analyst notes to the case.'],
        },
      };
    }

    function briefingText(result, sections) {
      return [
        'AI Incident Briefing',
        `Source: ${result.source || 'fallback'} | Provider: ${result.provider || 'none'} | Model: ${result.model || 'provider-default'}`,
        result.source === 'fallback' ? 'MODO DETERMINÍSTICO - IA indisponível' : '',
        '',
        ...sections.map(([title, body]) => `${title}: ${body}`),
      ].filter(Boolean).join('\n');
    }

    async function generateAiBriefing(forceLatestContainment) {
      const context = buildBriefingContext(Boolean(forceLatestContainment));
      const evidence = context.evidence || {};
      const incident = context.incident || {};
      const concreteMitre = caseMitre(incident);
      const requestPayload = {
        incident_id: incident.case_id || incident.caseId || incident.id || incident.document_id || incident.incident_id || evidence.incident_id || evidence.evidence_id || '',
        title: caseTitle(incident),
        severity: incident.priority || incident.severity || 'Requires analyst review',
        source_ip: caseIp(incident) || evidence.ip || '',
        target: caseTarget(incident),
        mitre: concreteMitre,
        wazuh_rule: incident.rule_id || incident.wazuh_rule || evidence.wazuh_rule || '',
        alert_count: incident.alert_count || evidence.alert_count || (context.hasContainment ? '' : (payload.wazuh?.total || payload.wazuh?.candidate_count || candidates.length || 0)),
        fortigate_object: containmentObjectName(evidence),
        fortigate_group: containmentGroupName(evidence),
        fortigate_policy: containmentPolicyName(evidence),
        wazuh_evidence: {
          alerts_in_range: context.hasContainment ? '' : (payload.wazuh?.total || 0),
          rule_id: incident.rule_id || incident.wazuh_rule || '',
          document_id: incident.document_id || '',
          agent_name: incident.agent_name || '',
          agent_ip: incident.agent_ip || '',
          level: incident.level || '',
          description: incident.description || incident.title || '',
        },
        evidence: {
          ...evidence,
          wazuh_rule: incident.rule_id || incident.wazuh_rule || evidence.wazuh_rule || '',
          alert_count: incident.alert_count || evidence.alert_count || (context.hasContainment ? '' : (payload.wazuh?.total || payload.wazuh?.candidate_count || candidates.length || 0)),
          fortigate_object: containmentObjectName(evidence),
          fortigate_group: containmentGroupName(evidence),
          fortigate_policy: containmentPolicyName(evidence),
          containment_confidence: context.confidence,
          containment_checks: context.checks,
        },
        evidence_id: evidence.evidence_id || '',
        containment_confidence: context.confidence,
        containment_checks: context.checks,
        response_action_log: context.actionLog,
        timeline_events: context.timelineEvents,
        containment_note: context.hasContainment ? '' : 'No containment action has been executed for this incident yet.',
        recommended_next_steps: context.hasContainment
          ? ['Validate traffic-path enforcement.', 'Review correlated alerts.', 'Attach Evidence Pack to the case.']
          : ['Review correlated alerts.', 'Decide whether containment is required.', 'Use FortiGate containment if the event requires network response.'],
      };
      setAiBriefingLoading(true);
      try {
        const result = api.incidents.generateIncidentBriefing
          ? await api.incidents.generateIncidentBriefing(requestPayload)
          : deterministicBriefingPayload(context);
        const sections = briefingSectionsFromPayload(result.briefing);
        const cleanSections = sections.map(([title, body]) => [title, sanitizeOperationalText(body)]);
        setAiBriefing({sections: cleanSections, text: sanitizeOperationalText(briefingText(result, cleanSections)), generatedAt: new Date(), source: result.source, provider: result.provider, model: result.model});
        toast.pushToast({
          tone: result.source === 'ai-live' ? 'success' : 'warn',
          title: result.source === 'ai-live' ? 'AI briefing generated' : 'Fallback briefing generated',
          message: context.hasContainment ? 'Briefing used latest containment evidence.' : 'Briefing used selected incident context.',
        });
      } catch (err) {
        const result = deterministicBriefingPayload(context);
        const sections = briefingSectionsFromPayload(result.briefing);
        const cleanSections = sections.map(([title, body]) => [title, sanitizeOperationalText(body)]);
        setAiBriefing({sections: cleanSections, text: sanitizeOperationalText(briefingText(result, cleanSections)), generatedAt: new Date(), source: 'fallback', provider: result.provider, model: result.model});
        toast.pushToast({tone: 'warn', title: 'Fallback briefing generated', message: 'Deterministic fallback kept the briefing available.'});
      } finally {
        setAiBriefingLoading(false);
      }
    }

    async function copyEvidencePack() {
      try {
        const text = await buildEvidencePackText(lastEvidence, payload, briefingCandidate, aiBriefing, fortiAnalyzerEvidence);
        await copyText(text);
        toast.pushToast({tone: 'success', title: 'Evidence Pack copied', message: 'Structured evidence is ready for handoff.'});
      } catch (err) {
        toast.pushToast({tone: 'error', title: 'Evidence Pack copy unavailable', message: err.message});
      }
    }

    async function exportEvidencePack() {
      try {
        const text = await buildEvidencePackText(lastEvidence, payload, briefingCandidate, aiBriefing, fortiAnalyzerEvidence);
        const blob = new Blob([text], {type: 'application/json'});
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `spark-evidence-pack-${lastEvidence?.evidence_id || Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        toast.pushToast({tone: 'success', title: 'Evidence Pack exported', message: 'JSON evidence package downloaded with integrity hash.'});
      } catch (err) {
        toast.pushToast({tone: 'error', title: 'Evidence Pack export unavailable', message: err.message});
      }
    }

    async function copyEvidenceHash() {
      if (!evidenceHash) return;
      try {
        await copyText(`SHA256:${evidenceHash}`);
        toast.pushToast({tone: 'success', title: 'Evidence hash copied', message: 'SHA256 integrity value copied to clipboard.'});
      } catch (err) {
        toast.pushToast({tone: 'error', title: 'Evidence hash copy unavailable', message: err.message});
      }
    }

    async function copyAiBriefing() {
      if (!aiBriefing?.text) return;
      try {
        await copyText(aiBriefing.text);
        toast.pushToast({tone: 'success', title: 'AI briefing copied', message: 'Briefing copied to clipboard.'});
      } catch (err) {
        toast.pushToast({tone: 'error', title: 'Briefing copy unavailable', message: err.message});
      }
    }

    const latestContainmentForUi = latestContainmentEvidence(false);

    function UnblockConfirmModal({open, target, reason, loading, onReasonChange, onClose, onConfirm}) {
      const Modal = components.Modal;
      if (!Modal) return null;
      const validReason = reason.trim().length >= 10;
      return h(Modal, {
        open,
        title: 'Confirm FortiGate Unblock',
        onClose,
        footer: h('div', {className: 'row-actions'},
          h('button', {className: 'btn', onClick: onClose, disabled: loading}, 'Cancel'),
          h('button', {className: 'btn btn-danger', onClick: onConfirm, disabled: loading || !validReason}, loading ? 'Unblocking...' : 'Confirm Unblock')
        ),
      },
        h('div', {className: 'form-stack'},
          h('label', null, 'IP address'),
          h('input', {className: 'form-input mono containment-target', readOnly: true, value: target?.ip || ''}),
          h('label', null, 'FortiGate object'),
          h('input', {className: 'form-input mono', readOnly: true, value: target?.object_name || target?.fortigate_object || 'not available'}),
          h('label', null, 'Unblock justification'),
          h('textarea', {className: 'form-input', rows: 4, value: reason, onChange: event => onReasonChange(event.target.value), placeholder: 'Describe why containment can be removed'}),
          h('div', {className: validReason ? 'empty-detail' : 'form-warning'}, validReason ? 'Justification accepted for audit evidence.' : 'Enter at least 10 characters to confirm unblock.'),
          h('div', {className: 'empty-detail'}, 'The object will be removed from SPARK_BLOCKLIST and an unblock evidence record will be stored.')
        )
      );
    }

    function traceActorClass(actor) {
      return {Wazuh: 'binfo', Analyst: 'bnew', FortiGate: 'blive', SPARK: 'bexp', AI: 'binfo', Shuffle: 'binfo', System: 'binfo'}[actor] || 'binfo';
    }

    function statusClass(status) {
      const value = String(status || '').toLowerCase();
      if (value.includes('fail') || value.includes('error')) return 'bcrit';
      if (value.includes('warn') || value.includes('pending')) return 'bwarn';
      if (value.includes('success') || value.includes('verified') || value.includes('blocked') || value.includes('generated')) return 'blive';
      return 'binfo';
    }

    function buildTraceEvents(payload, evidence, briefing) {
      const now = new Date().toISOString();
      const candidate = briefingCandidate || {};
      const events = [
        {
          timestamp: candidate.timestamp || payload?.wazuh?.latest_timestamp || now,
          actor: 'Wazuh',
          action: `Alert generated${candidate.rule_id ? ` by rule ${candidate.rule_id}` : ''}`,
          result: candidate.title || candidate.description || `${fmtNum(payload?.wazuh?.total)} alerts normalized for triage`,
          status: payload?.wazuh?.total || candidate.rule_id ? 'success' : 'pending',
        },
        {
          timestamp: evidence?.requested_at || evidence?.created_at || now,
          actor: 'Analyst',
          action: evidence?.status === 'unblocked' ? 'Unblock IP requested' : 'Block IP reviewed',
          result: evidence?.ip ? `Target ${evidence.ip}` : 'Awaiting analyst containment decision',
          status: evidence ? 'success' : 'pending',
        },
      ];
      if (evidence && evidence.status !== 'unblocked') {
        events.push({
          timestamp: evidence.created_at || evidence.timestamp || now,
          actor: 'FortiGate',
          action: 'Address object and blocklist updated',
          result: `${containmentObjectName(evidence) || 'Address object'} -> ${containmentGroupName(evidence) || 'SPARK_BLOCKLIST'}`,
          status: containmentObjectName(evidence) ? 'success' : 'warning',
        });
      }
      if (evidence?.status === 'unblocked') {
        events.push({
          timestamp: evidence.created_at || evidence.timestamp || now,
          actor: 'FortiGate',
          action: 'Blocklist member removed',
          result: evidence.reason || 'Containment cleanup recorded',
          status: 'success',
        });
      }
      events.push({
        timestamp: evidence?.created_at || now,
        actor: 'SPARK',
        action: 'Evidence Pack generated',
        result: evidence?.evidence_id ? `Evidence ${evidence.evidence_id}` : 'Evidence workspace ready',
        status: evidence?.evidence_id ? 'success' : 'pending',
      });
      events.push({
        timestamp: briefing?.generatedAt?.toISOString?.() || now,
        actor: 'AI',
        action: 'Incident Briefing generated',
        result: briefing ? `${briefing.source === 'ai-live' ? 'Groq live' : 'Deterministic fallback'} briefing available` : 'Awaiting analyst request',
        status: briefing ? 'success' : 'pending',
      });
      if (payload?.shuffle?.connected) {
        events.push({
          timestamp: now,
          actor: 'Shuffle',
          action: 'SOAR connector checked',
          result: `${fmtNum(payload.shuffle.items)} workflow items discovered`,
          status: 'success',
        });
      }
      return events.slice(0, 8);
    }

    function SparkTraceTimeline({payload, evidence, briefing}) {
      const events = buildTraceEvents(payload, evidence, briefing);
      return h('div', {className: 'card spark-trace-timeline-card'},
        h('div', {className: 'ch'},
          h('div', null,
            h('div', {className: 'ct'}, 'SPARK Trace Timeline'),
            h('div', {className: 'cs'}, 'Operational story from detection to evidence handoff')
          ),
          h('span', {className: 'badge binfo'}, `${fmtNum(events.length)} events`)
        ),
        h('div', {className: 'cb trace-timeline'},
          events.map((event, index) => h('div', {className: 'trace-event', key: `${event.actor}-${index}-${event.action}`},
            h('div', {className: 'trace-event-time mono'}, fmtTime(event.timestamp)),
            h('span', {className: `badge ${traceActorClass(event.actor)}`}, event.actor),
            h('div', {className: 'trace-event-main'},
              h('div', {className: 'row-title'}, event.action),
              h('div', {className: 'muted'}, event.result)
            ),
            h('span', {className: `badge ${statusClass(event.status)}`}, event.status)
          ))
        )
      );
    }

    function AiBriefingCard({briefing}) {
      if (!briefing) return null;
      return h('div', {className: 'card ai-briefing-card'},
        h('div', {className: 'ch'},
          h('div', null,
            h('div', {className: 'ct'}, 'AI Incident Briefing'),
            h('div', {className: 'cs'}, `Generated ${briefing.generatedAt.toLocaleTimeString('pt-BR', {hour12: false, timeZone: 'America/Sao_Paulo'})} BRT · ${briefing.source === 'ai-live' ? `${briefing.provider} live` : 'deterministic fallback'} · ${briefing.model || 'provider-default'}`)
          ),
          h('div', {className: 'row-actions'},
            briefing.source === 'fallback' ? h('span', {className: 'badge bwarn'}, 'MODO DETERMINÍSTICO - IA indisponível') : h('span', {className: 'badge blive'}, 'AI live'),
            h('button', {className: 'btn', onClick: copyAiBriefing}, 'Copy Briefing')
          )
        ),
        h('div', {className: 'cb briefing-grid'},
          briefing.sections.map(([title, body]) => h('div', {className: 'briefing-item', key: title},
            h('div', {className: 'response-title'}, title),
            h('p', null, body)
          ))
        )
      );
    }

    const status = useMemo(() => {
      if (loading) return `Updating ${range} response telemetry...`;
      if (updatedAt) return `Live source check - updated ${updatedAt.toLocaleTimeString('pt-BR', {hour12: false, timeZone: 'America/Sao_Paulo'})} BRT`;
      return 'Awaiting telemetry from connected sources.';
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
          h('button', {className: 'btn', onClick: () => generateAiBriefing(false), disabled: aiBriefingLoading}, aiBriefingLoading ? 'Generating...' : 'Generate AI Briefing'),
          latestContainmentForUi ? h('button', {className: 'btn', onClick: () => generateAiBriefing(true), disabled: aiBriefingLoading}, aiBriefingLoading ? 'Generating...' : 'Briefing from latest containment') : null,
          h('button', {className: 'btn btnp', onClick: () => document.querySelector('button[onclick*="jira"]')?.click()}, 'Cases & Response')
        )
      ),
      h('div', {className: `aibox ${error ? 'loading' : ''}`},
        h('strong', null, 'Incident Response: '),
        error ? `Integration unavailable in this environment. ${error}` : 'Showing Wazuh candidates with FortiGate blocklist response evidence. Containment is pending traffic-path validation.'
      ),
      h(SparkTrace, {payload, evidence: lastEvidence}),
      h(SparkTraceTimeline, {payload, evidence: lastEvidence, briefing: aiBriefing}),
      h('div', {className: 'source-strip'},
        h(SourceChip, {label: 'Wazuh Indexer', ok: wazuhOk}),
        h(SourceChip, {label: 'Shuffle', ok: shuffleOk && payload.shuffle?.api_authenticated, statusText: payload.shuffle?.api_authenticated ? 'Online' : shuffleOk ? 'Auth Required' : 'Offline'}),
        h(SourceChip, {label: 'FortiAnalyzer', ok: Boolean(payload.fortianalyzer?.connected), statusText: fortiAnalyzerStatusLabel(payload.fortianalyzer)})
      ),
      h(components.LoadingState && loading && !data ? components.LoadingState : React.Fragment, loading && !data ? {title: 'Consulting Wazuh Indexer...', detail: 'Collecting incident candidates, cases and response evidence for this workspace.'} : null),
      h('div', {className: 'g11'},
        h(EvidencePack, {evidence: lastEvidence, payload, candidate: briefingCandidate, fortiAnalyzerEvidence, onCopy: copyEvidencePack, onExport: exportEvidencePack, onCopyHash: copyEvidenceHash, hash: evidenceHash}),
        h(ContainmentConfidence, {evidence: lastEvidence})
      ),
      h(AiBriefingCard, {briefing: aiBriefing}),
      h('div', {className: 'g4'},
        h(KpiCard, {label: 'Incident Candidates', value: fmtNum(candidates.length), detail: `<span class="up">${fmtNum(payload.wazuh?.total)}</span> Wazuh alerts in range`, critical: candidates.length > 0}),
        h(KpiCard, {label: 'P1 Candidates', value: fmtNum(counts.p1), detail: 'Wazuh level >= 12'}),
        h(KpiCard, {label: 'P2 Candidates', value: fmtNum(counts.p2), detail: 'Wazuh level 7-11'}),
        h(KpiCard, {label: 'Open Cases', value: fmtNum(cases.length), detail: 'Lifecycle queue'}),
        h(KpiCard, {label: 'Shuffle Workflows', value: shuffleOk ? fmtNum(payload.shuffle?.items) : 'N/A', detail: shuffleOk ? `<span class="dn">${payload.shuffle?.source || 'connected'}</span>` : '<span class="up">Connector not validated</span>'})
      ),
      h('div', {className: 'g11'},
        h(ShuffleStatus, {shuffle: payload.shuffle}),
        h(ReadinessPanel, {notes: payload.notes})
      ),
      h(CandidateTable, {items: candidates, onCreateCase: createCase, onBlock: openBlockModal, actionState}),
      h(CaseQueue, {cases, onCaseAction: runCaseAction, onBlock: openBlockModal, actionState}),
      h(FortiGateBlocklistCard, {items: blocklist}),
      window.SparkIncident?.BlockIpModal ? h(window.SparkIncident.BlockIpModal, {
        open: Boolean(blockTarget),
        target: blockTarget,
        defaultReason: blockTarget ? `Containment for ${caseTitle(blockTarget)}` : '',
        action: {loading: actionState.startsWith('block:')},
        onClose: () => setBlockTarget(null),
        onSubmit: submitBlockIp,
      }) : null,
      h(UnblockConfirmModal, {
        open: Boolean(unblockTarget),
        target: unblockTarget,
        reason: unblockReason,
        loading: actionState.startsWith('unblock:'),
        onReasonChange: setUnblockReason,
        onClose: () => setUnblockTarget(null),
        onConfirm: unblockIp,
      }),
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

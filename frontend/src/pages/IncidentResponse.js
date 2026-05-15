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
    const ok = Boolean(shuffle?.connected);
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Shuffle SOAR Status'),
          h('div', {className: 'cs'}, 'Connectivity and basic endpoint discovery')
        ),
        h('span', {className: `badge ${ok ? 'blive' : 'bhigh'}`}, ok ? 'Connected' : 'Connector unavailable')
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
        !ok ? h('div', {style: {fontSize: 11, color: 'var(--amber)', marginTop: 10}}, shuffle?.error || 'SOAR connector credentials are not available in this workspace.') : null
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
    const [aiBriefing, setAiBriefing] = useState(null);
    const [aiBriefingLoading, setAiBriefingLoading] = useState(false);
    const [aiProvider, setAiProvider] = useState({provider: 'none', mode: 'deterministic_fallback'});
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
      return h('div', {className: 'card'},
        h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Containment Confidence'), h('div', {className: 'cs'}, 'Technical checks for FortiGate response evidence'))),
        h('div', {className: 'cb confidence-grid'},
          checks.map(item => h('div', {className: 'confidence-item', key: item.label},
            h('span', {className: `confidence-dot ${item.ok ? 'ok' : 'warn'}`}),
            h('div', null, h('div', {className: 'row-title'}, item.label), h('div', {className: 'muted'}, item.ok ? 'Validated by latest response' : 'Pending latest evidence'))
          ))
        )
      );
    }

    function evidencePackSections(evidence, payload, candidate) {
      const score = containmentScore(evidence);
      return [
        ['Executive Summary', `${caseTitle(candidate)}. Severity ${candidate?.priority || candidate?.severity || '--'} with source ${caseIp(candidate) || evidence?.ip || '--'} targeting ${caseTarget(candidate)}.`],
        ['Technical Evidence', `Wazuh alerts: ${fmtNum(payload.wazuh?.total)}. Rule: ${candidate?.rule_id || '--'}. MITRE: ${caseMitre(candidate)}.`],
        ['Response Actions', `FortiGate object ${containmentObjectName(evidence) || '--'} added to ${containmentGroupName(evidence) || 'SPARK_BLOCKLIST'} with policy ${containmentPolicyName(evidence) || 'SPARK_AUTO_BLOCK'}.`],
        ['Containment Proof', `Evidence ID ${evidence?.evidence_id || '--'}. Containment confidence ${score}%. Status ${evidence?.status || 'Awaiting response evidence'}.`],
        ['Compliance Evidence', 'Technical evidence is available for analyst review and auditor handoff. This is not automatic certification.'],
        ['Next Steps', 'Validate traffic-path enforcement, review related alerts, update the case owner and attach Evidence Pack to the customer workspace.'],
      ];
    }

    function buildEvidencePackText(evidence, payload, candidate) {
      return evidencePackSections(evidence, payload, candidate)
        .map(([title, body]) => `${title}\n${body}`)
        .join('\n\n');
    }

    function EvidencePack({evidence, payload, candidate, onCopy}) {
      const sections = evidencePackSections(evidence, payload, candidate);
      return h('div', {className: 'card'},
        h('div', {className: 'ch'},
          h('div', null, h('div', {className: 'ct'}, 'Evidence Pack'), h('div', {className: 'cs'}, 'Audit-ready response summary for MDR handoff')),
          h('button', {className: 'btn', onClick: onCopy}, 'Copy Evidence Pack')
        ),
        h('div', {className: 'cb evidence-pack'},
          sections.map(([title, body]) => h('div', {className: `response-evidence ${title === 'Containment Proof' && evidence ? 'ok' : ''}`, key: title},
            h('div', {className: 'response-title'}, title),
            h('p', {className: 'evidence-copy'}, body)
          ))
        )
      );
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
    const briefingCandidate = candidates[0] || cases[0] || {};

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
        ['Executive Summary', value.executive_summary || 'Incident summary requires analyst review.'],
        ['Severity Rationale', value.severity_rationale || 'Severity rationale requires analyst review.'],
        ['Response Taken', value.response_taken || 'No response evidence recorded yet.'],
        ['Containment Status', value.containment_status || 'Containment status requires analyst review.'],
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
          executive_summary: `${caseTitle(incident)} is prioritized as ${incident.priority || incident.severity || 'analyst review'} with source ${caseIp(incident) || evidence.ip || '--'} and target ${caseTarget(incident)}.`,
          severity_rationale: rule !== '--'
            ? `${incident.priority || incident.severity || 'Requires analyst review'} based on Wazuh rule ${rule}${alerts !== '' ? `, ${fmtNum(alerts)} alert(s),` : ''} and current incident context.`
            : `${incident.priority || incident.severity || 'Requires analyst review'} based on current incident context and analyst evidence.`,
          response_taken: selected.hasContainment
            ? `FortiGate object ${containmentObjectName(evidence) || '--'}, group ${containmentGroupName(evidence) || 'SPARK_BLOCKLIST'}, policy ${containmentPolicyName(evidence) || 'SPARK_AUTO_BLOCK'}, evidence ${evidence.evidence_id || '--'}.`
            : 'No containment action has been executed for this incident yet.',
          containment_status: containmentPhrase,
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
        '',
        ...sections.map(([title, body]) => `${title}: ${body}`),
      ].join('\n');
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
        const text = buildEvidencePackText(lastEvidence, payload, briefingCandidate);
        await copyText(text);
        toast.pushToast({tone: 'success', title: 'Evidence Pack copied', message: 'Structured evidence is ready for handoff.'});
      } catch (err) {
        toast.pushToast({tone: 'error', title: 'Evidence Pack copy unavailable', message: err.message});
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

    function AiBriefingCard({briefing}) {
      if (!briefing) return null;
      return h('div', {className: 'card ai-briefing-card'},
        h('div', {className: 'ch'},
          h('div', null,
            h('div', {className: 'ct'}, 'AI Incident Briefing'),
            h('div', {className: 'cs'}, `Generated ${briefing.generatedAt.toLocaleTimeString('pt-BR', {hour12: false, timeZone: 'America/Sao_Paulo'})} BRT · ${briefing.source === 'ai-live' ? `${briefing.provider} live` : 'deterministic fallback'} · ${briefing.model || 'provider-default'}`)
          ),
          h('button', {className: 'btn', onClick: copyAiBriefing}, 'Copy Briefing')
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
      h('div', {className: 'source-strip'},
        h(SourceChip, {label: 'Wazuh Indexer', ok: wazuhOk}),
        h(SourceChip, {label: 'Shuffle', ok: shuffleOk})
      ),
      h(components.LoadingState && loading && !data ? components.LoadingState : React.Fragment, loading && !data ? {title: 'Loading response telemetry', detail: 'Collecting candidates, cases, and action evidence.'} : null),
      h('div', {className: 'g11'},
        h(EvidencePack, {evidence: lastEvidence, payload, candidate: briefingCandidate, onCopy: copyEvidencePack}),
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

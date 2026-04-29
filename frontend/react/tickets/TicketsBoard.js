(function () {
  const {useEffect, useMemo, useState} = React;
  const h = React.createElement;

  const STATUSES = [
    ['open', 'Open'],
    ['inprogress', 'In Progress'],
    ['review', 'In Review'],
    ['done', 'Done'],
  ];
  const PRIORITIES = [['p1', 'P1'], ['p2', 'P2'], ['p3', 'P3'], ['p4', 'P4']];
  const TYPES = ['incident', 'threat', 'vuln', 'task', 'change'];

  function priorityClass(priority) {
    return {p1: 'bcrit', p2: 'bhigh', p3: 'bmed', p4: 'blow'}[priority] || 'blow';
  }

  function emptyTicket() {
    return {
      title: '',
      status: 'open',
      priority: 'p3',
      type: 'incident',
      assignee: '',
      incidentLink: '',
      mitre: '',
      ip: '',
      country: '',
      desc: '',
      playbook: '',
      escalatedTo: '',
      escalationReason: '',
      syncJira: false,
    };
  }

  function Kpi({label, value, tone}) {
    return h('div', {className: 'jstat'},
      h('div', {className: 'jstat-v', style: tone ? {color: `var(--${tone})`} : null}, value),
      h('div', {className: 'jstat-l'}, label)
    );
  }

  function TicketCard({ticket, onEdit}) {
    const pLabel = (ticket.priority || 'p4').toUpperCase();
    return h('div', {className: 'jcard', onClick: () => onEdit(ticket)},
      h('div', {className: 'jcard-id'},
        h('span', null, ticket.id || 'SPARK'),
        h('span', {style: {fontSize: 10, color: 'var(--tm)'}}, ticket.type || 'ticket')
      ),
      h('div', {className: 'jcard-title'}, ticket.title || 'Untitled ticket'),
      h('div', {className: 'jcard-meta'},
        h('span', {className: `badge ${priorityClass(ticket.priority)}`}, pLabel),
        ticket.incidentLink ? h('span', {className: 'jcard-inc'}, ticket.incidentLink) : null,
        ticket.ipBlocked ? h('span', {className: 'jcard-blocked'}, 'In Blocklist') : null,
        ticket.escalatedTo ? h('span', {className: 'jcard-escalated'}, 'Escalated') : null,
        ticket.externalKey ? h('span', {className: 'jcard-inc'}, ticket.externalKey) : null,
        ticket.assignee ? h('div', {className: 'jcard-av', title: ticket.assignee}, ticket.assignee.split(' ').map(x => x[0]).join('').slice(0, 2).toUpperCase()) : null,
        h('span', {style: {fontSize: 10, color: 'var(--tm)', marginLeft: 'auto'}}, ticket.created || '')
      )
    );
  }

  function Board({tickets, filters, onEdit}) {
    const filtered = tickets.filter(ticket =>
      (!filters.priority || ticket.priority === filters.priority) &&
      (!filters.type || ticket.type === filters.type) &&
      (!filters.assignee || ticket.assignee === filters.assignee)
    );
    return h('div', {className: 'jira-board'},
      STATUSES.map(([status, label]) => {
        const items = filtered.filter(ticket => ticket.status === status);
        return h('div', {className: `jira-col jcol-${status === 'inprogress' ? 'prog' : status}`, key: status},
          h('div', {className: 'jira-col-head'}, label, h('span', {className: 'jira-col-count'}, items.length)),
          h('div', {className: 'jira-col-body'},
            items.length ? items.map(ticket => h(TicketCard, {ticket, onEdit, key: ticket.id})) :
              h('div', {style: {fontSize: 11, color: 'var(--tm)', padding: 10}}, 'No cases')
          )
        );
      })
    );
  }

  function LogTable({title, subtitle, badge, rows, columns, empty}) {
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null, h('div', {className: 'ct'}, title), h('div', {className: 'cs'}, subtitle)),
        h('span', {className: 'badge binfo'}, badge)
      ),
      rows.length ? h('div', {className: 'table-scroll'},
        h('table', {className: 'ftable'},
          h('thead', null, h('tr', null, columns.map(col => h('th', {key: col.key}, col.label)))),
          h('tbody', null, rows.map((row, idx) => h('tr', {key: idx},
            columns.map(col => h('td', {key: col.key}, col.render ? col.render(row) : (row[col.key] || '--')))
          )))
        )
      ) : h('div', {style: {padding: 20, textAlign: 'center', fontSize: 12, color: 'var(--tm)'}}, empty)
    );
  }

  function TicketForm({value, onChange, onSubmit, onClose, onBlock, onEscalate, onSyncJira, jiraReady, saving, blocking, lastAction}) {
    function update(field, next) {
      onChange({...value, [field]: next});
    }
    return h('div', {className: 'card', style: {marginBottom: 14}},
      h('div', {className: 'ch'},
        h('div', null, h('div', {className: 'ct'}, value.id ? `Edit ${value.id}` : 'New Incident Case'), h('div', {className: 'cs'}, 'SOC case record with FortiGate response actions')),
        h('button', {className: 'btn', onClick: onClose}, 'Close')
      ),
      h('div', {className: 'case-form-grid'},
        h('div', {style: {display: 'flex', flexDirection: 'column', gap: 10}},
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-label'}, 'Incident Summary'), h('input', {className: 'jm-input', value: value.title || '', onChange: e => update('title', e.target.value), placeholder: 'Describe the incident or response task'})),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-label'}, 'Description / Evidence'), h('textarea', {className: 'jm-textarea', value: value.desc || '', onChange: e => update('desc', e.target.value), placeholder: 'Observed evidence, source alert IDs, analyst notes'})),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-label'}, 'Response Playbook'), h('textarea', {className: 'jm-textarea', value: value.playbook || '', onChange: e => update('playbook', e.target.value), placeholder: 'Use validated steps or leave empty until a real playbook is selected'}))
        ),
        h('div', {style: {display: 'flex', flexDirection: 'column', gap: 10}},
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'Status'), h('select', {className: 'jm-select', value: value.status || 'open', onChange: e => update('status', e.target.value)}, STATUSES.map(([status, label]) => h('option', {value: status, key: status}, label)))),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'Priority'), h('select', {className: 'jm-select', value: value.priority || 'p3', onChange: e => update('priority', e.target.value)}, PRIORITIES.map(([priority, label]) => h('option', {value: priority, key: priority}, label)))),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'Type'), h('select', {className: 'jm-select', value: value.type || 'incident', onChange: e => update('type', e.target.value)}, TYPES.map(type => h('option', {value: type, key: type}, type)))),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'Assignee'), h('input', {className: 'jm-input', value: value.assignee || '', onChange: e => update('assignee', e.target.value), placeholder: 'Unassigned'})),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'Linked Incident / Alert'), h('input', {className: 'jm-input', value: value.incidentLink || '', onChange: e => update('incidentLink', e.target.value), placeholder: 'Wazuh document ID or SPARK case ID'})),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'MITRE'), h('input', {className: 'jm-input', value: value.mitre || '', onChange: e => update('mitre', e.target.value), placeholder: 'Txxxx'})),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'Source IP'), h('input', {className: 'jm-input', value: value.ip || '', onChange: e => update('ip', e.target.value), placeholder: 'IP to investigate or block'})),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'Escalate To'), h('input', {className: 'jm-input', value: value.escalatedTo || '', onChange: e => update('escalatedTo', e.target.value), placeholder: 'Team Lead / SOC Manager / CISO'})),
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-sidebar-label'}, 'Escalation Reason'), h('textarea', {className: 'jm-textarea', value: value.escalationReason || '', onChange: e => update('escalationReason', e.target.value), placeholder: 'Reason for escalation'})),
          lastAction ? h('div', {className: `response-evidence ${lastAction.ok ? 'ok' : 'err'}`},
            h('div', {className: 'response-title'}, lastAction.ok ? 'FortiGate blocklist updated' : 'FortiGate action failed'),
            h('div', {className: 'response-line'}, lastAction.message || 'No API message returned.'),
            h('div', {className: 'response-grid'},
              h('span', null, 'Object'), h('strong', null, lastAction.object || '--'),
              h('span', null, 'Group'), h('strong', null, lastAction.group || '--'),
              h('span', null, 'Policy'), h('strong', null, lastAction.policy_found ? `${lastAction.policy} found` : `${lastAction.policy || 'policy'} missing`),
              h('span', null, 'Enforcement'), h('strong', null, lastAction.enforcement_path || 'pending network routing validation')
            )
          ) : null,
          !value.id ? h('label', {style: {display: 'flex', gap: 8, alignItems: 'center', fontSize: 11, color: 'var(--t2)'}} ,
            h('input', {type: 'checkbox', checked: Boolean(value.syncJira), disabled: !jiraReady, onChange: e => update('syncJira', e.target.checked)}),
            jiraReady ? 'Also sync to Jira on save' : 'Jira sync unavailable'
          ) : null,
          value.externalKey ? h('a', {href: value.externalUrl || '#', target: '_blank', rel: 'noreferrer', className: 'btn'}, `Open ${value.externalKey}`) : null,
          h('button', {className: 'jm-submit', disabled: saving || !value.title, onClick: onSubmit}, saving ? 'Saving...' : 'Save Case'),
          value.id && value.ip ? h('button', {className: 'btn btnp', disabled: blocking, onClick: onBlock}, blocking ? 'Applying to FortiGate...' : 'Add IP to FortiGate Blocklist') : null,
          value.id && !value.externalKey ? h('button', {className: 'btn btnj', disabled: !jiraReady, onClick: onSyncJira}, jiraReady ? 'Optional Jira Sync' : 'Jira Offline') : null,
          value.id && value.escalatedTo ? h('button', {className: 'btn', onClick: onEscalate}, 'Register Escalation') : null
        )
      )
    );
  }

  function JiraStatusCard({jira, onRefresh}) {
    const configured = Boolean(jira?.configured);
    const connected = Boolean(jira?.connected);
    return h('details', {className: 'card optional-integration', style: {marginBottom: 14}},
      h('summary', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Optional Jira Integration'),
          h('div', {className: 'cs'}, 'External issue sync; SPARK cases remain the primary SOC record')
        ),
        h('span', {className: `badge ${connected ? 'blive' : configured ? 'bhigh' : 'binfo'}`}, connected ? 'Connected' : configured ? 'Configured' : 'Not configured')
      ),
      h('div', {className: 'jira-status-grid'},
        h('div', {className: 'detail-cell'}, h('div', {className: 'detail-label'}, 'Project'), h('div', {className: 'detail-value'}, jira?.project || 'SPARK')),
        h('div', {className: 'detail-cell'}, h('div', {className: 'detail-label'}, 'Account'), h('div', {className: 'detail-value'}, jira?.account || '--')),
        h('div', {className: 'detail-cell'}, h('div', {className: 'detail-label'}, 'User API'), h('div', {className: 'detail-value'}, jira?.user_status || '--')),
        h('div', {className: 'detail-cell'}, h('div', {className: 'detail-label'}, 'Project API'), h('div', {className: 'detail-value'}, jira?.project_status || '--')),
        h('button', {className: 'btn', onClick: onRefresh}, 'Check')
      ),
      h('div', {style: {padding: '0 16px 14px', fontSize: 11, color: configured ? 'var(--t2)' : 'var(--amber)'}}, jira?.message || 'Configure JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN and JIRA_PROJECT_KEY.')
    );
  }

  function TicketsBoardApp() {
    const [tickets, setTickets] = useState([]);
    const [blockLog, setBlockLog] = useState([]);
    const [actionEvents, setActionEvents] = useState([]);
    const [escalations, setEscalations] = useState([]);
    const [jiraStatus, setJiraStatus] = useState({configured: false, connected: false});
    const [filters, setFilters] = useState({priority: '', type: '', assignee: ''});
    const [editing, setEditing] = useState(null);
    const [saving, setSaving] = useState(false);
    const [blocking, setBlocking] = useState(false);
    const [lastAction, setLastAction] = useState(null);
    const [message, setMessage] = useState('');
    const [updatedAt, setUpdatedAt] = useState(null);

    async function load() {
      const [ticketResp, blockResp, actionResp, escResp, jiraResp] = await Promise.all([
        fetch('/spark/tickets', {credentials: 'include'}),
        fetch('/spark/ip-block-log', {credentials: 'include'}),
        fetch('/spark/action-events?limit=20', {credentials: 'include'}),
        fetch('/spark/escalation-log', {credentials: 'include'}),
        fetch('/spark/jira/status', {credentials: 'include'}),
      ]);
      setTickets(ticketResp.ok ? await ticketResp.json() : []);
      setBlockLog(blockResp.ok ? await blockResp.json() : []);
      setActionEvents(actionResp.ok ? await actionResp.json() : []);
      setEscalations(escResp.ok ? await escResp.json() : []);
      setJiraStatus(jiraResp.ok ? await jiraResp.json() : {configured: false, connected: false, message: `HTTP ${jiraResp.status}`});
      setUpdatedAt(new Date());
    }

    useEffect(() => {
      load().catch(err => setMessage(`Ticket API unavailable: ${err.message}`));
      const refresh = () => load().catch(err => setMessage(`Ticket API unavailable: ${err.message}`));
      window.addEventListener('spark:tickets-refresh', refresh);
      return () => window.removeEventListener('spark:tickets-refresh', refresh);
    }, []);

    async function saveTicket() {
      setSaving(true);
      try {
        const isEdit = Boolean(editing.id);
        const response = await fetch(isEdit ? `/spark/tickets/${encodeURIComponent(editing.id)}` : '/spark/tickets', {
          method: isEdit ? 'PUT' : 'POST',
          credentials: 'include',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(editing),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        setEditing(null);
        setMessage('Ticket saved in SPARK case store.');
        await load();
      } catch (err) {
        setMessage(`Save failed: ${err.message}`);
      } finally {
        setSaving(false);
      }
    }

    async function blockIp() {
      if (!editing?.ip) return;
      setBlocking(true);
      setLastAction(null);
      try {
        const response = await fetch('/spark/block-ip', {
          method: 'POST',
          credentials: 'include',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            ip: editing.ip,
            country: editing.country || '',
            reason: editing.title || editing.id,
            analyst: editing.assignee || 'SOC',
            ticket_id: editing.id || '',
            case_id: editing.incidentLink || '',
          }),
        });
        const payload = await response.json().catch(() => ({}));
        const fg = payload.fortigate || {ok: false, message: payload.message || `HTTP ${response.status}`};
        setLastAction(fg);
        setMessage(response.ok ? (payload.message || `FortiGate blocklist updated for ${editing.ip}.`) : `Block failed: ${payload.message || `HTTP ${response.status}`}`);
        if (response.ok) setEditing({...editing, ipBlocked: true});
        await load();
      } finally {
        setBlocking(false);
      }
    }

    async function escalate() {
      if (!editing?.id || !editing?.escalatedTo) return;
      const response = await fetch('/spark/escalate', {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ticket_id: editing.id, to: editing.escalatedTo, reason: editing.escalationReason || '', analyst: editing.assignee || 'SOC'}),
      });
      setMessage(response.ok ? `Escalation registered for ${editing.id}.` : `Escalation failed: HTTP ${response.status}`);
      await load();
    }

    async function syncCurrentToJira() {
      if (!editing?.id) return;
      const response = await fetch(`/spark/tickets/${encodeURIComponent(editing.id)}/jira`, {
        method: 'POST',
        credentials: 'include',
      });
      const payload = await response.json().catch(() => ({}));
      if (response.ok) {
        setEditing(payload.ticket || editing);
        setMessage(`Jira issue ${payload.jira?.key || ''} created.`);
      } else {
        setMessage(`Jira sync failed: ${payload.jira?.message || payload.error || `HTTP ${response.status}`}`);
      }
      await load();
    }

    const stats = useMemo(() => ({
      open: tickets.filter(t => t.status !== 'done').length,
      p1: tickets.filter(t => t.priority === 'p1' && t.status !== 'done').length,
      p2: tickets.filter(t => t.priority === 'p2' && t.status !== 'done').length,
      done: tickets.filter(t => t.status === 'done').length,
      blocked: blockLog.filter(x => x.action === 'Blocked' && x.status === 'Active').length,
    }), [tickets, blockLog]);

    const assignees = [...new Set(tickets.map(t => t.assignee).filter(Boolean))];

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null, h('div', {className: 'ptitle'}, 'Cases & Response'), h('div', {className: 'psub'}, h('span', {className: 'ldot'}), updatedAt ? `SOC case store - updated ${updatedAt.toLocaleTimeString('en-US')}` : 'SOC case store')),
        h('div', {className: 'ha'}, h('button', {className: 'btn', onClick: load}, 'Refresh'), h('button', {className: 'btn btnj', onClick: () => { setLastAction(null); setEditing(emptyTicket()); }}, 'New Case'))
      ),
      h('div', {className: 'jira-stats'},
        h(Kpi, {label: 'Open Total', value: stats.open, tone: 'red'}),
        h(Kpi, {label: 'P1 Critical', value: stats.p1, tone: 'red'}),
        h(Kpi, {label: 'P2 High', value: stats.p2, tone: 'amber'}),
        h(Kpi, {label: 'Resolved', value: stats.done, tone: 'green'}),
        h(Kpi, {label: 'Active Blocks', value: stats.blocked, tone: 'blue'})
      ),
      h('div', {className: `aibox ${message ? '' : 'loading'}`}, h('strong', null, 'Cases & Response: '), message || 'Track incident cases, FortiGate response actions and escalation evidence.'),
      h(JiraStatusCard, {jira: jiraStatus, onRefresh: load}),
      editing ? h(TicketForm, {value: editing, onChange: setEditing, onSubmit: saveTicket, onClose: () => setEditing(null), onBlock: blockIp, onEscalate: escalate, onSyncJira: syncCurrentToJira, jiraReady: jiraStatus.connected, saving, blocking, lastAction}) : null,
      h('div', {className: 'jira-topbar'},
        h('div', {className: 'jira-filters'},
          h('select', {className: 'jira-filter-sel', value: filters.priority, onChange: e => setFilters({...filters, priority: e.target.value})}, h('option', {value: ''}, 'All priorities'), PRIORITIES.map(([p, label]) => h('option', {value: p, key: p}, label))),
          h('select', {className: 'jira-filter-sel', value: filters.type, onChange: e => setFilters({...filters, type: e.target.value})}, h('option', {value: ''}, 'All types'), TYPES.map(type => h('option', {value: type, key: type}, type))),
          h('select', {className: 'jira-filter-sel', value: filters.assignee, onChange: e => setFilters({...filters, assignee: e.target.value})}, h('option', {value: ''}, 'All assignees'), assignees.map(name => h('option', {value: name, key: name}, name)))
        ),
        h('div', {style: {fontSize: 11, color: 'var(--tm)'}}, updatedAt ? `Last sync: ${updatedAt.toLocaleTimeString('en-US')}` : 'Not synced')
      ),
      h(Board, {tickets, filters, onEdit: ticket => setEditing({...ticket})}),
      h('div', {className: 'g11'},
        h(LogTable, {
          title: 'IP Block Log',
          subtitle: 'FortiGate blocklist records via FortiOS REST API',
          badge: `${blockLog.length} entries`,
          rows: blockLog,
          empty: 'No IP block actions recorded.',
          columns: [
            {key: 'ip', label: 'IP', render: row => h('span', {className: 'mono'}, row.ip || '--')},
            {key: 'country', label: 'Country'},
            {key: 'action', label: 'Action', render: row => h('span', {className: `badge ${row.action === 'Blocked' ? 'bcrit' : 'bok'}`}, row.action || '--')},
            {key: 'reason', label: 'Reason'},
            {key: 'analyst', label: 'Analyst'},
            {key: 'time', label: 'Time', render: row => h('span', {className: 'mono'}, row.time || '--')},
            {key: 'status', label: 'Status'},
          ],
        }),
        h(LogTable, {
          title: 'FortiGate Action Evidence',
          subtitle: 'Configuration API evidence; runtime enforcement pending network routing validation',
          badge: `${actionEvents.length} entries`,
          rows: actionEvents,
          empty: 'No FortiGate response actions recorded.',
          columns: [
            {key: 'ip', label: 'IP', render: row => h('span', {className: 'mono'}, row.ip || '--')},
            {key: 'object_name', label: 'Object', render: row => h('span', {className: 'mono'}, row.object_name || '--')},
            {key: 'group_name', label: 'Group'},
            {key: 'policy_name', label: 'Policy'},
            {key: 'status', label: 'Status', render: row => h('span', {className: `badge ${row.status === 'success' ? 'blive' : 'bcrit'}`}, row.status || '--')},
            {key: 'enforcement_path', label: 'Enforcement'},
          ],
        }),
      ),
      h('div', {className: 'g11'},
        h(LogTable, {
          title: 'Escalations',
          subtitle: 'SPARK escalation records',
          badge: `${escalations.length} entries`,
          rows: escalations,
          empty: 'No escalations recorded.',
          columns: [
            {key: 'ticket', label: 'Ticket', render: row => h('span', {className: 'mono'}, row.ticket || '--')},
            {key: 'incident', label: 'Incident'},
            {key: 'to', label: 'To'},
            {key: 'reason', label: 'Reason'},
            {key: 'time', label: 'Time', render: row => h('span', {className: 'mono'}, row.time || '--')},
            {key: 'status', label: 'Status'},
          ],
        })
      )
    );
  }

  const root = document.getElementById('tickets-root');
  if (root) ReactDOM.createRoot(root).render(h(TicketsBoardApp));
})();

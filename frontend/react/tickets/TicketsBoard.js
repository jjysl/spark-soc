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
        ticket.ipBlocked ? h('span', {className: 'jcard-blocked'}, 'IP Blocked') : null,
        ticket.escalatedTo ? h('span', {className: 'jcard-escalated'}, 'Escalated') : null,
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
              h('div', {style: {fontSize: 11, color: 'var(--tm)', padding: 10}}, 'No tickets')
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
      rows.length ? h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, columns.map(col => h('th', {key: col.key}, col.label)))),
        h('tbody', null, rows.map((row, idx) => h('tr', {key: idx},
          columns.map(col => h('td', {key: col.key}, col.render ? col.render(row) : (row[col.key] || '--')))
        )))
      ) : h('div', {style: {padding: 20, textAlign: 'center', fontSize: 12, color: 'var(--tm)'}}, empty)
    );
  }

  function TicketForm({value, onChange, onSubmit, onClose, onBlock, onEscalate, saving}) {
    function update(field, next) {
      onChange({...value, [field]: next});
    }
    return h('div', {className: 'card', style: {marginBottom: 14}},
      h('div', {className: 'ch'},
        h('div', null, h('div', {className: 'ct'}, value.id ? `Edit ${value.id}` : 'New SPARK Ticket'), h('div', {className: 'cs'}, 'Local SOC case record')),
        h('button', {className: 'btn', onClick: onClose}, 'Close')
      ),
      h('div', {style: {padding: 14, display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14}},
        h('div', {style: {display: 'flex', flexDirection: 'column', gap: 10}},
          h('div', {className: 'jm-field'}, h('div', {className: 'jm-label'}, 'Title'), h('input', {className: 'jm-input', value: value.title || '', onChange: e => update('title', e.target.value), placeholder: 'Describe the incident or task'})),
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
          h('button', {className: 'jm-submit', disabled: saving || !value.title, onClick: onSubmit}, saving ? 'Saving...' : 'Save Ticket'),
          value.id && value.ip ? h('button', {className: 'btn', onClick: onBlock}, 'Block IP') : null,
          value.id && value.escalatedTo ? h('button', {className: 'btn', onClick: onEscalate}, 'Register Escalation') : null
        )
      )
    );
  }

  function TicketsBoardApp() {
    const [tickets, setTickets] = useState([]);
    const [blockLog, setBlockLog] = useState([]);
    const [escalations, setEscalations] = useState([]);
    const [filters, setFilters] = useState({priority: '', type: '', assignee: ''});
    const [editing, setEditing] = useState(null);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState('');
    const [updatedAt, setUpdatedAt] = useState(null);

    async function load() {
      const [ticketResp, blockResp, escResp] = await Promise.all([
        fetch('/spark/tickets', {credentials: 'include'}),
        fetch('/spark/ip-block-log', {credentials: 'include'}),
        fetch('/spark/escalation-log', {credentials: 'include'}),
      ]);
      setTickets(ticketResp.ok ? await ticketResp.json() : []);
      setBlockLog(blockResp.ok ? await blockResp.json() : []);
      setEscalations(escResp.ok ? await escResp.json() : []);
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
      const response = await fetch('/spark/block-ip', {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip: editing.ip, country: editing.country || '', reason: editing.title || editing.id, analyst: editing.assignee || 'SOC'}),
      });
      setMessage(response.ok ? `Block action registered for ${editing.ip}.` : `Block failed: HTTP ${response.status}`);
      await load();
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

    const stats = useMemo(() => ({
      open: tickets.filter(t => t.status !== 'done').length,
      p1: tickets.filter(t => t.priority === 'p1' && t.status !== 'done').length,
      p2: tickets.filter(t => t.priority === 'p2' && t.status !== 'done').length,
      done: tickets.filter(t => t.status === 'done').length,
      blocked: blockLog.filter(x => x.action === 'Bloqueado' && x.status === 'Ativo').length,
    }), [tickets, blockLog]);

    const assignees = [...new Set(tickets.map(t => t.assignee).filter(Boolean))];

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null, h('div', {className: 'ptitle'}, 'Incident Tickets'), h('div', {className: 'psub'}, h('span', {className: 'ldot'}), updatedAt ? `SPARK case store - updated ${updatedAt.toLocaleTimeString('en-US')}` : 'SPARK case store')),
        h('div', {className: 'ha'}, h('button', {className: 'btn', onClick: load}, 'Sync'), h('button', {className: 'btn btnj', onClick: () => setEditing(emptyTicket())}, 'New Ticket'))
      ),
      h('div', {className: 'jira-stats'},
        h(Kpi, {label: 'Open Total', value: stats.open, tone: 'red'}),
        h(Kpi, {label: 'P1 Critical', value: stats.p1, tone: 'red'}),
        h(Kpi, {label: 'P2 High', value: stats.p2, tone: 'amber'}),
        h(Kpi, {label: 'Resolved', value: stats.done, tone: 'green'}),
        h(Kpi, {label: 'Active Blocks', value: stats.blocked, tone: 'blue'})
      ),
      h('div', {className: `aibox ${message ? '' : 'loading'}`}, h('strong', null, 'Tickets: '), message || 'No seeded demo tickets are loaded. Create or sync real SPARK case records.'),
      editing ? h(TicketForm, {value: editing, onChange: setEditing, onSubmit: saveTicket, onClose: () => setEditing(null), onBlock: blockIp, onEscalate: escalate, saving}) : null,
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
          subtitle: 'SPARK block/unblock records',
          badge: `${blockLog.length} entries`,
          rows: blockLog,
          empty: 'No IP block actions recorded.',
          columns: [
            {key: 'ip', label: 'IP', render: row => h('span', {className: 'mono'}, row.ip || '--')},
            {key: 'country', label: 'Country'},
            {key: 'action', label: 'Action', render: row => h('span', {className: `badge ${row.action === 'Bloqueado' ? 'bcrit' : 'bok'}`}, row.action || '--')},
            {key: 'reason', label: 'Reason'},
            {key: 'analyst', label: 'Analyst'},
            {key: 'time', label: 'Time', render: row => h('span', {className: 'mono'}, row.time || '--')},
            {key: 'status', label: 'Status'},
          ],
        }),
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

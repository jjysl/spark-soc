(function () {
  const h = React.createElement;
  const C = window.SparkComponents;
  const L = window.SparkLayout;
  const api = window.SparkApi;

  function Cases() {
    const live = window.SparkHooks.useLiveData(() => api.incidents.listCases(), {interval: 60000});
    const cases = Array.isArray(live.data) ? live.data : [];
    return h(L.PageContainer, {title: 'Cases', subtitle: 'Incident case lifecycle and ownership.', actions: h('button', {className: 'btn', onClick: live.refresh}, 'Refresh')},
      live.loading ? h(C.LoadingState, {title: 'Loading cases'}) : null,
      live.error ? h(C.ErrorState, {detail: live.error.message}) : null,
      h('div', {className: 'card table-scroll'},
        h('table', {className: 'ftable'},
          h('thead', null, h('tr', null, ['Case', 'Priority', 'Status', 'Owner', 'SLA'].map(col => h('th', {key: col}, col)))),
          h('tbody', null, cases.map(item => h('tr', {key: item.case_id || item.id},
            h('td', null, h('div', {className: 'row-title'}, item.title || item.description || item.case_id), h('div', {className: 'muted'}, item.case_id || item.id)),
            h('td', null, h(C.StatusBadge, {status: item.priority || 'P3'})),
            h('td', null, h(C.StatusBadge, {status: item.status || 'open'})),
            h('td', null, item.owner || 'Unassigned'),
            h('td', null, item.sla_status || item.sla || '-')
          )))
        )
      ),
      !cases.length && !live.loading ? h(C.EmptyState, {title: 'No cases', detail: 'No incident cases returned by the backend.'}) : null
    );
  }

  window.SparkPages = window.SparkPages || {};
  window.SparkPages.Cases = Cases;
})();

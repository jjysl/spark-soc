(function () {
  const h = React.createElement;

  function EvidencePanel({evidence}) {
    if (!evidence) return null;
    const rows = [
      ['Status', evidence.status],
      ['IP', evidence.ip],
      ['Object', evidence.object_name || evidence.fortigate?.object],
      ['Group', evidence.group_name],
      ['Policy', evidence.policy_name],
      ['Evidence ID', evidence.evidence_id],
      ['Reason', evidence.reason],
    ];
    return h('div', {className: 'response-evidence ok'},
      h('div', {className: 'response-title'}, 'FortiGate containment evidence'),
      h('div', {className: 'response-grid'},
        rows.map(row => h(React.Fragment, {key: row[0]},
          h('span', null, row[0]),
          h('strong', null, row[1] || '--')
        ))
      )
    );
  }

  window.SparkIncident = window.SparkIncident || {};
  window.SparkIncident.EvidencePanel = EvidencePanel;
})();

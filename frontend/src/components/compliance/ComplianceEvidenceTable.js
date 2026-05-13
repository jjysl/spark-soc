(function () {
  const h = React.createElement;

  function ComplianceEvidenceTable({rows}) {
    const items = rows && rows.length ? rows : [
      ['FortiGate containment', 'T1562 / response action', 'RS.MA', 'Art. 46', 'A.5.24 / A.8.16', 'FortiOS REST + action log', 'Evidence Collected'],
      ['Wazuh endpoint telemetry', 'Multiple', 'DE.CM', 'Art. 46', 'A.8.15', 'Wazuh Manager/Indexer', 'Partially Covered'],
      ['Shuffle SOAR dispatch', 'Response workflow', 'RS.AN', 'Art. 46', 'A.5.26', 'Shuffle API/webhook', 'Requires Review'],
    ];
    return h('div', {className: 'card compliance-evidence-table'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Evidence Coverage'),
          h('div', {className: 'cs'}, 'Control evidence mapping for auditor review')
        )
      ),
      h('table', {className: 'ftable'},
        h('thead', null, h('tr', null, ['Playbook', 'MITRE Technique', 'NIST CSF 2.0', 'LGPD', 'ISO 27001:2022', 'Evidence Source', 'Status'].map(col => h('th', {key: col}, col)))),
        h('tbody', null, items.map((row, index) => h('tr', {key: `${row[0]}-${index}`}, row.map(cell => h('td', {key: cell}, cell)))))
      ),
      h('div', {className: 'compliance-disclaimer'},
        'SPARK generates auditable technical evidence for security controls. This is not automatic certification. Evidence collected must be reviewed by a qualified auditor.'
      )
    );
  }

  window.SparkCompliance = window.SparkCompliance || {};
  window.SparkCompliance.ComplianceEvidenceTable = ComplianceEvidenceTable;
})();

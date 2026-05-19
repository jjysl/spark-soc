(function () {
  const {useEffect, useMemo, useState} = React;
  const h = React.createElement;
  const api = window.SparkApi || {};

  function fmtNum(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function bandClass(band) {
    return {critical: 'bcrit', high: 'bhigh', medium: 'bmed', low: 'blow'}[band] || 'binfo';
  }

  function fmtTime(value) {
    if (!value) return 'No scores yet';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return `${date.toLocaleString('pt-BR', {hour12: false, timeZone: 'America/Sao_Paulo'})} BRT`;
  }

  function Kpi({label, value, detail, tone}) {
    return h('div', {className: `kpi ${tone === 'alert' ? 'ka' : ''}`},
      h('div', {className: 'kl'}, label),
      h('div', {className: 'kv'}, value),
      h('div', {className: 'kd'}, detail)
    );
  }

  function ScoreRows({rows}) {
    const safeRows = Array.isArray(rows) ? rows : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Top Risk Scores'),
          h('div', {className: 'cs'}, 'Explainable deterministic prioritization')
        ),
        h('span', {className: 'badge binfo'}, 'Analyst approval required')
      ),
      safeRows.length ? h('div', {className: 'table-scroll'},
        h('table', {className: 'ftable'},
          h('thead', null, h('tr', null,
            ['Incident', 'Score', 'Band', 'FortiAnalyzer', 'Recommended Action', 'Model'].map(label => h('th', {key: label}, label))
          )),
          h('tbody', null, safeRows.map((row, idx) => h('tr', {key: `${row.event_id || row.id || idx}`},
            h('td', null,
              h('div', {className: 'mono'}, row.incident_id || row.event_id || '--'),
              h('div', {className: 'cs'}, fmtTime(row.created_at || row.timestamp))
            ),
            h('td', null, h('strong', null, fmtNum(row.risk_score))),
            h('td', null, h('span', {className: `badge ${bandClass(row.risk_band)}`}, row.risk_band || 'unknown')),
            h('td', null,
              h('span', {className: `badge ${row.features?.containment_verified ? 'blive' : row.features?.fortianalyzer_evidence_status === 'evidence_pending' ? 'bwarn' : 'binfo'}`},
                row.features?.containment_verified ? 'verified' : row.features?.fortianalyzer_evidence_status || 'not queried'
              ),
              h('div', {className: 'cs'}, `${fmtNum(row.features?.fortianalyzer_log_count)} logs / ${fmtNum(row.features?.fortianalyzer_policy_hits)} policy hits`)
            ),
            h('td', null, row.recommended_action || 'Review evidence before containment.'),
            h('td', null, h('span', {className: 'mono'}, row.model_type || 'deterministic_scoring_v1'))
          )))
        )
      ) : h('div', {className: 'cb'}, h('div', {className: 'aibox loading'}, h('strong', null, 'ML dataset: '), 'No persisted scores yet. Score a live candidate to start the dataset.'))
    );
  }

  function CandidateRows({rows, onScore, scoringId}) {
    const safeRows = Array.isArray(rows) ? rows : [];
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'Live Case Candidates'),
          h('div', {className: 'cs'}, 'Preview scores from current SPARK incident cases')
        ),
        h('span', {className: 'badge bwarn'}, 'Not auto-blocking')
      ),
      safeRows.length ? h('div', {className: 'compact-list'},
        safeRows.map((row, idx) => h('div', {className: 'compact-row', key: row.incident_id || row.event_id || idx},
          h('div', {className: 'compact-main'},
            h('div', {className: 'compact-title'}, row.rule_description || row.incident_id || 'Incident candidate'),
            h('div', {className: 'compact-meta'},
              h('span', {className: 'mono'}, row.source_ip || 'source unknown'),
              h('span', {className: `badge ${bandClass(row.risk_band)}`}, `${row.risk_score}/100 ${row.risk_band}`),
              h('span', {className: `badge ${row.features_used?.containment_verified ? 'blive' : 'binfo'}`}, row.features_used?.fortianalyzer_evidence_status || 'FA not queried'),
              h('span', null, row.model_type)
            )
          ),
          h('div', {className: 'row-actions'},
            h('button', {
              className: 'btn btnp',
              disabled: scoringId === (row.incident_id || row.event_id || idx),
              onClick: () => onScore(row),
            }, scoringId === (row.incident_id || row.event_id || idx) ? 'Scoring...' : 'Persist Score')
          )
        ))
      ) : h('div', {className: 'cb'}, h('div', {className: 'cs'}, 'No active incident cases available from Wazuh/SPARK yet.'))
    );
  }

  function Distribution({data, repeated}) {
    const bands = ['critical', 'high', 'medium', 'low'];
    return h('div', {className: 'g11'},
      h('div', {className: 'card'},
        h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Score Distribution'), h('div', {className: 'cs'}, 'Persisted ML scores by band'))),
        h('div', {className: 'cb'},
          bands.map(band => {
            const value = Number(data?.[band] || 0);
            const width = Math.min(100, value * 20);
            return h('div', {className: 'rseg', key: band},
              h('div', {className: 'rsname'}, band),
              h('div', {className: 'rsbar'}, h('div', {className: 'rsfill', style: {width: `${width}%`, background: band === 'critical' || band === 'high' ? 'var(--red)' : band === 'medium' ? '#f59e0b' : '#10b981'}})),
              h('div', {className: 'rsval'}, value)
            );
          })
        )
      ),
      h('div', {className: 'card'},
        h('div', {className: 'ch'}, h('div', null, h('div', {className: 'ct'}, 'Repeated Sources'), h('div', {className: 'cs'}, 'Dataset signals for future model training'))),
        h('div', {className: 'compact-list'},
          (repeated || []).length ? repeated.map(item => h('div', {className: 'compact-row', key: item.source_ip},
            h('div', {className: 'compact-main'},
              h('div', {className: 'compact-title mono'}, item.source_ip),
              h('div', {className: 'compact-meta'}, `${fmtNum(item.count)} events - max risk ${fmtNum(item.max_risk)}`)
            )
          )) : h('div', {className: 'cb'}, h('div', {className: 'cs'}, 'Repeated source features will appear after multiple scored events.'))
        )
      )
    );
  }

  function FortiAnalyzerEvidence({distribution, verified}) {
    const rows = Object.entries(distribution || {});
    return h('div', {className: 'card'},
      h('div', {className: 'ch'},
        h('div', null,
          h('div', {className: 'ct'}, 'FortiAnalyzer Evidence Layer'),
          h('div', {className: 'cs'}, 'Runtime validation signals used by ML scoring')
        ),
        h('span', {className: `badge ${verified ? 'blive' : 'binfo'}`}, `${fmtNum(verified)} verified`)
      ),
      h('div', {className: 'cb'},
        rows.length ? rows.map(([status, count]) => {
          const width = Math.min(100, Number(count || 0) * 20);
          const color = status === 'evidence_collected' ? '#10b981' : status === 'evidence_pending' ? '#f59e0b' : 'var(--blue)';
          return h('div', {className: 'rseg', key: status},
            h('div', {className: 'rsname'}, status || 'unknown'),
            h('div', {className: 'rsbar'}, h('div', {className: 'rsfill', style: {width: `${width}%`, background: color}})),
            h('div', {className: 'rsval'}, fmtNum(count))
          );
        }) : h('div', {className: 'cs'}, 'No FortiAnalyzer evidence has been attached to ML events yet.')
      )
    );
  }

  function MLRiskInsightsApp() {
    const [payload, setPayload] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');
    const [scoringId, setScoringId] = useState('');

    async function load() {
      setLoading(true);
      try {
        const data = await api.ml.getInsights(30);
        setPayload(data);
        setError('');
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    async function persistCandidate(row) {
      const id = row.incident_id || row.event_id || 'candidate';
      setScoringId(id);
      try {
        await api.ml.scoreIncident({incident: row, include_fortianalyzer: true});
        setMessage(`Score persisted for ${id}.`);
        await load();
      } catch (err) {
        setMessage(`Score unavailable: ${err.message}`);
      } finally {
        setScoringId('');
      }
    }

    useEffect(() => {
      load();
      const timer = setInterval(load, 30000);
      return () => clearInterval(timer);
    }, []);

    const status = payload?.status || {};
    const counts = status.dataset_counts || {};
    const highCount = useMemo(() => (payload?.top_risks || []).filter(row => Number(row.risk_score || 0) >= 70).length, [payload]);

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'ML Risk Insights'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), loading ? 'Updating deterministic scoring telemetry...' : 'Deterministic analytics - dataset ready for future supervised ML')
        ),
        h('div', {className: 'ha'},
          h('a', {className: 'btn', href: api.ml.exportJsonUrl}, 'Export JSON'),
          h('a', {className: 'btn', href: api.ml.exportCsvUrl}, 'Export CSV'),
          h('button', {className: 'btn btnp', onClick: load}, 'Refresh')
        )
      ),
      h('div', {className: `aibox ${error ? 'loading' : ''}`},
        h('strong', null, 'ML operating mode: '),
        error ? `ML insights unavailable. ${error}` : (message || status.model_note || 'Deterministic scoring module is enabled.')
      ),
      h('div', {className: 'krow'},
        h(Kpi, {label: 'ML Events', value: fmtNum(counts.ml_events), detail: 'Rows available for training export'}),
        h(Kpi, {label: 'ML Scores', value: fmtNum(counts.ml_scores), detail: 'Persisted deterministic scores'}),
        h(Kpi, {label: 'High Risk', value: fmtNum(highCount), detail: 'Current top-risk queue', tone: highCount ? 'alert' : ''}),
        h(Kpi, {label: 'FA Verified', value: fmtNum(payload?.containment_verified_count), detail: 'FortiAnalyzer-confirmed evidence'}),
        h(Kpi, {label: 'Last Score', value: status.last_score_timestamp ? 'Ready' : 'None', detail: fmtTime(status.last_score_timestamp)})
      ),
      h('div', {className: 'g21', style: {alignItems: 'start'}},
        h(ScoreRows, {rows: payload?.top_risks || []}),
        h(CandidateRows, {rows: payload?.live_candidates || [], onScore: persistCandidate, scoringId})
      ),
      h(Distribution, {data: payload?.score_distribution || {}, repeated: payload?.repeated_source_ips || []}),
      h(FortiAnalyzerEvidence, {distribution: payload?.fortianalyzer_distribution || {}, verified: payload?.containment_verified_count || 0})
    );
  }

  const root = document.getElementById('ml-root');
  if (root) ReactDOM.createRoot(root).render(h(MLRiskInsightsApp));
})();

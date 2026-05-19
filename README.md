# SPARK SOC

SPARK SOC is a cloud NG-SOC / MDR workspace for detection, analyst-approved response, SOAR orchestration and auditable evidence.

The operational model is:

```text
Detect -> Analyze -> Recommend -> Orchestrate -> Contain -> Document
```

SPARK is not positioned as a fully autonomous SOC. It assists analysts with telemetry, AI briefing, deterministic risk scoring and response automation, but containment actions require analyst approval.

## Current Capabilities

- Cloud dashboard for SOC operations and executive visibility.
- Wazuh Manager / Indexer integration for endpoint telemetry and alert triage.
- FortiGate API containment with source IP block/unblock.
- FortiGate destination / egress block/unblock for malicious destination IOCs.
- Reusable FortiGate groups and policies:
  - `SPARK_BLOCKLIST`
  - `SPARK_EGRESS_BLOCKLIST`
  - `SPARK_AUTO_BLOCK`
  - `SPARK_EGRESS_AUTO_BLOCK`
- Shuffle SOAR dispatch with `execution_id` tracking.
- SOAR analyst notification workflow.
- IOC enrichment with local evidence and direction recommendation.
- FortiAnalyzer JSON-RPC evidence layer.
- Groq AI Incident Briefing with deterministic fallback.
- Deterministic ML Risk scoring, not trained autonomous ML.
- Evidence Pack export with SHA256 integrity hash.
- SPARK Trace and Containment Confidence for response storytelling.

## Console Areas

### Executive Overview

Operational summary for the MDR workspace:

- SOC health and active incident indicators.
- Integration health for Wazuh, FortiGate, FortiAnalyzer, Shuffle, Groq and ML Risk.
- Incident Priority Queue.
- SOC Shift Summary.
- FortiAnalyzer connector/evidence readiness.

### Threat Detection

Wazuh-focused detection and triage:

- Alert candidates with rule ID, severity, source IP and target asset.
- MITRE technique when available.
- Filters and evidence context for analyst review.

### Incident Response

Main analyst workspace:

- Incident candidates and case lifecycle actions.
- AI Incident Briefing.
- Recommended Response with deterministic risk scoring.
- IOC Enrichment.
- Source Block and Destination Block actions.
- Execute Recommended Response with analyst approval.
- Dispatch SOAR Evidence.
- Notify Analyst.
- SPARK Trace timeline.
- Evidence Pack with FortiGate, Shuffle, FortiAnalyzer, ML Risk and SHA256.

### Network / Endpoint

Infrastructure and containment visibility:

- Wazuh agents and endpoint state.
- FortiGate, FortiAnalyzer, Shuffle and Indexer status.
- Source blocklist and destination blocklist.
- Containment evidence and unblock actions.

### Compliance / Risk

Evidence-oriented compliance support:

```text
NIST CSF Function | SPARK Control | Evidence Source | Evidence ID | Status | Notes
```

SPARK generates auditable technical evidence for security controls. It does not provide automatic certification. Evidence must be reviewed by a qualified auditor.

### ML Risk Insights

Deterministic risk scoring dashboard:

- Engine: `deterministic_scoring_v1`.
- Score: `0-100`.
- Bands: low, medium, high, critical.
- Explanation, features used and missing fields.
- FortiAnalyzer-aware confidence when real evidence exists.
- JSON/CSV export for review.

## Practical Response Actions

### Source IP Block

Blocks traffic coming from a malicious source IP.

```bash
curl -X POST http://127.0.0.1:5000/spark/fortigate/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.124","reason":"Analyst approved containment","source":"manual","severity":"high"}'
```

Unblock:

```bash
curl -X POST http://127.0.0.1:5000/spark/fortigate/unblock-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.124","reason":"Containment cleanup approved by analyst"}'
```

List:

```bash
curl http://127.0.0.1:5000/spark/fortigate/blocklist
```

### Destination / Egress IP Block

Prevents protected endpoints from accessing a malicious destination IP.

```bash
curl -X POST http://127.0.0.1:5000/spark/fortigate/block-destination-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.4.4","reason":"Analyst approved egress containment","source":"manual","severity":"high"}'
```

Unblock:

```bash
curl -X POST http://127.0.0.1:5000/spark/fortigate/unblock-destination-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.4.4","reason":"Egress containment cleanup approved by analyst"}'
```

List:

```bash
curl http://127.0.0.1:5000/spark/fortigate/destination-blocklist
```

Policy applied on FortiGate. Runtime enforcement depends on traffic passing through the policy and logs being available in FortiAnalyzer.

## SOAR Endpoints

```bash
curl http://127.0.0.1:5000/spark/soar/status
```

Dispatch evidence to Shuffle:

```bash
curl -X POST http://127.0.0.1:5000/spark/soar/dispatch-evidence \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-001","title":"Suspicious IOC","severity":"high","source_ip":"10.10.1.20","evidence_id":"EVD-001"}'
```

Notify analyst:

```bash
curl -X POST http://127.0.0.1:5000/spark/soar/notify-analyst \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-001","title":"Suspicious IOC","severity":"high","recommended_action":"destination_block","destination_ip":"8.8.4.4","evidence_id":"EVD-001"}'
```

Enrich IOC:

```bash
curl -X POST http://127.0.0.1:5000/spark/soar/enrich-ioc \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.4.4","severity":"high","alert_count":22,"context":"malicious destination"}'
```

IOC enrichment is local and evidence-based. It does not fake AbuseIPDB, VirusTotal or external reputation results.

## Response Recommendation

Recommendation endpoint:

```bash
curl -X POST http://127.0.0.1:5000/spark/response/recommendation \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-001","title":"SSH brute force","severity":"high","source_ip":"10.255.255.200","mitre":"T1110 - Brute Force","alert_count":47}'
```

Execute recommended response:

```bash
curl -X POST http://127.0.0.1:5000/spark/response/execute \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-001","recommended_action":"block","source_ip":"10.255.255.200","analyst_reason":"Confirmed malicious brute force source","approval_confirmed":true}'
```

`/spark/response/execute` can chain FortiGate action, FortiAnalyzer lookup, deterministic ML score and Shuffle evidence dispatch. It remains analyst-approved automation.

## FortiAnalyzer

SPARK uses FortiAnalyzer JSON-RPC with bearer token authentication.

Endpoints:

```bash
curl http://127.0.0.1:5000/spark/fortianalyzer/status
curl "http://127.0.0.1:5000/spark/fortianalyzer/evidence?ip=10.255.255.210"
```

If no logs are found, SPARK returns `no_results` or `evidence_pending`. It does not claim confirmed traffic evidence unless FortiAnalyzer returns real data.

## AI Incident Briefing

Supported provider configuration:

```env
AI_PROVIDER=groq
GROQ_API_KEY=
GROQ_MODEL=llama-3.1-8b-instant
```

Status:

```bash
curl http://127.0.0.1:5000/spark/ai/status
```

Briefing:

```bash
curl -X POST http://127.0.0.1:5000/spark/ai/incident-briefing \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-001","title":"SSH brute force detected","severity":"high","source_ip":"10.255.255.200","target":"cloud-agent","mitre":"T1110 - Brute Force","evidence":{"wazuh_rule":"5763","alert_count":47}}'
```

If Groq is unavailable, SPARK keeps a deterministic fallback so the workflow remains usable.

## ML Risk

Endpoints:

```bash
curl http://127.0.0.1:5000/spark/ml/status
curl -X POST http://127.0.0.1:5000/spark/ml/score-incident -H "Content-Type: application/json" -d '{"incident_id":"ML-001","severity":"high","source_ip":"10.255.255.220","alert_count":47}'
curl http://127.0.0.1:5000/spark/ml/insights
curl "http://127.0.0.1:5000/spark/ml/export?format=json"
curl "http://127.0.0.1:5000/spark/ml/export?format=csv"
```

The current ML layer is deterministic scoring for prioritization and evidence quality. It is not a trained model and it must not trigger autonomous blocking.

## Runtime Configuration

Real credentials belong only in the runtime environment, never in Git.

Typical cloud variables:

```env
SPARK_PROFILE=azure-cloud
WAZUH_BASE=
INDEXER_BASE=
SHUFFLE_BASE_URL=
SHUFFLE_BACKEND_URL=
SHUFFLE_API_KEY=
SHUFFLE_INCIDENT_WEBHOOK_URL=
SHUFFLE_NOTIFICATION_WEBHOOK_URL=
FORTIGATE_BASE_URL=
FORTIGATE_API_KEY=
FORTIANALYZER_BASE_URL=
FORTIANALYZER_API_KEY=
AI_PROVIDER=groq
GROQ_API_KEY=
GROQ_MODEL=llama-3.1-8b-instant
SPARK_DASHBOARD_URL=
```

`config.py` is local runtime configuration and is ignored by Git. Use `config.example.py` and `.env.example` as templates.

## Cloud Deployment Notes

Current production-style deployment runs SPARK as a systemd service on the cloud SOC VM:

```bash
sudo systemctl restart spark-soc
sudo systemctl status spark-soc --no-pager
sudo journalctl -u spark-soc -n 100 --no-pager
```

Do not edit source code permanently under `/opt/spark-soc`. The Git repository is the source of truth.

## Local Development

Start Flask locally:

```powershell
python backend/app.py
```

Open:

```text
http://localhost:5000
```

Useful validation:

```powershell
python -m py_compile backend\fortigate.py backend\shuffle.py backend\fortianalyzer.py backend\ml_scoring.py backend\response_engine.py backend\spark_api.py backend\app.py
node --check frontend\src\pages\IncidentResponse.js
```

## Frontend

The operational console is served by Flask and uses React modules under `frontend/src`.

```text
frontend/src/api/          API client and domain modules
frontend/src/hooks/        Live data, async action and toast hooks
frontend/src/components/   Reusable UI and SOC components
frontend/src/pages/        Console pages
frontend/src/styles/       Product design tokens and dashboard styles
frontend/landingpage.html  Product landing page for business/academic presentation
```

New frontend code should use the centralized API modules and reusable components. Avoid adding inline fetch calls or duplicate state logic.

## Security

- Never commit `.env`, real API keys, bearer tokens or private runtime config.
- Do not print tokens in logs or README examples.
- Keep FortiGate, FortiAnalyzer, Shuffle and Groq credentials only in runtime environment files.
- Review `git diff` before every commit touching configuration or deployment.

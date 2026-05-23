# SPARK SOC - Implementation and Reproduction Guide

This guide explains how to reproduce the SPARK SOC environment at a practical level and how to test the main workflows.

The production-style deployment used by the team runs in Azure cloud, with SPARK SOC deployed as a Flask/systemd service and integrated with Wazuh, FortiGate, FortiAnalyzer, Shuffle and Groq.

## Repository

Public repository:

```text
https://github.com/jjysl/spark-soc
```

Clone:

```bash
git clone https://github.com/jjysl/spark-soc.git
cd spark-soc
```

## Runtime Requirements

Minimum runtime:

- Python 3.10+
- Flask dependencies from the project environment
- Network access from SPARK backend to Wazuh, FortiGate, FortiAnalyzer and Shuffle
- Runtime `.env` or `config.py` with credentials

Do not commit runtime credentials.

## Environment Variables

Use `.env.example` and `config.example.py` as templates.

Typical cloud configuration:

```env
SPARK_PROFILE=azure-cloud

WAZUH_BASE=
WAZUH_MANAGER_IP=
WAZUH_AGENT_IP=
INDEXER_BASE=

SHUFFLE_BASE_URL=
SHUFFLE_BACKEND_URL=
SHUFFLE_API_KEY=
SHUFFLE_INCIDENT_WEBHOOK_URL=
SHUFFLE_NOTIFICATION_WEBHOOK_URL=

FORTIGATE_BASE_URL=
FORTIGATE_API_KEY=
FORTIGATE_BLOCK_SRCINTF=any
FORTIGATE_BLOCK_DSTINTF=any
FORTIGATE_DESTINATION_BLOCK_SRCADDR=all
FORTIGATE_DESTINATION_BLOCK_SRCINTF=any
FORTIGATE_DESTINATION_BLOCK_DSTINTF=any

FORTIANALYZER_BASE_URL=
FORTIANALYZER_API_KEY=

AI_PROVIDER=groq
GROQ_API_KEY=
GROQ_MODEL=llama-3.1-8b-instant

SPARK_DASHBOARD_URL=
```

## Local Development

Start the backend locally:

```powershell
python backend/app.py
```

Open:

```text
http://localhost:5000
```

Without real runtime credentials, integrations return safe statuses such as `not_configured`, `connector_ready`, `no_results` or `evidence_pending`.

## Cloud Service Deployment

The cloud deployment runs SPARK under systemd:

```bash
sudo systemctl restart spark-soc
sudo systemctl status spark-soc --no-pager
sudo journalctl -u spark-soc -n 100 --no-pager
```

Expected app path:

```text
/opt/spark-soc
```

Do not edit source code directly in `/opt/spark-soc` unless it is a temporary debugging step. The Git repository is the source of truth.

## Validation Commands

Compile Python files:

```bash
python -m py_compile backend/fortigate.py backend/shuffle.py backend/fortianalyzer.py backend/ml_scoring.py backend/response_engine.py backend/spark_api.py backend/app.py
```

Check frontend JavaScript:

```bash
node --check frontend/src/pages/IncidentResponse.js
node --check frontend/src/api/fortigate.js
```

Check service health:

```bash
curl -s http://127.0.0.1:5000/spark/fortigate-status
curl -s http://127.0.0.1:5000/spark/fortianalyzer/status
curl -s http://127.0.0.1:5000/spark/ai/status
curl -s http://127.0.0.1:5000/spark/ml/status
curl -s http://127.0.0.1:5000/spark/soar/status
curl -s http://127.0.0.1:5000/spark/stats
```

## Test Workflow: IOC Enrichment

```bash
curl -s -X POST http://127.0.0.1:5000/spark/soar/enrich-ioc \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.4.4","severity":"high","alert_count":22,"context":"malicious destination"}'
```

Expected result:

- `ip_type`
- `direction_recommendation`
- `recommended_action`
- local evidence counters

No external reputation data is faked.

## Test Workflow: Source IP Block

```bash
curl -s -X POST http://127.0.0.1:5000/spark/fortigate/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.124","reason":"Analyst approved source containment","source":"manual","severity":"high"}'
```

Expected FortiGate objects:

```text
SPARK_BLOCK_<IP>
SPARK_BLOCKLIST
SPARK_AUTO_BLOCK
```

Unblock:

```bash
curl -s -X POST http://127.0.0.1:5000/spark/fortigate/unblock-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.124","reason":"Source containment cleanup approved by analyst"}'
```

## Test Workflow: Destination / Egress IP Block

```bash
curl -s -X POST http://127.0.0.1:5000/spark/fortigate/block-destination-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.4.4","reason":"Analyst approved destination containment","source":"manual","severity":"high"}'
```

Expected FortiGate objects:

```text
SPARK_DST_BLOCK_<IP>
SPARK_EGRESS_BLOCKLIST
SPARK_EGRESS_AUTO_BLOCK
```

Unblock:

```bash
curl -s -X POST http://127.0.0.1:5000/spark/fortigate/unblock-destination-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.4.4","reason":"Destination containment cleanup approved by analyst"}'
```

Runtime note:

```text
Policy applied on FortiGate. Runtime enforcement depends on traffic passing through the policy and logs being available in FortiAnalyzer.
```

## Test Workflow: SOAR Dispatch

Dispatch evidence:

```bash
curl -s -X POST http://127.0.0.1:5000/spark/soar/dispatch-evidence \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-001","title":"Suspicious IOC","severity":"high","source_ip":"10.10.1.20","destination_ip":"8.8.4.4","evidence_id":"EVD-001"}'
```

Notify analyst:

```bash
curl -s -X POST http://127.0.0.1:5000/spark/soar/notify-analyst \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-001","title":"Suspicious IOC","severity":"high","recommended_action":"destination_block","destination_ip":"8.8.4.4","evidence_id":"EVD-001"}'
```

When configured, Shuffle returns `execution_id`.

## Test Workflow: AI Briefing

```bash
curl -s -X POST http://127.0.0.1:5000/spark/ai/incident-briefing \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-001","title":"SSH brute force detected","severity":"high","source_ip":"10.255.255.200","target":"cloud-agent","mitre":"T1110 - Brute Force","evidence":{"wazuh_rule":"5763","alert_count":47}}'
```

Expected response:

- provider and model
- `source=ai-live` when Groq is configured
- `source=fallback` when AI provider is unavailable
- structured briefing fields

## Test Workflow: ML Risk

```bash
curl -s -X POST http://127.0.0.1:5000/spark/ml/score-incident \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"ML-001","title":"SSH brute force","severity":"high","source_ip":"10.255.255.220","mitre":"T1110 - Brute Force","wazuh_rule":"5763","alert_count":47}'
```

Export:

```bash
curl -s "http://127.0.0.1:5000/spark/ml/export?format=json"
curl -s "http://127.0.0.1:5000/spark/ml/export?format=csv"
```

## Demonstration Script

Recommended 10-minute flow for evaluators:

1. Open the SPARK dashboard.
2. Show Executive Overview and integration status.
3. Open Incident Response.
4. Enrich IOC.
5. Generate ML Risk recommendation.
6. Generate AI Incident Briefing.
7. Approve response as analyst.
8. Execute Source Block or Destination Block.
9. Show Shuffle `execution_id`.
10. Show FortiAnalyzer evidence status.
11. Export Evidence Pack and SHA256 hash.

## Troubleshooting

If an integration is unavailable, SPARK should return product-safe statuses:

- `not_configured`
- `connector_ready`
- `auth_required`
- `auth_failed`
- `no_results`
- `evidence_pending`
- `timeout`

It should not return fake evidence and should not expose API keys.

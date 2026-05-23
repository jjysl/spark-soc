# SPARK SOC - Technical Architecture

## Objective

SPARK SOC is a cloud NG-SOC / MDR workspace that connects telemetry, SOAR orchestration, firewall containment, AI-assisted briefing and evidence generation into one analyst workflow.

The platform is designed for small and mid-sized organizations that need SOC capability without building a full SOC stack from scratch.

## High-Level Flow

```text
Endpoint / Server
  -> Wazuh Agent
  -> Wazuh Manager
  -> Wazuh Indexer
  -> SPARK SOC Backend
  -> SPARK Dashboard

SPARK SOC Backend
  -> FortiGate API for source/destination containment
  -> FortiAnalyzer JSON-RPC for evidence lookup
  -> Shuffle SOAR webhooks for orchestration and analyst notification
  -> Groq API for AI Incident Briefing
  -> SQLite evidence store for actions, cases, ML scores and audit records
```

## Architecture Diagram

```text
                         +-----------------------------+
                         |        Analyst Browser      |
                         |  SPARK Dashboard / Console  |
                         +--------------+--------------+
                                        |
                                        | HTTP(S)
                                        v
+-------------------+        +-------------------------+        +----------------------+
| Wazuh Agent       |        | SPARK SOC Cloud VM      |        | Groq AI Provider     |
| Endpoint telemetry+------->| Flask backend + frontend+------->| Incident Briefing    |
+-------------------+        | SQLite evidence store   |        +----------------------+
                             +------------+------------+
                                          |
              +---------------------------+---------------------------+
              |                           |                           |
              v                           v                           v
+-------------------------+   +-------------------------+   +-------------------------+
| Wazuh Manager / Indexer |   | FortiGate API           |   | Shuffle SOAR            |
| Alerts and agent state  |   | Source/Destination deny |   | Dispatch + notification |
+-------------------------+   +------------+------------+   +-------------------------+
                                           |
                                           v
                              +-------------------------+
                              | FortiAnalyzer JSON-RPC  |
                              | Evidence lookup         |
                              +-------------------------+
```

## Main Components

### SPARK SOC Backend

Technology:

- Python
- Flask
- SQLite
- Requests-based API clients

Responsibilities:

- Serves dashboard and product landing page.
- Exposes `/spark/*` API endpoints.
- Normalizes integration health.
- Executes analyst-approved FortiGate actions.
- Dispatches evidence payloads to Shuffle.
- Queries FortiAnalyzer for evidence.
- Generates deterministic ML Risk scores.
- Calls Groq for AI Incident Briefing, with deterministic fallback.
- Stores action logs and evidence records.

### SPARK Dashboard

Technology:

- HTML/CSS/JS served by Flask.
- React modules under `frontend/src`.

Main pages:

- Executive Overview
- Threat Detection
- Incident Response
- Network / Endpoint
- Compliance / Risk
- Cases & Response
- ML Risk Insights

### Wazuh

Role:

- Endpoint telemetry.
- Alert generation.
- Agent state.
- Rule metadata.

SPARK uses Wazuh Manager and Indexer data to populate incident candidates and operational status.

### FortiGate

Role:

- API-driven containment.
- Source IP block for inbound malicious sources.
- Destination IP block for egress/C2/phishing destination IOCs.

Source block:

```text
Address object: SPARK_BLOCK_<IP>
Address group:  SPARK_BLOCKLIST
Policy:         SPARK_AUTO_BLOCK
Direction:      srcaddr=SPARK_BLOCKLIST -> dstaddr=all
Action:         deny
```

Destination block:

```text
Address object: SPARK_DST_BLOCK_<IP>
Address group:  SPARK_EGRESS_BLOCKLIST
Policy:         SPARK_EGRESS_AUTO_BLOCK
Direction:      srcaddr=all -> dstaddr=SPARK_EGRESS_BLOCKLIST
Action:         deny
```

Runtime note:

```text
Policy applied on FortiGate. Runtime enforcement depends on traffic passing through the policy and logs being available in FortiAnalyzer.
```

### FortiAnalyzer

Role:

- Fortinet log and evidence layer.
- Queried through JSON-RPC with bearer token authentication.
- Adds evidence status, log count and references when logs exist.

SPARK does not invent FortiAnalyzer evidence. If no logs are returned, the response remains `no_results` or `evidence_pending`.

### Shuffle SOAR

Role:

- SOAR orchestration.
- Receives SPARK evidence payloads.
- Returns `execution_id` when dispatch succeeds.
- Supports analyst notification through a dedicated notification webhook or fallback incident webhook.

### Groq AI

Role:

- AI Incident Briefing.
- Structured incident summary for analysts.
- Fallback remains deterministic when the provider is unavailable.

AI does not execute response actions.

### Deterministic ML Risk

Engine:

```text
deterministic_scoring_v1
```

Purpose:

- Prioritize incidents.
- Explain the risk score.
- Show missing fields.
- Increase confidence when FortiAnalyzer evidence exists.

This is not trained autonomous ML and must not trigger blocking by itself.

## Critical Endpoints

### Integration Status

```text
GET /spark/fortigate-status
GET /spark/fortianalyzer/status
GET /spark/ai/status
GET /spark/ml/status
GET /spark/soar/status
GET /spark/stats
```

### FortiGate Source Block

```text
POST /spark/fortigate/block-ip
POST /spark/fortigate/unblock-ip
GET  /spark/fortigate/blocklist
```

### FortiGate Destination Block

```text
POST /spark/fortigate/block-destination-ip
POST /spark/fortigate/unblock-destination-ip
GET  /spark/fortigate/destination-blocklist
```

### SOAR

```text
POST /spark/soar/dispatch-evidence
POST /spark/soar/notify-analyst
POST /spark/soar/enrich-ioc
```

### Response Engine

```text
POST /spark/response/recommendation
POST /spark/response/execute
```

### AI and ML

```text
POST /spark/ai/incident-briefing
POST /spark/ml/score-incident
GET  /spark/ml/insights
GET  /spark/ml/export?format=json
GET  /spark/ml/export?format=csv
```

## Security and Evidence Principles

- No secrets are committed to Git.
- Real credentials live only in runtime `.env` or systemd environment files.
- FortiGate actions require analyst approval.
- Evidence Pack records the response chain and SHA256 hash.
- Compliance views provide technical evidence, not automatic certification.
- FortiAnalyzer evidence is only confirmed when logs are returned by the connector.

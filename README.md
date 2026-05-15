# SPARK SOC

SPARK SOC is an NG-SOC / MDR command center for organizations that need managed detection, incident response, containment evidence and executive visibility without building a full SOC from scratch.

The platform connects security telemetry, SOAR automation and firewall containment into one operational workflow:

```text
Detect -> Decide -> Respond -> Contain -> Document
```

## What SPARK SOC Delivers

- Unified SOC dashboard for Wazuh, FortiGate, Shuffle SOAR and endpoint telemetry.
- Real FortiGate containment through address objects, blocklist group updates and policy enforcement.
- Incident Response workspace with AI Incident Briefing, SPARK Trace, Evidence Pack and Containment Confidence.
- Executive Overview for service health, active incidents, integration status and response activity.
- Compliance / Risk evidence view focused on auditable technical evidence, not automatic certification claims.
- Product onboarding and plans page for MDR / NG-SOC as a Service positioning.

## Console Areas

### Executive Overview

The executive screen summarizes the MDR workspace posture:

- SOC health and active incident indicators.
- Integration health for Wazuh Manager, Wazuh Indexer, FortiGate, Shuffle and Agent.
- Alert volume, workqueue, open cases and response activity.
- Live operational signals for the current workspace.

### Threat Detection

Threat Detection focuses on Wazuh telemetry and analyst triage:

- Wazuh alerts with rule ID, severity, source IP and target asset.
- MITRE technique when available from telemetry.
- Filters and visual summaries for analyst review.
- Candidate incidents that can move into response workflows.

### Network / Endpoint

Network / Endpoint gives the analyst the infrastructure and containment view:

- Wazuh agents and endpoint status.
- FortiGate, Shuffle and Indexer operational status.
- FortiGate SPARK blocklist entries.
- Correlation between blocked IPs and recorded evidence.
- Unblock workflow for containment cleanup.

### Incident Response

Incident Response is the main analyst workspace:

- Incident candidate queue and case lifecycle actions.
- Block IP / Unblock IP through FortiGate.
- SPARK Trace: Detect, Analyze, Respond, Contain and Document.
- Evidence Pack with executive summary, technical evidence, response actions and compliance evidence.
- Containment Confidence based on FortiGate object, blocklist, policy and evidence confirmation.
- AI Incident Briefing with deterministic fallback when no AI provider is configured.

### Compliance / Risk

Compliance / Risk presents evidence coverage without overstating certification status:

```text
Playbook | MITRE Technique | NIST CSF 2.0 | LGPD | ISO 27001:2022 | Evidence Source | Status
```

SPARK generates auditable technical evidence for security controls. This is not automatic certification. Evidence collected must be reviewed by a qualified auditor.

### Cases & Response

Cases & Response manages operational follow-through:

- Case list and lifecycle status.
- Severity, owner, response history and next action.
- Evidence and containment linkage.
- Optional Jira/service request integration when configured.

## Core Integrations

| Integration | Purpose |
| --- | --- |
| Wazuh Manager | Agent inventory and operational status |
| Wazuh Indexer | Alert search, candidate detection and dashboards |
| FortiGate / Fortinet | Network containment, blocklist and policy evidence |
| Shuffle SOAR | Automation and playbook execution signals |
| Jira | Optional case/service request handoff |
| AI Provider | Incident briefing and operational summary |

## FortiGate Containment

SPARK SOC supports real containment using FortiGate API calls.

Block IP:

```bash
curl -X POST http://192.168.50.20:5000/spark/fortigate/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.124","reason":"Analyst containment action","source":"manual","severity":"high"}'
```

List blocklist:

```bash
curl http://192.168.50.20:5000/spark/fortigate/blocklist
```

Unblock IP:

```bash
curl -X POST http://192.168.50.20:5000/spark/fortigate/unblock-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.124","reason":"Containment cleanup approved by analyst"}'
```

Default FortiGate containment objects:

```text
FORTIGATE_BLOCKLIST_GROUP=SPARK_BLOCKLIST
FORTIGATE_BLOCKLIST_POLICY=SPARK_AUTO_BLOCK
FORTIGATE_BLOCK_SRCINTF=any
FORTIGATE_BLOCK_DSTINTF=any
```

The FortiGate API key must be configured only in the real runtime environment. Do not commit API keys to Git, README files, examples or logs.

## AI Incident Briefing

The Incident Response page can generate an AI Incident Briefing from the current incident or the latest containment action.

Supported providers:

```env
AI_PROVIDER=none
AI_MODEL=
GEMINI_API_KEY=
GROQ_API_KEY=
GROQ_MODEL=llama-3.1-8b-instant
DEEPSEEK_API_KEY=
```

Use `AI_PROVIDER=groq` and `GROQ_API_KEY` in the real environment to enable Groq-backed briefings. When no provider is configured, SPARK keeps a deterministic fallback active so the response workflow remains available.

The briefing uses operational context such as:

- Incident title, severity, source IP and target asset.
- MITRE technique and Wazuh evidence when available.
- FortiGate object, blocklist group and policy.
- Evidence ID, response action log and containment confidence.
- Recommended next steps for the analyst.

## Runtime Configuration

SPARK is configured through environment variables and local runtime files. Keep real credentials out of Git.

Recommended production-style variables:

```env
SPARK_PROFILE=vmware-lab
WAZUH_BASE=https://192.168.50.20:55000
WAZUH_MANAGER_IP=192.168.50.20
WAZUH_AGENT_IP=192.168.50.30
SHUFFLE_BASE_URL=http://192.168.50.20:3001
SHUFFLE_BACKEND_URL=http://192.168.50.20:5001
INDEXER_BASE=https://localhost:9200
FORTIGATE_BASE_URL=https://192.168.50.40
FORTIGATE_API_KEY=
AI_PROVIDER=none
GROQ_API_KEY=
```

`config.py` is local runtime configuration and is ignored by Git. Use `config.example.py` as the template when preparing a new environment.

## VMware Deployment

In the current deployment model, the source code is maintained on the Windows workstation and the SPARK backend runs as a systemd service on the Wazuh / Shuffle VM.

Environment:

```text
Windows browser:      192.168.50.1
Wazuh + SPARK:        192.168.50.20
Agent endpoint:       192.168.50.30
FortiGate:            192.168.50.40
Dashboard:            http://192.168.50.20:5000
Shuffle frontend:     http://192.168.50.20:3001
Shuffle backend/API:  http://192.168.50.20:5001
Wazuh API:            https://192.168.50.20:55000
Wazuh Indexer:        https://localhost:9200
```

Deploy from the project root on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-vmware.ps1
```

The deploy script packages the project, sends it to the VM, preserves runtime-only files and restarts the `spark-soc` service.

Preserved on the VM:

- `/opt/spark-soc/.env`
- `/opt/spark-soc/config.py`
- `/opt/spark-soc/vendor`

Do not edit application source directly under `/opt/spark-soc`. The Windows repository is the source of truth.

Service diagnostics on the VM:

```bash
sudo systemctl status spark-soc --no-pager
sudo journalctl -u spark-soc -n 100 --no-pager
```

## Local Development

Start Flask locally:

```powershell
python backend/app.py
```

When running the backend on Windows and the Wazuh Indexer is only reachable inside the VM, start the local SSH tunnel:

```powershell
.\scripts\start-indexer-tunnel.ps1
```

For the local tunnel profile, set:

```env
INDEXER_BASE=https://localhost:19200
```

For the VMware runtime profile, set:

```env
INDEXER_BASE=https://localhost:9200
```

Stop the tunnel:

```powershell
.\scripts\stop-indexer-tunnel.ps1
```

## Frontend Architecture

The console is served by Flask and uses React modules under `frontend/src`.

```text
frontend/src/api/          Central API client and domain modules
frontend/src/hooks/        Live data, async action and toast hooks
frontend/src/components/   Reusable UI, layout, incident, integration and compliance components
frontend/src/pages/        Dashboard pages
frontend/src/styles/       Product design tokens and dashboard styles
```

All new frontend work should use:

- Centralized API calls through `frontend/src/api`.
- Reusable components for buttons, badges, cards, tables, modals, drawers and status states.
- Loading, success, error and empty states designed for SOC operations.
- BRT time display for analyst-facing timestamps.

## Security Notes

- Never commit `.env`, API keys, bearer tokens or private runtime config.
- Configure FortiGate and AI provider keys only in the real runtime environment.
- Keep `config.py` local and out of Git.
- Review `git diff` before every commit when touching configuration or deployment files.


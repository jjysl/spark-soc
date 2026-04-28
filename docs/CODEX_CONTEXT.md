# SPARK SOC Codex Context

Use this file when continuing development from another machine or a new Codex session.

Prompt to use:

```text
Read docs/CODEX_CONTEXT.md, inspect the current worktree, and continue from the listed next tasks. Do not rewrite Executive Overview unless explicitly requested. The next major task is Threat Detection real-data integration using the existing config contract.
```

## Project Goal

SPARK SOC is an NG-SOC as a Service dashboard for the FIAP/Fortinet Challenge 2025. It presents executive SOC visibility, threat detection, network and endpoint telemetry, incident response, compliance risk, AI-assisted triage, and an incident ticket Kanban.

The target style is professional Fortinet/SOCaaS: restrained, operational, English UI text, useful analyst data, and no obviously fake or hardcoded values in live views.

## Repository State

Main structure:

```text
backend/
  app.py          Flask app factory and static frontend serving
  auth.py         Local login, Microsoft Entra ID OAuth, Google OAuth
  spark_api.py    Main SPARK API routes and Executive Overview aggregator
  wazuh.py        Wazuh Indexer and Wazuh Manager API helpers
  fortigate.py    FortiGate Monitor API helpers
  shuffle.py      Shuffle health/API helpers
  tickets.py      SQLite-backed ticket APIs
  ai_proxy.py     Anthropic/Ollama proxy logic
frontend/
  dashboard.html
  login.html
  js/
  react/executive/ExecutiveOverview.js
scripts/
  start-spark.ps1
  start-indexer-tunnel.ps1
  stop-indexer-tunnel.ps1
  setup-wazuh-ssh-key.ps1
  open-ssh-key-setup.ps1
data/
  events.db       local runtime DB, ignored by Git
config.example.py
config.py         local secrets, ignored by Git
```

Git remote:

```text
origin https://github.com/jjysl/spark-soc.git
branch main
```

Recent important commits:

```text
4df86b0 refactor: split spark soc app structure
11febe0 fix: improve executive overview loading
c254ddc feat: enrich executive overview investigation
f63aaca fix: restore executive workqueue title
83e08da feat: add executive workqueue drilldown filters
76aa1fd feat: refine executive filtering and refresh
```

## Local Runtime Commands

Run everything from the repository root.

Start tunnel plus Flask:

```powershell
.\scripts\start-spark.ps1
```

Start only the Wazuh Indexer tunnel:

```powershell
.\scripts\start-indexer-tunnel.ps1
```

Stop the Wazuh Indexer tunnel:

```powershell
.\scripts\stop-indexer-tunnel.ps1
```

Manual Flask start:

```powershell
python backend/app.py
```

Dashboard:

```text
http://127.0.0.1:5000/
```

Wazuh Dashboard from host:

```text
https://localhost:8443
```

Wazuh Indexer from host through SSH tunnel:

```text
https://localhost:19200
```

Wazuh API from host:

```text
https://localhost:55000
```

Shuffle from host:

```text
http://localhost:3001
```

## Current Live Integrations

Required values are local only and should be placed in `config.py` or environment variables. Do not commit real secrets.

Wazuh Indexer:

```text
INDEXER_BASE=https://localhost:19200
INDEXER_USER=admin
INDEXER_PASS=<local indexer password>
```

Known working check:

```powershell
curl.exe -k -u admin:<password> "https://localhost:19200/_cat/indices/wazuh-alerts-*?v"
curl.exe -k -u admin:<password> "https://localhost:19200/wazuh-alerts-*/_count"
```

Observed indices exist for `wazuh-alerts-4.x-*`, with live alert data.

Wazuh Manager API:

```text
WAZUH_BASE=https://localhost:55000
WAZUH_USER=wazuh
WAZUH_PASS=<local API password>
```

Token test:

```powershell
$WAZUH_TOKEN = curl.exe -k -u wazuh:<password> "https://localhost:55000/security/user/authenticate?raw=true"
curl.exe -k -H "Authorization: Bearer $WAZUH_TOKEN" "https://localhost:55000/agents?select=id,name,ip,status,version"
```

Current agent reality:

```text
Only manager agent 000 exists.
Do not install wazuh-agent on the Wazuh Manager VM; it conflicts with wazuh-manager.
Install Wazuh Agent later on a separate endpoint VM or Windows/Linux endpoint.
FortiGate cannot run Wazuh Agent; integrate it through FortiGate API/syslog.
```

FortiGate:

```text
FORTIGATE_BASE_URL=https://192.168.138.128
FORTIGATE_API_KEY=<local FortiGate API token>
```

Known working endpoint:

```powershell
curl.exe -k "https://192.168.138.128/api/v2/monitor/system/resource/usage?access_token=<token>"
```

Known data from this endpoint includes CPU, memory, disk, sessions, and historical series. The endpoint `/api/v2/monitor/firewall/session` returned 404 on this FortiGate version, so use resource usage/session metrics for Executive Overview until a valid session endpoint is confirmed.

Shuffle:

```text
SHUFFLE_BASE_URL=http://localhost:3001
SHUFFLE_API_KEY=<local Shuffle API key>
```

Current use is basic health/connectivity. Workflow-specific integration still needs endpoint validation.

## Executive Overview Status

Frontend:

```text
frontend/react/executive/ExecutiveOverview.js
```

Backend:

```text
backend/spark_api.py route /spark/executive-overview
```

Current behavior:

- Uses a React island inside `dashboard.html`.
- Supports time ranges: `1h`, `6h`, `24h`, `7d`, `30d`.
- Does not clear visible data during refresh; it keeps previous data and shows an updating state.
- Uses a short backend cache for fast repeated range requests.
- Aggregates Wazuh Indexer, Wazuh API, FortiGate and Shuffle in parallel.
- Builds `Open Incidents - Service Workqueue` from Wazuh alert candidates.
- Workqueue includes SLA thresholds, priority, status, owner, expandable detail, JSON, rule tab, free text search, priority filters, and click-to-filter field values.
- MTTD and MTTR are not faked. They show `N/A` or live/status text until real incident lifecycle timestamps exist.

Known performance:

```text
Cold /spark/executive-overview request: around 2s to 5s depending on Wazuh API.
Warm cached request: near instant.
Wazuh API agent query can take around 5s.
Wazuh Indexer alert query can take around 2s.
FortiGate resource usage is usually fast.
Shuffle health can take around 2s.
```

Next Executive improvements:

- Add a visible "data age / cached" indicator.
- Add optional auto-refresh toggle.
- Create real incident lifecycle persistence so MTTD/MTTR can become real values.
- Add more useful executive drilldowns without turning the page into a raw SIEM clone.

## Remaining Real Data Work By Page

Threat Detection:

- Use Wazuh Indexer `wazuh-alerts-*` as the primary alert source.
- Add correlated feed from normalized Wazuh alerts.
- Add filters similar to Wazuh Dashboard: click field value to filter, active filter tokens, JSON detail, rule/MITRE view.
- Add severity, rule group, agent, decoder, MITRE tactic/technique, source/destination fields.
- Keep raw JSON available in drilldown, but show normalized analyst summary first.

Network & Endpoint:

- FortiGate Monitor API for CPU, memory, sessions and interfaces.
- FortiGate policy/address/session/log endpoints still need endpoint discovery.
- Wazuh Manager API for agents and endpoint health once separate agents exist.
- Wazuh Indexer for endpoint events, file integrity, rootcheck and system audit events.

Incident Response:

- Tickets currently exist in SQLite/Kanban.
- Need correlation path from Wazuh alert candidate to incident ticket.
- Need fields: incident id, priority, status, owner, SLA due, source alert ids, playbook status, timeline.
- Shuffle workflows should be called or at least listed through validated API endpoints.

Compliance & Risk:

- Wazuh modules can feed policy monitoring, vulnerability, SCA, system audit and file integrity.
- Need real queries for Wazuh rule groups/SCA once agents exist.
- FortiGate can feed security posture for network control and policy status if valid endpoints are confirmed.

Tickets:

- Current SQLite tickets are local.
- Need stronger relationship to normalized incidents.
- Consider keeping tickets as SPARK-owned SOC case records, not raw Wazuh events.

AI Proxy:

- Anthropic/Ollama hooks exist.
- Use AI only for summarization/recommendation after deterministic data is collected.
- Avoid making AI the source of truth.

## Testing Real Data

Wazuh Dashboard:

- Open `https://localhost:8443`.
- Go to `Security events`.
- Use filters such as `rule.id: 502`, `rule.id: 510`, `agent.name: wazuh-server`.
- Current alerts include Wazuh manager/rootcheck style events until endpoint agents are added.

Manual Indexer checks:

```powershell
curl.exe -k -u admin:<password> "https://localhost:19200/wazuh-alerts-*/_search?size=1&sort=@timestamp:desc"
```

Manual Executive API check:

```powershell
curl.exe -b cookies.txt -k "http://127.0.0.1:5000/spark/executive-overview?range=24h"
```

For authenticated API testing, log in through the browser first or perform `/auth/login` and preserve cookies.

Future injection tests:

- Add a separate Linux or Windows endpoint with Wazuh Agent.
- Generate SSH auth failures, suspicious process executions, file integrity changes and web scan traffic on that endpoint.
- Confirm alert appears in Wazuh Dashboard Security events.
- Confirm normalized alert appears in SPARK Threat Detection and, if high enough severity, Executive Workqueue.

## Authentication Notes

Local users are configured in `config.py` through `LOCAL_USERS`.

The login page must not display lab passwords. It should look like enterprise access with:

- local lab account support;
- optional Microsoft Entra ID;
- optional Google OAuth;
- clear "not configured" response if SSO variables are empty.

This is a good concept for an NG-SOC demo because SOC platforms are expected to have authenticated analyst workspaces and role-aware access. For the challenge, keep it functional but do not over-invest in full IAM unless required.

## Security Rules

- Never commit `config.py`, `.env`, `data/events.db`, root `events.db`, SSH keys, API tokens, Wazuh/FortiGate passwords or generated cookies.
- Keep `config.example.py` and `.env.example` safe examples only.
- Prefer English UI text.
- Avoid hardcoded fake values in live views.

## Next Recommended Task

Integrate the Threat Detection page with real Wazuh data.

Requirements:

- Preserve the existing Executive Overview implementation unless the user explicitly asks to change it.
- Add backend routes that query Wazuh Indexer through `INDEXER_BASE`, `INDEXER_USER` and `INDEXER_PASS`.
- Keep secrets in `config.py` or environment variables only.
- Do not hardcode lab credentials, API keys or real passwords.
- Build the page around normalized analyst data, with expandable raw JSON for each alert.
- Use Wazuh-like filtering behavior: click field values to filter, show active filter tokens, support free text search and time range filters.
- If live APIs are unavailable on the development machine, implement the code against the config contract and leave manual live validation for the home lab.

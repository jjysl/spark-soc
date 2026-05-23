# SPARK SOC - Final Presentation Deck Source

This markdown file is the source for the final presentation. It can be converted to PPT if required, but the team can also present directly from the dashboard and use this as speaker notes.

## Slide 1 - Title

**SPARK SOC**

NG-SOC em cloud para detecção, resposta e evidência auditável.

Positioning:

- MDR / NG-SOC as a Service.
- Analyst-approved automation.
- Fortinet-native response and evidence.

## Slide 2 - Problem

Organizations without mature SOC teams face:

- Too many alerts and not enough context.
- Manual incident triage.
- Slow containment.
- Weak response documentation.
- Difficulty proving what action was taken and why.

## Slide 3 - Solution

SPARK SOC connects:

- Wazuh telemetry.
- FortiGate containment.
- FortiAnalyzer evidence.
- Shuffle SOAR workflows.
- Groq AI Incident Briefing.
- Deterministic ML Risk scoring.
- Evidence Pack with SHA256.

Operational flow:

```text
Detect -> Analyze -> Recommend -> Orchestrate -> Contain -> Document
```

## Slide 4 - Architecture

```text
Wazuh Agent -> Wazuh Manager/Indexer -> SPARK SOC
SPARK SOC -> FortiGate API
SPARK SOC -> FortiAnalyzer JSON-RPC
SPARK SOC -> Shuffle SOAR
SPARK SOC -> Groq AI
SPARK SOC -> Evidence Pack / SHA256
```

Key point:

SPARK does not replace the analyst. It gives the analyst a faster, documented and repeatable response workflow.

## Slide 5 - Main Dashboard

Show:

- Executive Overview.
- Integration health.
- Incident Priority Queue.
- SOC Shift Summary.
- FortiAnalyzer evidence readiness.

Talk track:

The console is designed for analysts and managers: status, priorities and actions are visible without jumping between tools.

## Slide 6 - Incident Response Workflow

Show Incident Response:

- Incident candidate.
- IOC Enrichment.
- ML Risk score.
- AI Incident Briefing.
- Analyst reason and approval.
- Source Block / Destination Block.
- Shuffle SOAR dispatch.
- Evidence Pack.

## Slide 7 - FortiGate Response

Source Block:

- Blocks traffic coming from a malicious source IP.
- Uses `SPARK_BLOCKLIST`.
- Policy: `SPARK_AUTO_BLOCK`.

Destination Block:

- Prevents protected endpoints from accessing malicious destination IPs.
- Uses `SPARK_EGRESS_BLOCKLIST`.
- Policy: `SPARK_EGRESS_AUTO_BLOCK`.

Important:

Policy applied on FortiGate. Runtime enforcement depends on traffic passing through the policy and logs being available in FortiAnalyzer.

## Slide 8 - SOAR and Evidence

Shuffle SOAR:

- Receives SPARK evidence payload.
- Dispatches playbook or notification.
- Returns `execution_id`.
- Stores payload hash.

Evidence Pack:

- FortiGate object/group/policy.
- Shuffle execution.
- FortiAnalyzer evidence status.
- ML Risk summary.
- AI briefing summary.
- Analyst reason.
- SHA256 hash.

## Slide 9 - AI and ML

AI Incident Briefing:

- Uses Groq when configured.
- Uses deterministic fallback when AI is unavailable.
- Produces structured analyst briefing.

ML Risk:

- `deterministic_scoring_v1`.
- Score 0-100.
- Explainable features.
- Missing fields.
- FortiAnalyzer evidence impact.

Clarification:

This is deterministic risk scoring, not autonomous trained ML.

## Slide 10 - Product Model

SPARK SOC is not a simple download.

It is a cloud subscription workspace:

- Monthly subscription.
- Data ingestion measured in GB/day.
- Endpoint count.
- MDR/SOAR add-ons.
- Onboarding through agents, connectors and API integration.

Target customers:

- SMBs.
- Companies with Fortinet stack.
- Teams without mature SOC.
- MSSPs that need repeatable response evidence.

## Slide 11 - Differentiators

- Analyst-approved automation.
- Real FortiGate API containment.
- Source and destination blocking.
- FortiAnalyzer evidence layer.
- Shuffle orchestration with execution ID.
- AI briefing with fallback.
- Evidence Pack with SHA256.
- Honest statuses: no fake evidence, no fake compliance.

## Slide 12 - Closing

SPARK SOC turns security alerts into an auditable response workflow.

Final message:

```text
Detect faster.
Respond with approval.
Document with evidence.
```

Recommended live demo:

1. Open dashboard.
2. Enrich IOC.
3. Generate recommendation.
4. Generate AI briefing.
5. Approve response.
6. Execute FortiGate block.
7. Show Shuffle execution ID.
8. Show Evidence Pack and SHA256.

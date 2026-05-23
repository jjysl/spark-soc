# SPARK SOC - Challenge Deliverables

This file maps the Fortinet/FIAP Challenge requirements to the repository contents.

## Submission Checklist

| Required item | Repository answer | Status |
| --- | --- | --- |
| Public GitHub link | https://github.com/jjysl/spark-soc | Ready |
| Technical architecture with integrations | [ARCHITECTURE.md](ARCHITECTURE.md) | Ready |
| Implementation documentation and reproduction guide | [IMPLEMENTATION.md](IMPLEMENTATION.md) | Ready |
| Final presentation deck | [presentation/SPARK_SOC_FINAL_DECK.md](presentation/SPARK_SOC_FINAL_DECK.md) | Ready as deck source |

## Suggested Submission Format

Submit the public repository link:

```text
https://github.com/jjysl/spark-soc
```

If the portal requires a ZIP file, export the repository without local runtime files:

```text
SPARKSoc/
  README.md
  docs/
  backend/
  frontend/
  scripts/
  config.example.py
  .env.example
```

Do not include:

- `.env`
- real API keys
- `config.py`
- `.venv`
- `__pycache__`
- local database files with sensitive runtime evidence

## Notes for the Evaluators

SPARK SOC is a cloud NG-SOC / MDR MVP. It demonstrates a practical analyst-approved response workflow:

```text
Detect -> Analyze -> Recommend -> Orchestrate -> Contain -> Document
```

The current solution includes:

- Wazuh telemetry and alert triage.
- FortiGate source IP block/unblock.
- FortiGate destination/egress IP block/unblock.
- Shuffle SOAR dispatch and analyst notification.
- IOC enrichment with local evidence.
- FortiAnalyzer evidence lookup.
- Groq AI Incident Briefing with deterministic fallback.
- Deterministic ML Risk scoring.
- Evidence Pack with SHA256 integrity hash.

Containment is not fully autonomous. The platform recommends actions and executes them after analyst approval.

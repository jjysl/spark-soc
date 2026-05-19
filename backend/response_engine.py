"""Deterministic response recommendation engine for SPARK SOC.

This is not trained ML. It is an analyst-facing risk scoring layer that turns
incident evidence into a recommended action while keeping approval mandatory.
"""
from __future__ import annotations

import ipaddress


PROTECTED_IPS = {"127.0.0.1", "0.0.0.0", "192.168.50.1", "192.168.50.20", "192.168.50.30", "192.168.50.40", "10.10.1.4"}


def _severity_score(severity: str) -> int:
    value = str(severity or "").lower()
    if value in {"critical", "p1"}:
        return 35
    if value in {"high", "p2"}:
        return 28
    if value in {"medium", "p3"}:
        return 16
    if value in {"low", "p4"}:
        return 6
    return 10


def _is_bruteforce_or_lateral(mitre: str, title: str) -> bool:
    haystack = f"{mitre} {title}".lower()
    return any(token in haystack for token in ("t1110", "brute force", "lateral", "remote service", "credential"))


def recommend(payload: dict) -> dict:
    source_ip = str(payload.get("source_ip") or payload.get("ip") or "").strip()
    reasons = []
    risk = _severity_score(payload.get("severity"))

    protected = False
    private_ip = False
    try:
        parsed = ipaddress.ip_address(source_ip)
        private_ip = parsed.is_private
        protected = source_ip in PROTECTED_IPS or parsed.is_loopback or parsed.is_unspecified
    except ValueError:
        reasons.append("Source IP is missing or invalid; containment requires analyst review.")

    severity = str(payload.get("severity") or "requires review").lower()
    alert_count = int(payload.get("alert_count") or 0)
    repeated = int(payload.get("repeated_source_count") or 0)
    previous_blocks = int(payload.get("previous_blocks") or 0)
    fa_logs = int(payload.get("fortianalyzer_log_count") or 0)
    mitre = str(payload.get("mitre") or "")
    title = str(payload.get("title") or "Security incident")

    if severity in {"critical", "high", "p1", "p2"}:
        reasons.append(f"Severity is {severity}.")
    if alert_count >= 20:
        risk += 20
        reasons.append(f"{alert_count} alerts observed for this incident.")
    elif alert_count >= 5:
        risk += 10
        reasons.append(f"{alert_count} correlated alerts observed.")
    if _is_bruteforce_or_lateral(mitre, title):
        risk += 18
        reasons.append("MITRE/context indicates brute force, credential activity or lateral movement.")
    if repeated:
        risk += min(15, repeated * 3)
        reasons.append(f"Source IP appears in {repeated} previous response/evidence event(s).")
    if previous_blocks:
        risk += 10
        reasons.append("Source IP has previous containment history.")
    if fa_logs:
        risk += min(12, fa_logs * 2)
        reasons.append(f"FortiAnalyzer returned {fa_logs} related log record(s).")
    if private_ip:
        risk -= 5
        reasons.append("Source IP is private; containment should consider internal asset context.")
    if protected:
        risk = min(risk, 30)
        reasons.append("Source IP is protected/control-plane; block and quarantine are not recommended.")

    risk = max(0, min(100, risk))
    if protected:
        action = "monitor"
    elif risk >= 70 and alert_count >= 20 and _is_bruteforce_or_lateral(mitre, title):
        action = "block"
    elif risk >= 40 or severity in {"medium", "high", "p2", "p3"}:
        action = "quarantine"
    else:
        action = "monitor"

    if action == "block":
        playbook = "SPARK - Block Confirmed Malicious IP"
    elif action == "quarantine":
        playbook = "SPARK - Quarantine Suspicious IP"
    else:
        playbook = "SPARK - Monitor and Document IOC"

    confidence = "high" if risk >= 75 else "medium" if risk >= 45 else "low"
    if not reasons:
        reasons.append("Evidence is incomplete; monitoring is recommended until more telemetry arrives.")

    return {
        "recommended_action": action,
        "risk_score": risk,
        "confidence": confidence,
        "reasons": reasons,
        "required_approval": True,
        "automation_mode": "analyst_approved",
        "playbook": playbook,
        "engine": "deterministic risk scoring",
    }

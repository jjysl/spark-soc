"""Deterministic ML-readiness scoring for SPARK SOC incidents.

This module intentionally implements explainable analytics, not a trained
machine-learning model. The output is designed to become a clean dataset for a
future lightweight model after analyst labels exist.
"""
from __future__ import annotations

import csv
import ipaddress
import io
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

import config

MODEL_TYPE = "deterministic_scoring_v1"

EVENT_COLUMNS = [
    "event_id",
    "incident_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "target_host",
    "user",
    "rule_id",
    "rule_description",
    "mitre_technique",
    "severity",
    "alert_count",
    "source_reputation",
    "geo_country",
    "asset_criticality",
    "fortigate_object",
    "fortigate_group",
    "fortigate_policy",
    "action_taken",
    "action_success",
    "containment_confidence",
    "fortianalyzer_evidence_status",
    "fortianalyzer_log_count",
    "fortianalyzer_policy_hits",
    "fortianalyzer_deny_count",
    "fortianalyzer_allow_count",
    "fortianalyzer_traffic_action",
    "fortianalyzer_policyid",
    "containment_verified",
    "evidence_id",
    "response_time_seconds",
    "analyst_decision",
    "false_positive",
    "label",
    "risk_score",
    "risk_band",
    "explanation_json",
]


def _db() -> sqlite3.Connection:
    try:
        config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    except AttributeError:
        pass
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "ok", "success", "blocked", "present"}


def _is_external_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def _first(payload: dict, *keys: str, default: Any = "") -> Any:
    for key in keys:
        if key in payload and payload.get(key) not in (None, ""):
            return payload.get(key)
    return default


def _fortianalyzer_summary(raw: dict) -> dict:
    evidence = raw.get("fortianalyzer") or raw.get("fortianalyzer_evidence") or raw.get("fa_evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}
    references = evidence.get("references") if isinstance(evidence.get("references"), list) else []
    items = evidence.get("items") if isinstance(evidence.get("items"), list) else []
    rows = [item for item in [*references, *items] if isinstance(item, dict)]
    actions = [str(item.get("action") or item.get("traffic_action") or "").lower() for item in rows]
    policy_ids = [str(item.get("policyid") or item.get("policy_id") or "") for item in rows if item.get("policyid") or item.get("policy_id")]
    deny_count = sum(1 for action in actions if action in {"deny", "denied", "blocked", "block", "dropped", "drop"})
    allow_count = sum(1 for action in actions if action in {"accept", "accepted", "allow", "allowed", "pass"})
    policy_hits = len([policy for policy in policy_ids if policy])
    log_count = _as_int(_first(evidence, "log_count", "total", default=len(rows)), len(rows))
    status = str(_first(evidence, "evidence_status", "status", default="not_queried"))
    traffic_action = "deny" if deny_count else "allow" if allow_count else str(_first(evidence, "traffic_action", "action", default=""))
    containment_verified = status == "evidence_collected" and (deny_count > 0 or policy_hits > 0)
    return {
        "fortianalyzer_evidence_status": status,
        "fortianalyzer_log_count": log_count,
        "fortianalyzer_policy_hits": policy_hits,
        "fortianalyzer_deny_count": deny_count,
        "fortianalyzer_allow_count": allow_count,
        "fortianalyzer_traffic_action": traffic_action,
        "fortianalyzer_policyid": ", ".join(policy_ids[:5]),
        "containment_verified": containment_verified,
    }


def _severity_level(payload: dict) -> int:
    level = _as_int(_first(payload, "level", "rule_level", "severity_level"), 0)
    if level:
        return max(0, min(15, level))
    severity = str(_first(payload, "severity", "priority", default="")).lower()
    if severity in {"critical", "crit", "p1"}:
        return 14
    if severity in {"high", "p2"}:
        return 10
    if severity in {"medium", "med", "p3"}:
        return 6
    if severity in {"low", "p4"}:
        return 3
    return 0


def normalize_incident(payload: dict) -> dict:
    payload = payload or {}
    raw = payload.get("incident") or payload.get("case") or payload.get("alert") or payload
    if not isinstance(raw, dict):
        raw = {}
    source_ip = _first(raw, "source_ip", "src_ip", "ip", "indicator", default="")
    fa = _fortianalyzer_summary(raw)
    return {
        "event_id": str(_first(raw, "event_id", "id", "document_id", "source_alert_id", default="")).strip(),
        "incident_id": str(_first(raw, "incident_id", "case_id", "caseId", "ticket_id", default="")).strip(),
        "timestamp": str(_first(raw, "timestamp", "alert_timestamp", "created_at", default=_iso_now())),
        "source_ip": str(source_ip or ""),
        "destination_ip": str(_first(raw, "destination_ip", "dst_ip", "target_ip", default="")),
        "target_host": str(_first(raw, "target_host", "agent_name", "host", "target", default="")),
        "user": str(_first(raw, "user", "username", default="")),
        "rule_id": str(_first(raw, "rule_id", "ruleId", default="")),
        "rule_description": str(_first(raw, "rule_description", "description", "title", default="")),
        "mitre_tactic": str(_first(raw, "mitre_tactic", "tactic", default="")),
        "mitre_technique": str(_first(raw, "mitre_technique", "technique", "mitre", default="")),
        "severity": str(_first(raw, "severity", "priority", default="")),
        "level": _severity_level(raw),
        "alert_count": max(1, _as_int(_first(raw, "alert_count", "alerts_in_range", default=1), 1)),
        "repeated_source_count": _as_int(_first(raw, "repeated_source_count", "source_count", default=0), 0),
        "previous_block_count": _as_int(_first(raw, "previous_block_count", "previous_blocks", default=0), 0),
        "source_reputation": str(_first(raw, "source_reputation", "reputation", default="unknown")),
        "geo_country": str(_first(raw, "geo_country", "country", default="")),
        "asset_criticality": str(_first(raw, "asset_criticality", "criticality", default="normal")),
        "fortigate_object": str(_first(raw, "fortigate_object", "object_name", "object", default="")),
        "fortigate_group": str(_first(raw, "fortigate_group", "group_name", "group", default="")),
        "fortigate_policy": str(_first(raw, "fortigate_policy", "policy_name", "policy", default="")),
        "action_taken": str(_first(raw, "action_taken", "action", default="")),
        "action_success": _as_bool(_first(raw, "action_success", "ok", "success", default=False)),
        "containment_status": str(_first(raw, "containment_status", "status", default="")),
        "containment_confidence": str(_first(raw, "containment_confidence", default="")),
        **fa,
        "evidence_id": str(_first(raw, "evidence_id", default="")),
        "response_time_seconds": _as_int(_first(raw, "response_time_seconds", default=0), 0),
        "analyst_decision": str(_first(raw, "analyst_decision", default="")),
        "false_positive": _as_bool(_first(raw, "false_positive", default=False)),
        "label": str(_first(raw, "label", default="")),
    }


def score_incident(payload: dict) -> dict:
    item = normalize_incident(payload)
    missing_fields = [
        field for field in ("source_ip", "target_host", "rule_id", "mitre_technique")
        if not item.get(field)
    ]
    features = {
        "severity_level": item["level"],
        "alert_count": item["alert_count"],
        "asset_criticality": item["asset_criticality"],
        "external_source_ip": _is_external_ip(item["source_ip"]),
        "mitre_present": bool(item["mitre_tactic"] or item["mitre_technique"]),
        "repeated_source_count": item["repeated_source_count"],
        "previous_block_count": item["previous_block_count"],
        "action_success": item["action_success"],
        "fortigate_evidence_present": bool(item["fortigate_object"] or item["fortigate_group"] or item["fortigate_policy"]),
        "fortianalyzer_evidence_status": item["fortianalyzer_evidence_status"],
        "fortianalyzer_log_count": item["fortianalyzer_log_count"],
        "fortianalyzer_policy_hits": item["fortianalyzer_policy_hits"],
        "fortianalyzer_deny_count": item["fortianalyzer_deny_count"],
        "containment_verified": item["containment_verified"],
    }

    asset_text = f"{item['asset_criticality']} {item['target_host']}".lower()
    critical_asset = any(term in asset_text for term in ("critical", "high", "server", "dc", "domain", "wazuh", "firewall", "fortigate"))
    severity_score = min(25, round((item["level"] / 15) * 25))
    alert_score = min(20, item["alert_count"] * 4)
    asset_score = 15 if critical_asset else 7 if item["asset_criticality"].lower() in {"medium", "moderate"} else 0
    external_score = 10 if features["external_source_ip"] else 0
    mitre_score = 10 if features["mitre_present"] else 0
    repeated_score = min(10, max(item["repeated_source_count"], item["alert_count"] - 1) * 2)
    containment_score = 5 if item["action_success"] or item["containment_status"].lower() in {"blocked", "contained"} else 0
    previous_block_score = min(5, item["previous_block_count"] * 2)
    fortianalyzer_score = 0
    if item["containment_verified"]:
        fortianalyzer_score = 8
    elif item["fortianalyzer_evidence_status"] == "evidence_collected":
        fortianalyzer_score = 3

    score = min(100, severity_score + alert_score + asset_score + external_score + mitre_score + repeated_score + containment_score + previous_block_score + fortianalyzer_score)
    if score >= 85:
        band = "critical"
    elif score >= 60:
        band = "high"
    elif score >= 30:
        band = "medium"
    else:
        band = "low"

    explanation = [
        f"Severity contribution {severity_score}/25 from level {item['level']}.",
        f"Alert volume contribution {alert_score}/20 from {item['alert_count']} alert(s).",
    ]
    if critical_asset:
        explanation.append("Target or asset criticality increased business impact.")
    if features["external_source_ip"]:
        explanation.append("Source IP is external to private/control-plane ranges.")
    if features["mitre_present"]:
        explanation.append("MITRE context is present and improves triage confidence.")
    if repeated_score:
        explanation.append("Repeated source activity increased correlation risk.")
    if containment_score:
        explanation.append("FortiGate containment evidence is present; runtime enforcement still requires traffic-path validation.")
    if item["containment_verified"]:
        explanation.append("FortiAnalyzer returned log or policy-hit evidence that increases containment confidence.")
    elif item["fortianalyzer_evidence_status"] in {"evidence_pending", "connector_ready", "not_queried", "no_results"}:
        explanation.append(f"FortiAnalyzer validation status is {item['fortianalyzer_evidence_status']}; do not claim runtime enforcement until logs confirm it.")
    if missing_fields:
        explanation.append(f"Missing fields limited confidence: {', '.join(missing_fields)}.")

    if band in {"critical", "high"}:
        recommended_action = "block"
    elif band == "medium":
        recommended_action = "quarantine"
    else:
        recommended_action = "monitor"

    return {
        **item,
        "risk_score": score,
        "risk_band": band,
        "recommended_action": recommended_action,
        "confidence": "high" if score >= 75 and not missing_fields else "medium" if score >= 45 else "low",
        "explanation": explanation,
        "features_used": features,
        "missing_fields": missing_fields,
        "model_type": MODEL_TYPE,
        "model_note": "Deterministic scoring for prioritization; this is not a trained ML model.",
    }


def init_ml_store() -> None:
    conn = _db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ml_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,
            incident_id TEXT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            target_host TEXT,
            user TEXT,
            rule_id TEXT,
            rule_description TEXT,
            mitre_technique TEXT,
            severity TEXT,
            alert_count INTEGER,
            source_reputation TEXT,
            geo_country TEXT,
            asset_criticality TEXT,
            fortigate_object TEXT,
            fortigate_group TEXT,
            fortigate_policy TEXT,
            action_taken TEXT,
            action_success INTEGER,
            containment_confidence TEXT,
            fortianalyzer_evidence_status TEXT,
            fortianalyzer_log_count INTEGER,
            fortianalyzer_policy_hits INTEGER,
            fortianalyzer_deny_count INTEGER,
            fortianalyzer_allow_count INTEGER,
            fortianalyzer_traffic_action TEXT,
            fortianalyzer_policyid TEXT,
            containment_verified INTEGER,
            evidence_id TEXT,
            response_time_seconds INTEGER,
            analyst_decision TEXT,
            false_positive INTEGER,
            label TEXT,
            risk_score INTEGER,
            risk_band TEXT,
            explanation_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(ml_events)").fetchall()}
    migrations = {
        "fortianalyzer_evidence_status": "TEXT",
        "fortianalyzer_log_count": "INTEGER",
        "fortianalyzer_policy_hits": "INTEGER",
        "fortianalyzer_deny_count": "INTEGER",
        "fortianalyzer_allow_count": "INTEGER",
        "fortianalyzer_traffic_action": "TEXT",
        "fortianalyzer_policyid": "TEXT",
        "containment_verified": "INTEGER",
    }
    for column, definition in migrations.items():
        if column not in existing_columns:
            conn.execute(f"ALTER TABLE ml_events ADD COLUMN {column} {definition}")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ml_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,
            incident_id TEXT,
            timestamp TEXT,
            risk_score INTEGER NOT NULL,
            risk_band TEXT NOT NULL,
            recommended_action TEXT,
            explanation_json TEXT NOT NULL,
            features_json TEXT NOT NULL,
            missing_fields_json TEXT NOT NULL,
            model_type TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def persist_score(score: dict) -> dict:
    init_ml_store()
    created_at = _iso_now()
    event_id = score.get("event_id") or f"ml-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
    score["event_id"] = event_id
    explanation_json = json.dumps({
        "explanation": score.get("explanation", []),
        "recommended_action": score.get("recommended_action", ""),
        "features_used": score.get("features_used", {}),
        "missing_fields": score.get("missing_fields", []),
        "model_type": MODEL_TYPE,
    }, ensure_ascii=False, sort_keys=True)
    conn = _db()
    cursor = conn.execute(
        f"""
        INSERT INTO ml_events ({", ".join(EVENT_COLUMNS)}, created_at)
        VALUES ({", ".join(["?"] * len(EVENT_COLUMNS))}, ?)
        """,
        [
            score.get("event_id", ""),
            score.get("incident_id", ""),
            score.get("timestamp", ""),
            score.get("source_ip", ""),
            score.get("destination_ip", ""),
            score.get("target_host", ""),
            score.get("user", ""),
            score.get("rule_id", ""),
            score.get("rule_description", ""),
            score.get("mitre_technique", ""),
            score.get("severity", ""),
            score.get("alert_count", 0),
            score.get("source_reputation", ""),
            score.get("geo_country", ""),
            score.get("asset_criticality", ""),
            score.get("fortigate_object", ""),
            score.get("fortigate_group", ""),
            score.get("fortigate_policy", ""),
            score.get("action_taken", ""),
            1 if score.get("action_success") else 0,
            score.get("containment_confidence", ""),
            score.get("fortianalyzer_evidence_status", ""),
            score.get("fortianalyzer_log_count", 0),
            score.get("fortianalyzer_policy_hits", 0),
            score.get("fortianalyzer_deny_count", 0),
            score.get("fortianalyzer_allow_count", 0),
            score.get("fortianalyzer_traffic_action", ""),
            score.get("fortianalyzer_policyid", ""),
            1 if score.get("containment_verified") else 0,
            score.get("evidence_id", ""),
            score.get("response_time_seconds", 0),
            score.get("analyst_decision", ""),
            1 if score.get("false_positive") else 0,
            score.get("label", ""),
            score.get("risk_score", 0),
            score.get("risk_band", ""),
            explanation_json,
            created_at,
        ],
    )
    score_row_id = cursor.lastrowid
    conn.execute(
        """
        INSERT INTO ml_scores (
            event_id, incident_id, timestamp, risk_score, risk_band, recommended_action,
            explanation_json, features_json, missing_fields_json, model_type, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            score.get("incident_id", ""),
            score.get("timestamp", ""),
            score.get("risk_score", 0),
            score.get("risk_band", ""),
            score.get("recommended_action", ""),
            json.dumps(score.get("explanation", []), ensure_ascii=False),
            json.dumps(score.get("features_used", {}), ensure_ascii=False, sort_keys=True),
            json.dumps(score.get("missing_fields", []), ensure_ascii=False),
            MODEL_TYPE,
            created_at,
        ),
    )
    conn.commit()
    conn.close()
    return {**score, "ml_event_id": score_row_id, "created_at": created_at}


def _decode_score_row(row: sqlite3.Row) -> dict:
    item = dict(row)
    for key, fallback in (("explanation_json", []), ("features_json", {}), ("missing_fields_json", [])):
        try:
            item[key.replace("_json", "")] = json.loads(item.get(key) or json.dumps(fallback))
        except (TypeError, ValueError):
            item[key.replace("_json", "")] = fallback
    return item


def get_status() -> dict:
    init_ml_store()
    conn = _db()
    counts = {
        "ml_events": conn.execute("SELECT COUNT(*) FROM ml_events").fetchone()[0],
        "ml_scores": conn.execute("SELECT COUNT(*) FROM ml_scores").fetchone()[0],
    }
    last = conn.execute("SELECT created_at FROM ml_scores ORDER BY created_at DESC LIMIT 1").fetchone()
    conn.close()
    return {
        "ready": True,
        "enabled": True,
        "engine": MODEL_TYPE,
        "model_type": MODEL_TYPE,
        "trained_model": False,
        "model_note": "Deterministic scoring for prioritization; this is not a trained ML model.",
        "tables_ready": True,
        "event_count": counts["ml_events"],
        "score_count": counts["ml_scores"],
        "dataset_counts": counts,
        "last_score_timestamp": last["created_at"] if last else "",
    }


def get_insights(limit: int = 25) -> dict:
    init_ml_store()
    conn = _db()
    rows = conn.execute(
        """
        SELECT * FROM ml_scores
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    top_rows = conn.execute(
        """
        SELECT * FROM ml_scores
        ORDER BY risk_score DESC, created_at DESC
        LIMIT 8
        """,
    ).fetchall()
    distribution_rows = conn.execute(
        "SELECT risk_band, COUNT(*) AS count FROM ml_scores GROUP BY risk_band"
    ).fetchall()
    repeated_rows = conn.execute(
        """
        SELECT source_ip, COUNT(*) AS count, MAX(risk_score) AS max_risk
        FROM ml_events
        WHERE source_ip != ''
        GROUP BY source_ip
        HAVING COUNT(*) > 1
        ORDER BY count DESC, max_risk DESC
        LIMIT 10
        """
    ).fetchall()
    fa_rows = conn.execute(
        "SELECT fortianalyzer_evidence_status, COUNT(*) AS count FROM ml_events GROUP BY fortianalyzer_evidence_status"
    ).fetchall()
    verified_count = conn.execute(
        "SELECT COUNT(*) FROM ml_events WHERE containment_verified = 1"
    ).fetchone()[0]
    conn.close()

    latest = [_decode_score_row(row) for row in rows]
    top = [_decode_score_row(row) for row in top_rows]
    recommendations = [
        {
            "incident_id": item.get("incident_id", ""),
            "event_id": item.get("event_id", ""),
            "risk_score": item.get("risk_score", 0),
            "risk_band": item.get("risk_band", ""),
            "recommendation": item.get("recommended_action", ""),
            "analyst_approval_required": True,
        }
        for item in top if item.get("risk_score", 0) >= 70
    ]
    return {
        "status": get_status(),
        "latest_scores": latest,
        "top_risks": top,
        "score_distribution": {row["risk_band"] or "unknown": row["count"] for row in distribution_rows},
        "repeated_source_ips": [dict(row) for row in repeated_rows],
        "fortianalyzer_distribution": {row["fortianalyzer_evidence_status"] or "unknown": row["count"] for row in fa_rows},
        "containment_verified_count": verified_count,
        "containment_recommendations": recommendations,
        "exports": {
            "json": "/spark/ml/export?format=json",
            "csv": "/spark/ml/export?format=csv",
        },
    }


def export_dataset(fmt: str = "json") -> tuple[str, str]:
    init_ml_store()
    conn = _db()
    rows = [dict(row) for row in conn.execute("SELECT * FROM ml_events ORDER BY created_at DESC").fetchall()]
    conn.close()
    for row in rows:
        row["action_success"] = bool(row.get("action_success"))
        row["false_positive"] = bool(row.get("false_positive"))
        try:
            row["explanation"] = json.loads(row.get("explanation_json") or "{}")
        except (TypeError, ValueError):
            row["explanation"] = {}
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[*EVENT_COLUMNS, "created_at"])
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in [*EVENT_COLUMNS, "created_at"]})
        return output.getvalue(), "text/csv"
    return json.dumps({"model_type": MODEL_TYPE, "rows": rows}, ensure_ascii=False, indent=2), "application/json"

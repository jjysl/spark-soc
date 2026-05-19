"""
SPARK SOC — API Blueprint /spark/*
=====================================
Todos os endpoints do dashboard agrupados num Blueprint Flask.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import time

from flask import Blueprint, Response, jsonify, request

import config
from backend import tickets as ticket_store
from backend import fortigate, fortianalyzer, ml_scoring, response_engine, wazuh, ai_proxy, shuffle, jira

spark_bp = Blueprint("spark", __name__)

EXECUTIVE_RANGES = {"1h", "6h", "24h", "7d", "30d"}
SLA_POLICY_MINUTES = {"P1": 15, "P2": 45, "P3": 90, "P4": 360}
EXECUTIVE_CACHE_TTL_SECONDS = 20
_executive_cache: dict[str, tuple[float, dict]] = {}
PROTECTED_BLOCK_IPS = {"127.0.0.1", "0.0.0.0", "192.168.50.1", "192.168.50.20", "192.168.50.30", "192.168.50.40"}


def _parse_wazuh_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value
    if len(value) > 5 and (value[-5] in {"+", "-"}) and value[-2:].isdigit():
        normalized = f"{value[:-2]}:{value[-2:]}"
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_block_ip(raw_ip: str) -> tuple[str | None, tuple[dict, int] | None]:
    ip = (raw_ip or "").strip()
    if not ip:
        return None, ({"status": "invalid_ip", "message": "IP is required."}, 400)
    try:
        parsed = ipaddress.IPv4Address(ip)
    except ValueError:
        return None, ({"status": "invalid_ip", "message": "Only valid IPv4 addresses are accepted.", "ip": ip}, 400)
    text = str(parsed)
    if text in PROTECTED_BLOCK_IPS:
        return None, ({"status": "protected_ip", "message": "Protected workspace/control-plane IP cannot be blocked.", "ip": text}, 400)
    return text, None


def _block_config() -> dict:
    return {
        "group_name": getattr(config, "FORTIGATE_BLOCKLIST_GROUP", "SPARK_BLOCKLIST"),
        "policy_name": getattr(config, "FORTIGATE_BLOCKLIST_POLICY", "SPARK_AUTO_BLOCK"),
        "srcintf": getattr(config, "FORTIGATE_BLOCK_SRCINTF", "any"),
        "dstintf": getattr(config, "FORTIGATE_BLOCK_DSTINTF", "any"),
    }


def _quarantine_config() -> dict:
    return {
        "group_name": getattr(config, "FORTIGATE_QUARANTINE_GROUP", "SPARK_QUARANTINE_LIST"),
        "policy_name": getattr(config, "FORTIGATE_QUARANTINE_POLICY", "SPARK_QUARANTINE_REVIEW"),
        "srcintf": getattr(config, "FORTIGATE_QUARANTINE_SRCINTF", getattr(config, "FORTIGATE_BLOCK_SRCINTF", "any")),
        "dstintf": getattr(config, "FORTIGATE_QUARANTINE_DSTINTF", getattr(config, "FORTIGATE_BLOCK_DSTINTF", "any")),
    }


def _destination_block_config() -> dict:
    return {
        "group_name": getattr(config, "FORTIGATE_DESTINATION_BLOCK_GROUP", "SPARK_EGRESS_BLOCKLIST"),
        "policy_name": getattr(config, "FORTIGATE_DESTINATION_BLOCK_POLICY", "SPARK_EGRESS_AUTO_BLOCK"),
        "srcaddr_name": getattr(config, "FORTIGATE_DESTINATION_BLOCK_SRCADDR", "all") or "all",
        "srcintf": getattr(config, "FORTIGATE_DESTINATION_BLOCK_SRCINTF", getattr(config, "FORTIGATE_BLOCK_SRCINTF", "any")),
        "dstintf": getattr(config, "FORTIGATE_DESTINATION_BLOCK_DSTINTF", getattr(config, "FORTIGATE_BLOCK_DSTINTF", "any")),
    }


def _fortianalyzer_config() -> tuple[str, str]:
    return (
        getattr(config, "FORTIANALYZER_BASE_URL", "") or "",
        getattr(config, "FORTIANALYZER_API_KEY", "") or "",
    )


def _payload_hash(payload: dict) -> str:
    blob = json.dumps(payload or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _dashboard_link() -> str:
    return getattr(config, "SPARK_DASHBOARD_URL", "") or getattr(config, "DASHBOARD_URL", "") or ""


def _notification_webhook() -> str:
    return getattr(config, "SHUFFLE_NOTIFICATION_WEBHOOK_URL", "") or getattr(config, "SHUFFLE_INCIDENT_WEBHOOK_URL", "")


def _fortianalyzer_evidence_for_score(ip: str, limit: int = 10) -> dict:
    if not ip:
        return {
            "configured": False,
            "connected": False,
            "source": "fortianalyzer",
            "evidence_status": "not_queried",
            "log_count": 0,
            "items": [],
            "references": [],
            "message": "No source IP was available for FortiAnalyzer evidence lookup.",
        }
    try:
        base_url, api_key = _fortianalyzer_config()
        return fortianalyzer.get_evidence_for_ip(base_url, api_key, ip, limit=limit)
    except Exception as exc:
        return {
            "configured": False,
            "connected": False,
            "source": "fortianalyzer",
            "evidence_status": "evidence_pending",
            "log_count": 0,
            "items": [],
            "references": [],
            "message": "FortiAnalyzer evidence lookup is pending analyst review.",
            "error": str(exc),
        }


def _with_fortianalyzer_evidence(payload: dict, force: bool = False) -> dict:
    data = dict(payload or {})
    raw = data.get("incident") or data.get("case") or data.get("alert") or data
    if not isinstance(raw, dict):
        return data
    if raw.get("fortianalyzer") or raw.get("fortianalyzer_evidence"):
        return data
    should_query = force or bool(data.get("include_fortianalyzer") or data.get("enrich_fortianalyzer"))
    if not should_query:
        return data
    ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("ip") or raw.get("indicator") or ""
    enriched = dict(raw)
    enriched["fortianalyzer"] = _fortianalyzer_evidence_for_score(ip)
    if data.get("incident") is raw:
        data["incident"] = enriched
    elif data.get("case") is raw:
        data["case"] = enriched
    elif data.get("alert") is raw:
        data["alert"] = enriched
    else:
        data = enriched
    return data


def _score_and_persist_safe(payload: dict) -> dict:
    try:
        score = ml_scoring.score_incident(payload)
        return ml_scoring.persist_score(score)
    except Exception as exc:
        return {"status": "ml_score_failed", "error": str(exc), "model_type": "deterministic_scoring_v1"}


def _record_fortigate_evidence(action: str, status: str, payload: dict, case_id: str = "", ticket_id: str = "") -> dict:
    return ticket_store.record_action_event(
        case_id=case_id,
        ticket_id=ticket_id,
        action=action,
        status=status,
        payload=payload,
    )


def _fmt_minutes(minutes: int) -> str:
    sign = "-" if minutes < 0 else ""
    minutes = abs(int(minutes))
    if minutes < 60:
        return f"{sign}{minutes} min"
    hours, rem = divmod(minutes, 60)
    if hours < 24:
        return f"{sign}{hours}h {rem:02d}m"
    days, hours = divmod(hours, 24)
    return f"{sign}{days}d {hours}h"


def _priority_from_level(level: int) -> str:
    if level >= 12:
        return "P1"
    if level >= 7:
        return "P2"
    return "P3"


def _badge_from_priority(priority: str) -> str:
    return {"P1": "bp1", "P2": "bp2", "P3": "bp3", "P4": "bp4"}.get(priority, "bp3")


def _status_label(status: str, sla_state: str) -> str:
    if status == "closed":
        return "Closed"
    return {
        "new": "New",
        "investigating": "Investigating",
        "acknowledged": "Acknowledged",
        "resolved": "Resolved",
    }.get(status or "new", "New")


def _build_workqueue(cases: list[dict]) -> tuple[list[dict], dict]:
    now = datetime.now(timezone.utc)
    workqueue = []
    within_sla = 0
    measurable = 0

    for idx, case in enumerate(cases, start=1):
        raw_event = {}
        if case.get("raw_json"):
            try:
                raw_event = json.loads(case.get("raw_json") or "{}")
            except (TypeError, ValueError):
                raw_event = {"parse_error": "raw_json is not valid JSON"}
        priority = case.get("priority") or "P3"
        policy_minutes = int(case.get("sla_minutes") or SLA_POLICY_MINUTES.get(priority, 90))
        created_at = _parse_wazuh_timestamp(case.get("created_at", ""))
        due_at = _parse_wazuh_timestamp(case.get("due_at", ""))
        age_minutes = 0
        remaining_minutes = policy_minutes
        sla_state = "unknown"
        if created_at and due_at:
            measurable += 1
            age_minutes = max(0, int((now - created_at).total_seconds() // 60))
            remaining_minutes = int((due_at - now).total_seconds() // 60)
            if case.get("status") == "closed":
                sla_state = "closed"
            elif remaining_minutes < 0:
                sla_state = "breached"
            elif remaining_minutes <= max(5, policy_minutes * 0.25):
                sla_state = "at_risk"
            else:
                sla_state = "within"
            if remaining_minutes >= 0 or sla_state == "closed":
                within_sla += 1

        status = _status_label(case.get("status", "new"), sla_state)
        fill_pct = max(5, min(100, int((age_minutes / policy_minutes) * 100))) if policy_minutes else 0
        sla_class = "slbr" if sla_state == "breached" else "slwarn" if sla_state == "at_risk" else "slok"
        fill_class = "fbr" if sla_state == "breached" else "fwarn" if sla_state == "at_risk" else "fok"

        alert_timestamp = case.get("alert_timestamp") or case.get("created_at", "")

        workqueue.append({
            "id": case.get("case_id") or f"SPARK-INC-{idx:04d}",
            "caseId": case.get("case_id", ""),
            "documentId": case.get("source_alert_id", ""),
            "index": case.get("source_index", ""),
            "time": alert_timestamp[11:16] or "--:--",
            "timestamp": case.get("created_at", ""),
            "alertTimestamp": alert_timestamp,
            "description": case.get("title") or "Wazuh alert",
            "level": case.get("rule_level", ""),
            "groups": [item.strip() for item in (case.get("rule_groups") or "").split(",") if item.strip()],
            "agentId": case.get("agent_id", ""),
            "agentName": case.get("agent_name", "unknown"),
            "agentIp": case.get("agent_ip", ""),
            "managerName": case.get("manager_name", ""),
            "decoderName": case.get("decoder_name", ""),
            "location": case.get("location", ""),
            "srcIp": case.get("src_ip", ""),
            "dstIp": case.get("dst_ip", ""),
            "srcPort": case.get("src_port", ""),
            "dstPort": case.get("dst_port", ""),
            "tactic": case.get("mitre_tactic") or "Detection",
            "technique": case.get("mitre_technique", ""),
            "priority": priority,
            "badge": _badge_from_priority(priority),
            "analyst": case.get("owner") or "Unassigned",
            "sla": _fmt_minutes(remaining_minutes),
            "slaPolicy": f"{policy_minutes} min",
            "createdAt": case.get("created_at", ""),
            "dueAt": case.get("due_at", ""),
            "slaState": sla_state,
            "slaClass": sla_class,
            "fillClass": fill_class,
            "slaPct": fill_pct,
            "status": status,
            "statusBadge": "bdone" if status == "Closed" else "binv" if status in {"Investigating", "Acknowledged"} else "bnew",
            "fullLog": case.get("raw_summary", ""),
            "rawEvent": raw_event,
        })

    sla_compliance = round((within_sla / measurable) * 100, 1) if measurable else None
    return workqueue, {"measurable": measurable, "within": within_sla, "compliance": sla_compliance}


def _build_posture(alert_data: dict, agents: dict, fortigate_data: dict, shuffle_data: dict, sla_summary: dict) -> dict:
    p1 = int(alert_data.get("p1", 0) or 0)
    p2 = int(alert_data.get("p2", 0) or 0)
    total_agents = int(agents.get("total", 0) or 0)
    active_agents = int(agents.get("active", 0) or 0)
    agent_ratio = (active_agents / total_agents) if total_agents else 0
    threat_detection = max(0, min(100, 100 - p1 * 18 - p2 * 5))
    wazuh_assets = round(agent_ratio * 100) if total_agents else 0
    fortigate_health = 90 if fortigate_data.get("source") == "fortigate-live" else 35
    fortigate_health -= 15 if int(fortigate_data.get("mem") or 0) >= 80 else 0
    fortigate_health -= 15 if int(fortigate_data.get("cpu") or 0) >= 80 else 0
    shuffle_score = 85 if shuffle_data.get("connected") else 35
    incident_pressure = max(0, min(100, 100 - p1 * 20 - p2 * 6))
    sla_score = sla_summary.get("compliance")
    score = round((threat_detection * 0.30) + (wazuh_assets * 0.20) + (fortigate_health * 0.20) + (shuffle_score * 0.15) + (incident_pressure * 0.15))
    rows = [
        {"name": "Threat Detection", "value": threat_detection},
        {"name": "Wazuh Assets", "value": wazuh_assets},
        {"name": "FortiGate Health", "value": max(0, fortigate_health)},
        {"name": "Shuffle SOAR", "value": shuffle_score},
        {"name": "Incident Pressure", "value": incident_pressure},
    ]
    if sla_score is not None:
        rows.append({"name": "SLA Compliance", "value": sla_score})
    return {"score": max(0, min(100, score)), "rows": rows}


# ── FortiGate Proxy ────────────────────────────────────────────────────────

@spark_bp.route("/spark/fortigate-status")
def fortigate_status():
    data = fortigate.get_resource_usage(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY)
    return jsonify(data)


@spark_bp.route("/spark/fortianalyzer/status")
def fortianalyzer_status():
    try:
        base_url, api_key = _fortianalyzer_config()
        data = fortianalyzer.get_status(base_url, api_key)
    except Exception as exc:
        data = {
            "configured": bool(getattr(config, "FORTIANALYZER_BASE_URL", "")),
            "connected": False,
            "status": "endpoint_error",
            "source": "fortianalyzer",
            "message": "FortiAnalyzer connector status is unavailable.",
            "endpoint_used": "",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return jsonify(data)


@spark_bp.route("/spark/fortianalyzer/evidence")
def fortianalyzer_evidence():
    ip = request.args.get("ip", "")
    try:
        limit = int(request.args.get("limit", 10))
    except (TypeError, ValueError):
        limit = 10
    try:
        base_url, api_key = _fortianalyzer_config()
        data = fortianalyzer.get_evidence_for_ip(base_url, api_key, ip, limit=limit)
    except Exception as exc:
        data = {
            "configured": bool(getattr(config, "FORTIANALYZER_BASE_URL", "")),
            "connected": False,
            "status": "endpoint_error",
            "source": "fortianalyzer",
            "ip": ip or "",
            "evidence_status": "endpoint_error",
            "message": "FortiAnalyzer evidence search is unavailable.",
            "log_count": 0,
            "items": [],
            "references": [],
            "error": f"{type(exc).__name__}: {exc}",
        }
    return jsonify(data)


# ── SQLite Stats ───────────────────────────────────────────────────────────

@spark_bp.route("/spark/stats")
def spark_stats():
    return jsonify(wazuh.get_stats(config.DB_PATH))


@spark_bp.route("/spark/top-ips")
def spark_top_ips():
    return jsonify(wazuh.get_top_ips(config.DB_PATH))


@spark_bp.route("/spark/timeline")
def spark_timeline():
    return jsonify(wazuh.get_timeline(config.DB_PATH))


@spark_bp.route("/spark/recent-events")
def spark_recent_events():
    return jsonify(wazuh.get_recent_events(config.DB_PATH))


@spark_bp.route("/spark/incidents")
def spark_incidents():
    return jsonify(wazuh.get_incidents(config.DB_PATH))


# ── Wazuh / OpenSearch ─────────────────────────────────────────────────────

@spark_bp.route("/spark/wazuh-alerts")
def spark_wazuh_alerts():
    try:
        data = wazuh.get_alerts_opensearch(
            config.INDEXER_BASE, config.INDEXER_USER, config.INDEXER_PASS
        )
    except Exception as exc:
        print(f"[OpenSearch] Error: {exc}")
        data = {
            "source": "offline",
            "levels": {},
            "alerts": [],
            "stats": {"total": 0, "critical": 0, "auth_failures": 0, "auth_success": 0},
            "error": str(exc),
        }
    return jsonify(data)


@spark_bp.route("/spark/wazuh-debug")
def spark_wazuh_debug():
    return jsonify(
        wazuh.get_wazuh_debug(config.WAZUH_BASE, config.WAZUH_USER, config.WAZUH_PASS)
    )


@spark_bp.route("/spark/threat-detection")
def threat_detection():
    time_range = request.args.get("range", "24h")
    search = request.args.get("q", "").strip()
    size = request.args.get("size", 100, type=int)
    filters = []
    for raw_filter in request.args.getlist("filter"):
        if ":" not in raw_filter:
            continue
        field, value = raw_filter.split(":", 1)
        field = field.strip()
        value = value.strip()
        if field and value:
            filters.append((field, value))
    try:
        data = wazuh.get_threat_detection_alerts(
            config.INDEXER_BASE,
            config.INDEXER_USER,
            config.INDEXER_PASS,
            time_range,
            search,
            filters,
            size,
        )
    except Exception as exc:
        print(f"[Threat Detection] OpenSearch error: {exc}")
        data = {
            "source": "offline",
            "range": time_range,
            "total": 0,
            "returned": 0,
            "filters": [{"field": field, "value": value} for field, value in filters],
            "search": search,
            "counts": {"p1": 0, "p2": 0, "p3": 0, "p4": 0},
            "levels": {},
            "facets": {"tactics": [], "groups": [], "decoders": []},
            "timeline": [],
            "alerts": [],
            "triage": "Wazuh Indexer is unavailable. Check INDEXER_BASE, INDEXER_USER and INDEXER_PASS.",
            "error": str(exc),
        }
    analytics = _build_risk_correlations(data.get("alerts", []))
    data["analytics"] = analytics
    if analytics.get("insights"):
        top = analytics["insights"][0]
        data["triage"] = (
            f"{data.get('triage', 'Threat analytics ready.')} "
            f"Top correlation: {top.get('title')} (risk {top.get('risk_score')}/100)."
        )
    return jsonify(data)


def _is_private_ip(value: str) -> bool:
    text = str(value or "")
    return text.startswith(("10.", "127.", "192.168.", "169.254.")) or any(
        text.startswith(f"172.{idx}.") for idx in range(16, 32)
    )


def _build_risk_correlations(alerts: list[dict]) -> dict:
    """Risk-based correlation engine: severity + frequency + asset + external IP + MITRE + FortiGate evidence."""
    blocked_ips = {item.get("ip") for item in ticket_store.get_blocked_ips() if item.get("ip")}
    now = datetime.now(timezone.utc)
    buckets: dict[str, dict] = {}

    for alert in alerts or []:
        indicator = alert.get("src_ip") or alert.get("agent_ip") or alert.get("agent_name") or "unknown"
        item = buckets.setdefault(indicator, {
            "indicator": indicator,
            "alerts": [],
            "rules": set(),
            "agents": set(),
            "mitre": set(),
            "max_level": 0,
            "external_ip": bool(indicator and not _is_private_ip(indicator) and "." in indicator),
            "fortigate_signal": indicator in blocked_ips,
        })
        level = int(alert.get("level") or 0)
        item["alerts"].append(alert)
        item["rules"].add(str(alert.get("rule_id") or ""))
        item["agents"].add(str(alert.get("agent_name") or "unknown"))
        if alert.get("mitre_tactic"):
            item["mitre"].add(str(alert.get("mitre_tactic")))
        if alert.get("mitre_technique"):
            item["mitre"].add(str(alert.get("mitre_technique")))
        item["max_level"] = max(item["max_level"], level)

    insights = []
    for indicator, item in buckets.items():
        count = len(item["alerts"])
        latest = max(
            (_parse_wazuh_timestamp(alert.get("timestamp", "")) for alert in item["alerts"]),
            default=None,
        )
        recent = bool(latest and (now - latest).total_seconds() <= 3600)
        asset_text = " ".join(item["agents"]).lower()
        critical_asset = any(term in asset_text for term in ("server", "dc", "domain", "wazuh", "firewall", "fortigate"))
        repeated_rule = count > len(item["rules"])
        brute_force = any(
            "ssh" in f"{alert.get('description', '')} {alert.get('groups', '')}".lower()
            or "authentication" in f"{alert.get('description', '')} {alert.get('groups', '')}".lower()
            for alert in item["alerts"]
        ) and count >= 3
        score = min(100, (
            min(45, item["max_level"] * 4)
            + min(20, count * 4)
            + (10 if critical_asset else 0)
            + (10 if item["external_ip"] else 0)
            + (8 if item["mitre"] else 0)
            + (7 if repeated_rule else 0)
            + (12 if item["fortigate_signal"] else 0)
        ))
        if score < 35 and count < 2:
            continue

        if item["fortigate_signal"]:
            recommendation = "IP already appears in SPARK/FortiGate blocklist evidence. Validate runtime routing before claiming enforcement."
        elif brute_force or item["external_ip"] or score >= 70:
            recommendation = "Create incident case and consider FortiGate blocklist action after analyst validation."
        elif critical_asset:
            recommendation = "Start investigation and review host evidence, because a monitored critical asset is involved."
        else:
            recommendation = "Monitor and correlate with repeated activity before containment."

        insights.append({
            "indicator": indicator,
            "title": "FortiGate blocklist + Wazuh alert correlation" if item["fortigate_signal"] else "Repeated alert cluster" if count >= 3 else "Risk-based detection insight",
            "risk_score": score,
            "severity": "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 45 else "low",
            "alert_count": count,
            "max_level": item["max_level"],
            "external_ip": item["external_ip"],
            "critical_asset": critical_asset,
            "repeated_rule": repeated_rule,
            "recent": recent,
            "mitre": sorted(item["mitre"])[:5],
            "agents": sorted(item["agents"])[:5],
            "fortigate_signal": "blocklist evidence" if item["fortigate_signal"] else "no FortiGate match",
            "recommendation": recommendation,
        })

    insights.sort(key=lambda row: (row["risk_score"], row["alert_count"]), reverse=True)
    return {
        "engine": "risk-based correlation",
        "model": "severity + frequency + critical asset + external IP + MITRE + repetition + FortiGate blocklist evidence",
        "insights": insights[:8],
        "summary": {
            "clusters": len(insights),
            "high_or_critical": sum(1 for item in insights if item["risk_score"] >= 70),
            "fortigate_matches": sum(1 for item in insights if item["fortigate_signal"] == "blocklist evidence"),
        },
    }


def _build_fortigate_correlations(alerts: list[dict], fortigate_data: dict) -> list[dict]:
    """Correlate Wazuh network indicators with live FortiGate config/monitor data."""
    policies = fortigate_data.get("policies", []) or []
    interfaces = fortigate_data.get("interfaces", []) or []
    blocked = ticket_store.get_blocked_ips()
    policy_text = " ".join(
        f"{item.get('name', '')} {item.get('srcaddr', '')} {item.get('dstaddr', '')} {item.get('service', '')} {item.get('comments', '')}"
        for item in policies
    ).lower()
    interface_names = {str(item.get("name", "")).lower() for item in interfaces if item.get("name")}
    blocked_ips = {item.get("ip") or item.get("src_ip") for item in blocked}
    rows = []
    for alert in alerts:
        src_ip = alert.get("src_ip") or alert.get("agent_ip") or ""
        dst_ip = alert.get("dst_ip") or ""
        location = str(alert.get("location") or "").lower()
        matched_interfaces = [name for name in interface_names if name and name in location]
        policy_match = bool(src_ip and src_ip.lower() in policy_text) or bool(dst_ip and dst_ip.lower() in policy_text)
        rows.append({
            "timestamp": alert.get("timestamp", ""),
            "description": alert.get("description") or "Wazuh alert",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "agent": alert.get("agent_name", ""),
            "priority": alert.get("priority", "P3"),
            "mitre_tactic": alert.get("mitre_tactic", ""),
            "fortigate_signal": "blocked" if src_ip in blocked_ips else "policy match" if policy_match else "interface context" if matched_interfaces else "no direct policy match",
            "matched_interfaces": matched_interfaces,
        })
    return rows


@spark_bp.route("/spark/network-endpoint")
def network_endpoint():
    errors: dict[str, str] = {}
    fortianalyzer_base, fortianalyzer_key = _fortianalyzer_config()
    executor = ThreadPoolExecutor(max_workers=4)
    try:
        futures = {
            "fortigate": executor.submit(
                fortigate.get_network_inventory,
                config.FORTIGATE_BASE_URL,
                config.FORTIGATE_API_KEY,
            ),
            "wazuh_agents": executor.submit(
                wazuh.get_agents_summary,
                config.WAZUH_BASE,
                config.WAZUH_USER,
                config.WAZUH_PASS,
            ),
            "alerts": executor.submit(
                wazuh.get_threat_detection_alerts,
                config.INDEXER_BASE,
                config.INDEXER_USER,
                config.INDEXER_PASS,
                "24h",
                "",
                [],
                20,
            ),
            "fortianalyzer": executor.submit(
                fortianalyzer.get_status,
                fortianalyzer_base,
                fortianalyzer_key,
            ),
        }
        try:
            fortigate_data = futures["fortigate"].result(timeout=5)
        except TimeoutError:
            fortigate_data = {"source": "offline", "cpu": 0, "mem": 0, "sessions": 0, "error": "timeout"}
        except Exception as exc:
            fortigate_data = {"source": "offline", "cpu": 0, "mem": 0, "sessions": 0, "error": str(exc)}

        try:
            agents = futures["wazuh_agents"].result(timeout=7)
        except TimeoutError:
            agents = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "agents": [], "error": "timeout"}
        except Exception as exc:
            agents = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "agents": [], "error": str(exc)}

        try:
            alert_data = futures["alerts"].result(timeout=8)
        except TimeoutError:
            alert_data = {"alerts": [], "total": 0, "error": "timeout"}
        except Exception as exc:
            alert_data = {"alerts": [], "total": 0, "error": str(exc)}

        try:
            fortianalyzer_data = futures["fortianalyzer"].result(timeout=5)
        except TimeoutError:
            fortianalyzer_data = {"configured": bool(fortianalyzer_base and fortianalyzer_key), "connected": False, "source": "fortianalyzer", "status": "timeout", "message": "FortiAnalyzer connector timed out.", "error": "timeout"}
        except Exception as exc:
            fortianalyzer_data = {"configured": bool(fortianalyzer_base and fortianalyzer_key), "connected": False, "source": "fortianalyzer", "status": "endpoint_error", "message": "FortiAnalyzer connector status is unavailable.", "error": str(exc)}
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    if fortigate_data.get("source") not in {"fortigate-live", "not_configured"}:
        errors["fortigate"] = fortigate_data.get("error", "offline")
        fortigate_data = {
            "source": "offline",
            "cpu": 0,
            "mem": 0,
            "sessions": 0,
            "error": errors["fortigate"],
        }
    if agents.get("error"):
        errors["wazuh_api"] = agents["error"]
    if alert_data.get("error"):
        errors["wazuh_indexer"] = alert_data["error"]

    agent_items = agents.get("agents", [])
    endpoint_status = {
        "total": agents.get("total", len(agent_items)),
        "active": agents.get("active", 0),
        "disconnected": agents.get("disconnected", 0),
        "pending": agents.get("pending", 0),
        "agents": agent_items,
    }
    blocked = ticket_store.get_blocked_ips()
    correlations = _build_fortigate_correlations(alert_data.get("alerts", []), fortigate_data)

    return jsonify({
        "source": "live" if not errors else "partial",
        "errors": errors,
        "fortigate": fortigate_data,
        "fortianalyzer": fortianalyzer_data,
        "wazuh": endpoint_status,
        "wazuh_alerts": {
            "total": alert_data.get("total", 0),
            "alerts": alert_data.get("alerts", []),
        },
        "correlations": correlations,
        "blocked_ips": blocked,
        "notes": {
            "sessions": "Active session count is read from FortiGate resource usage. Detailed session list depends on FortiOS endpoint availability.",
            "endpoint_agents": "Wazuh agent inventory reflects the Wazuh Manager API. Only real registered agents are shown.",
            "fortigate": "Interface, policy, route and policy-stat tables are populated only when the FortiOS REST endpoint is available to the API token.",
        },
    })


@spark_bp.route("/spark/incident-response")
def incident_response():
    time_range = request.args.get("range", "24h")
    if time_range not in EXECUTIVE_RANGES:
        time_range = "24h"
    errors: dict[str, str] = {}
    fortianalyzer_base, fortianalyzer_key = _fortianalyzer_config()
    executor = ThreadPoolExecutor(max_workers=3)
    try:
        futures = {
            "shuffle": executor.submit(
                shuffle.get_status,
                config.SHUFFLE_BASE_URL,
                config.SHUFFLE_API_KEY,
                getattr(config, "SHUFFLE_BACKEND_URL", ""),
            ),
            "alerts": executor.submit(
                wazuh.get_threat_detection_alerts,
                config.INDEXER_BASE,
                config.INDEXER_USER,
                config.INDEXER_PASS,
                time_range,
                "",
                [],
                25,
            ),
            "fortianalyzer": executor.submit(
                fortianalyzer.get_status,
                fortianalyzer_base,
                fortianalyzer_key,
            ),
        }
        try:
            shuffle_data = futures["shuffle"].result(timeout=5)
        except TimeoutError:
            shuffle_data = {"connected": False, "source": "shuffle", "error": "timeout"}
        except Exception as exc:
            shuffle_data = {"connected": False, "source": "shuffle", "error": str(exc)}

        try:
            alert_data = futures["alerts"].result(timeout=8)
        except TimeoutError:
            alert_data = {"total": 0, "alerts": [], "counts": {"p1": 0, "p2": 0, "p3": 0, "p4": 0}, "error": "timeout"}
        except Exception as exc:
            alert_data = {"total": 0, "alerts": [], "counts": {"p1": 0, "p2": 0, "p3": 0, "p4": 0}, "error": str(exc)}

        try:
            fortianalyzer_data = futures["fortianalyzer"].result(timeout=5)
        except TimeoutError:
            fortianalyzer_data = {
                "configured": bool(fortianalyzer_base and fortianalyzer_key),
                "connected": False,
                "status": "timeout",
                "source": "fortianalyzer",
                "message": "FortiAnalyzer connector timed out.",
                "error": "timeout",
            }
        except Exception as exc:
            fortianalyzer_data = {
                "configured": bool(fortianalyzer_base and fortianalyzer_key),
                "connected": False,
                "status": "endpoint_error",
                "source": "fortianalyzer",
                "message": "FortiAnalyzer connector status is unavailable.",
                "error": str(exc),
            }
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    if not shuffle_data.get("connected"):
        errors["shuffle"] = shuffle_data.get("error", "offline")
    if alert_data.get("error"):
        errors["wazuh_indexer"] = alert_data["error"]

    candidates = []
    for alert in alert_data.get("alerts", []):
        level = int(alert.get("level") or 0)
        if level < 7:
            continue
        candidates.append({
            "document_id": alert.get("document_id", ""),
            "index": alert.get("index", ""),
            "timestamp": alert.get("timestamp", ""),
            "title": alert.get("description") or "Wazuh alert",
            "priority": alert.get("priority", "P3"),
            "severity": alert.get("severity", ""),
            "level": level,
            "agent_name": alert.get("agent_name", "unknown"),
            "agent_ip": alert.get("agent_ip", ""),
            "src_ip": alert.get("src_ip", ""),
            "dst_ip": alert.get("dst_ip", ""),
            "mitre_tactic": alert.get("mitre_tactic", ""),
            "mitre_technique": alert.get("mitre_technique", ""),
            "rule_id": alert.get("rule_id", ""),
            "decoder_name": alert.get("decoder_name", ""),
            "status": "Candidate",
        })

    case_records = ticket_store.list_incident_cases(limit=25, include_closed=False)
    action_events = ticket_store.list_action_events(limit=20)

    return jsonify({
        "source": "live" if not errors else "partial",
        "range": time_range,
        "errors": errors,
        "shuffle": shuffle_data,
        "fortianalyzer": fortianalyzer_data,
        "wazuh": {
            "total": alert_data.get("total", 0),
            "counts": alert_data.get("counts", {}),
            "candidate_count": len(candidates),
            "candidates": candidates,
        },
        "playbooks": [],
        "cases": case_records,
        "timeline": action_events,
        "actions": action_events,
        "notes": {
            "playbooks": "Shuffle webhook dispatch is enabled after FortiGate block actions.",
            "timeline": "Case lifecycle actions are persisted as SPARK action events.",
            "actions": "FortiGate and Shuffle response evidence is persisted when actions execute.",
        },
    })


@spark_bp.route("/spark/compliance-risk")
def compliance_risk():
    time_range = request.args.get("range", "7d")
    if time_range not in EXECUTIVE_RANGES:
        time_range = "7d"
    errors: dict[str, str] = {}
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        futures = {
            "findings": executor.submit(
                wazuh.get_compliance_risk_events,
                config.INDEXER_BASE,
                config.INDEXER_USER,
                config.INDEXER_PASS,
                time_range,
                50,
            ),
            "agents": executor.submit(
                wazuh.get_agents_summary,
                config.WAZUH_BASE,
                config.WAZUH_USER,
                config.WAZUH_PASS,
            ),
        }
        try:
            finding_data = futures["findings"].result(timeout=8)
        except TimeoutError:
            finding_data = {"total": 0, "returned": 0, "modules": {}, "groups": {}, "levels": {}, "findings": [], "error": "timeout"}
        except Exception as exc:
            finding_data = {"total": 0, "returned": 0, "modules": {}, "groups": {}, "levels": {}, "findings": [], "error": str(exc)}

        try:
            agents = futures["agents"].result(timeout=7)
        except TimeoutError:
            agents = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "agents": [], "error": "timeout"}
        except Exception as exc:
            agents = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "agents": [], "error": str(exc)}
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    if finding_data.get("error"):
        errors["wazuh_indexer"] = finding_data["error"]
    if agents.get("error"):
        errors["wazuh_api"] = agents["error"]

    modules = {
        "sca": 0,
        "fim": 0,
        "rootcheck": 0,
        "vulnerability": 0,
        "audit": 0,
        **finding_data.get("modules", {}),
    }
    return jsonify({
        "source": "live" if not errors else "partial",
        "range": time_range,
        "errors": errors,
        "findings": finding_data.get("findings", []),
        "total_findings": finding_data.get("total", 0),
        "returned": finding_data.get("returned", 0),
        "modules": modules,
        "groups": finding_data.get("groups", {}),
        "levels": finding_data.get("levels", {}),
        "agents": {
            "total": agents.get("total", 0),
            "active": agents.get("active", 0),
            "disconnected": agents.get("disconnected", 0),
            "pending": agents.get("pending", 0),
            "items": agents.get("agents", []),
        },
        "controls": [
            {"name": "SCA policy checks", "module": "sca", "count": modules.get("sca", 0), "status": "live" if modules.get("sca", 0) else "no_data"},
            {"name": "File integrity monitoring", "module": "fim", "count": modules.get("fim", 0), "status": "live" if modules.get("fim", 0) else "no_data"},
            {"name": "Rootcheck / system audit", "module": "rootcheck", "count": modules.get("rootcheck", 0), "status": "live" if modules.get("rootcheck", 0) else "no_data"},
            {"name": "Vulnerability detector", "module": "vulnerability", "count": modules.get("vulnerability", 0), "status": "live" if modules.get("vulnerability", 0) else "no_data"},
            {"name": "Audit / policy monitoring", "module": "audit", "count": modules.get("audit", 0), "status": "live" if modules.get("audit", 0) else "no_data"},
        ],
        "notes": {
            "frameworks": "ISO/PCI/LGPD/NIST percentages are not calculated until real control mappings exist.",
            "fortigate": "FortiGate policy/configuration compliance endpoints still need endpoint discovery.",
            "agents": "SCA, FIM, rootcheck and vulnerability data require real Wazuh endpoint agents.",
        },
    })


@spark_bp.route("/spark/executive-overview")
def executive_overview():
    time_range = request.args.get("range", "24h")
    if time_range not in EXECUTIVE_RANGES:
        time_range = "24h"
    refresh = request.args.get("refresh") == "1"
    cache_key = time_range
    cached = _executive_cache.get(cache_key)
    if cached and not refresh and (time.time() - cached[0]) < EXECUTIVE_CACHE_TTL_SECONDS:
        payload = dict(cached[1])
        payload["cached"] = True
        return jsonify(payload)

    errors: dict[str, str] = {}

    fortianalyzer_base, fortianalyzer_key = _fortianalyzer_config()
    executor = ThreadPoolExecutor(max_workers=5)
    try:
        futures = {
            "wazuh_indexer": executor.submit(
                wazuh.get_executive_alerts,
                config.INDEXER_BASE,
                config.INDEXER_USER,
                config.INDEXER_PASS,
                time_range,
            ),
            "wazuh_api": executor.submit(
                wazuh.get_agents_summary,
                config.WAZUH_BASE,
                config.WAZUH_USER,
                config.WAZUH_PASS,
            ),
            "fortigate": executor.submit(
                fortigate.get_resource_usage,
                config.FORTIGATE_BASE_URL,
                config.FORTIGATE_API_KEY,
            ),
            "shuffle": executor.submit(
                shuffle.get_status,
                config.SHUFFLE_BASE_URL,
                config.SHUFFLE_API_KEY,
                getattr(config, "SHUFFLE_BACKEND_URL", ""),
            ),
            "fortianalyzer": executor.submit(
                fortianalyzer.get_status,
                fortianalyzer_base,
                fortianalyzer_key,
            ),
        }

        try:
            alert_data = futures["wazuh_indexer"].result(timeout=8)
        except TimeoutError:
            errors["wazuh_indexer"] = "timeout"
            alert_data = {"total": 0, "p1": 0, "p2": 0, "p3": 0, "alerts": [], "timeline": []}
        except Exception as exc:
            errors["wazuh_indexer"] = str(exc)
            alert_data = {"total": 0, "p1": 0, "p2": 0, "p3": 0, "alerts": [], "timeline": []}

        try:
            agents = futures["wazuh_api"].result(timeout=6)
        except TimeoutError:
            errors["wazuh_api"] = "timeout"
            agents = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "agents": []}
        except Exception as exc:
            errors["wazuh_api"] = str(exc)
            agents = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "agents": []}

        try:
            fortigate_data = futures["fortigate"].result(timeout=4)
        except TimeoutError:
            fortigate_data = {"source": "offline", "cpu": 0, "mem": 0, "sessions": 0, "error": "timeout"}
        if fortigate_data.get("source") not in {"fortigate-live", "not_configured"}:
            errors["fortigate"] = fortigate_data.get("error", "offline")

        try:
            shuffle_data = futures["shuffle"].result(timeout=4)
        except TimeoutError:
            shuffle_data = {"connected": False, "source": "shuffle", "error": "timeout"}
        if not shuffle_data.get("connected"):
            errors["shuffle"] = shuffle_data.get("error", "offline")

        try:
            fortianalyzer_data = futures["fortianalyzer"].result(timeout=5)
        except TimeoutError:
            fortianalyzer_data = {
                "configured": bool(fortianalyzer_base and fortianalyzer_key),
                "connected": False,
                "source": "fortianalyzer",
                "status": "timeout",
                "message": "FortiAnalyzer connector timed out.",
                "error": "timeout",
            }
        except Exception as exc:
            fortianalyzer_data = {
                "configured": bool(fortianalyzer_base and fortianalyzer_key),
                "connected": False,
                "source": "fortianalyzer",
                "status": "endpoint_error",
                "message": "FortiAnalyzer connector status is unavailable.",
                "error": str(exc),
            }
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    if "alert_data" not in locals():
        alert_data = {"total": 0, "p1": 0, "p2": 0, "p3": 0, "alerts": [], "timeline": []}
    if "agents" not in locals():
        agents = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "agents": []}
    if "fortigate_data" not in locals():
        fortigate_data = {"source": "offline", "cpu": 0, "mem": 0, "sessions": 0, "error": "unavailable"}
    if "shuffle_data" not in locals():
        shuffle_data = {"connected": False, "source": "shuffle", "error": "unavailable"}
    if "fortianalyzer_data" not in locals():
        fortianalyzer_data = fortianalyzer.get_status(fortianalyzer_base, fortianalyzer_key)

    alerts = alert_data.get("alerts", [])
    promoted_cases = ticket_store.promote_alerts_to_cases(alerts, SLA_POLICY_MINUTES) if alerts else []
    case_records = ticket_store.list_incident_cases(limit=100, sort="recent")
    lifecycle_metrics = ticket_store.get_incident_lifecycle_metrics()
    workqueue, sla_summary = _build_workqueue(case_records)
    posture = _build_posture(alert_data, agents, fortigate_data, shuffle_data, sla_summary)
    top_alert = alerts[0] if alerts else {}
    triage = (
        f"Wazuh Indexer: {alert_data.get('total', 0)} alerts in {time_range}. "
        f"P1: {alert_data.get('p1', 0)} | P2: {alert_data.get('p2', 0)}. "
        f"FortiGate: CPU {fortigate_data.get('cpu', 0)}%, memory {fortigate_data.get('mem', 0)}%, "
        f"{fortigate_data.get('sessions', 0)} active sessions."
    )
    if top_alert:
        triage += f" Latest alert: {top_alert.get('description', 'Wazuh alert')}."

    payload = {
        "source": "live",
        "cached": False,
        "range": time_range,
        "errors": errors,
        "kpis": {
            "critical_incidents": alert_data.get("p1", 0),
            "mttd": lifecycle_metrics.get("mttd", "N/A"),
            "mttd_detail": lifecycle_metrics.get("mttd_detail", ""),
            "mttr": lifecycle_metrics.get("mttr", "N/A"),
            "mttr_detail": lifecycle_metrics.get("mttr_detail", ""),
            "sla_compliance": sla_summary.get("compliance"),
            "sla_detail": f"{sla_summary.get('within', 0)}/{sla_summary.get('measurable', 0)} within escalation policy",
            "sla_target": 95,
            "monitored_assets": agents.get("total", 0),
            "assets_alerting": agents.get("disconnected", 0) + agents.get("pending", 0),
            "events": alert_data.get("total", 0),
            "events_24h": alert_data.get("total", 0),
        },
        "posture": posture,
        "sla": {
            "policy_minutes": SLA_POLICY_MINUTES,
            **sla_summary,
        },
        "wazuh": {
            "alerts": alerts,
            "timeline": alert_data.get("timeline", []),
            "levels": alert_data.get("levels", {}),
            "agents": agents,
        },
        "fortigate": fortigate_data,
        "fortianalyzer": fortianalyzer_data,
        "shuffle": shuffle_data,
        "triage": triage,
        "workqueue": workqueue,
        "case_lifecycle": {
            "promoted": len(promoted_cases),
            "open_cases": len(case_records),
            "total_cases": lifecycle_metrics.get("total_cases", 0),
            "closed_cases": lifecycle_metrics.get("closed_cases", 0),
            "model": "alert -> candidate -> case/workqueue -> owner/status/SLA",
        },
    }
    _executive_cache[cache_key] = (time.time(), payload)
    return jsonify(payload)


# ── Tickets CRUD ───────────────────────────────────────────────────────────

@spark_bp.route("/spark/tickets", methods=["GET"])
def list_tickets():
    status   = request.args.get("status")
    priority = request.args.get("priority")
    return jsonify(ticket_store.list_tickets(status, priority))


@spark_bp.route("/spark/tickets", methods=["POST"])
def create_ticket():
    data = request.get_json()
    if not data or not data.get("title"):
        return jsonify({"error": "Campo 'title' obrigatório"}), 400
    ticket = ticket_store.create_ticket(data)
    if (data or {}).get("syncJira"):
        result = jira.create_issue(
            config.JIRA_BASE_URL,
            config.JIRA_EMAIL,
            config.JIRA_API_TOKEN,
            config.JIRA_PROJECT_KEY,
            config.JIRA_DEFAULT_ISSUE_TYPE,
            ticket,
        )
        ticket = ticket_store.mark_ticket_sync(
            ticket["id"],
            "jira",
            result.get("key", ""),
            result.get("url", ""),
            "synced" if result.get("ok") else result.get("status", "failed"),
            result.get("message", ""),
        ) or ticket
    print(f"[TICKET] Criado: {ticket['id']} — {ticket['title'][:60]}")
    return jsonify(ticket), 201


@spark_bp.route("/spark/tickets/<ticket_id>", methods=["GET"])
def get_ticket(ticket_id):
    ticket = ticket_store.get_ticket(ticket_id)
    if not ticket:
        return jsonify({"error": "Ticket não encontrado"}), 404
    return jsonify(ticket)


@spark_bp.route("/spark/tickets/<ticket_id>", methods=["PUT"])
def update_ticket(ticket_id):
    data   = request.get_json()
    ticket = ticket_store.update_ticket(ticket_id, data)
    if not ticket:
        return jsonify({"error": "Ticket não encontrado"}), 404
    print(f"[TICKET] Atualizado: {ticket_id}")
    return jsonify(ticket)


@spark_bp.route("/spark/jira/status")
def jira_status():
    return jsonify(
        jira.status(
            config.JIRA_BASE_URL,
            config.JIRA_EMAIL,
            config.JIRA_API_TOKEN,
            config.JIRA_PROJECT_KEY,
        )
    )


@spark_bp.route("/spark/tickets/<ticket_id>/jira", methods=["POST"])
def sync_ticket_to_jira(ticket_id):
    ticket = ticket_store.get_ticket(ticket_id)
    if not ticket:
        return jsonify({"error": "Ticket não encontrado"}), 404
    result = jira.create_issue(
        config.JIRA_BASE_URL,
        config.JIRA_EMAIL,
        config.JIRA_API_TOKEN,
        config.JIRA_PROJECT_KEY,
        config.JIRA_DEFAULT_ISSUE_TYPE,
        ticket,
    )
    updated = ticket_store.mark_ticket_sync(
        ticket_id,
        "jira",
        result.get("key", ""),
        result.get("url", ""),
        "synced" if result.get("ok") else result.get("status", "failed"),
        result.get("message", ""),
    )
    status = 200 if result.get("ok") else 400
    return jsonify({"ticket": updated or ticket, "jira": result}), status


@spark_bp.route("/spark/tickets/<ticket_id>", methods=["DELETE"])
def delete_ticket(ticket_id):
    if not ticket_store.delete_ticket(ticket_id):
        return jsonify({"error": "Ticket não encontrado"}), 404
    print(f"[TICKET] Removido: {ticket_id}")
    return jsonify({"message": f"Ticket {ticket_id} removido"})


# ── IP Block / Unblock ─────────────────────────────────────────────────────

@spark_bp.route("/spark/incident-cases", methods=["GET"])
def list_incident_cases():
    include_closed = request.args.get("include_closed") == "1"
    limit = request.args.get("limit", 25, type=int)
    sort = request.args.get("sort", "recent")
    return jsonify(ticket_store.list_incident_cases(limit=limit, include_closed=include_closed, sort=sort))


@spark_bp.route("/spark/incident-cases", methods=["POST"])
def create_incident_case():
    data = request.get_json() or {}
    title = data.get("title") or data.get("description") or "Wazuh alert"
    if not title:
        return jsonify({"error": "Case title is required"}), 400

    level = int(data.get("level") or 0)
    if not level:
        level = {"P1": 12, "P2": 7, "P3": 4, "P4": 1}.get(data.get("priority", "P3"), 4)
    alert = {
        "document_id": data.get("document_id") or data.get("source_alert_id") or f"manual:{title}:{data.get('timestamp', '')}",
        "index": data.get("index", "spark-manual"),
        "timestamp": data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "description": title,
        "priority": data.get("priority") or _priority_from_level(level),
        "level": level,
        "severity": data.get("severity", ""),
        "agent_name": data.get("agent_name", "unknown"),
        "agent_id": data.get("agent_id", ""),
        "agent_ip": data.get("agent_ip", ""),
        "manager_name": data.get("manager_name", ""),
        "decoder_name": data.get("decoder_name", ""),
        "location": data.get("location", ""),
        "src_ip": data.get("src_ip", ""),
        "dst_ip": data.get("dst_ip", ""),
        "src_port": data.get("src_port", ""),
        "dst_port": data.get("dst_port", ""),
        "mitre_tactic": data.get("mitre_tactic") or "Detection",
        "mitre_technique": data.get("mitre_technique", ""),
        "rule_id": data.get("rule_id", "manual"),
        "groups": data.get("groups", []),
        "full_log": data.get("full_log") or data.get("raw_summary") or "",
        "raw": data.get("raw") or data,
    }
    cases = ticket_store.promote_alerts_to_cases([alert], SLA_POLICY_MINUTES)
    case = cases[0] if cases else None
    if not case:
        return jsonify({"error": "Case could not be created"}), 500

    action = ticket_store.record_action_event(
        case_id=case.get("case_id", ""),
        action="create_case",
        status="success",
        payload={
            "action": "create_case",
            "message": "Incident case created from detection candidate.",
            "case_id": case.get("case_id", ""),
            "ip": case.get("src_ip", ""),
            "priority": case.get("priority", ""),
            "title": case.get("title", ""),
        },
    )
    _executive_cache.clear()
    return jsonify({"case": case, "action": action}), 201


@spark_bp.route("/spark/incident-cases/<case_id>", methods=["PUT"])
def update_incident_case(case_id):
    case = ticket_store.update_incident_case(case_id, request.get_json() or {})
    if not case:
        return jsonify({"error": "Incident case not found"}), 404
    _executive_cache.clear()
    return jsonify(case)


@spark_bp.route("/spark/incident-cases/<case_id>/action", methods=["POST"])
def incident_case_action(case_id):
    data = request.get_json() or {}
    requested = (data.get("action") or "").strip()
    analyst = data.get("analyst") or "SOC"
    case = ticket_store.get_incident_case(case_id)
    if not case:
        return jsonify({"error": "Incident case not found"}), 404

    updates = {}
    action_name = requested
    message = ""
    status = "success"
    if requested == "assign":
        updates = {"owner": analyst}
        action_name = "assign_to_me"
        message = f"Case assigned to {analyst}."
    elif requested == "start":
        updates = {"status": "investigating", "owner": analyst if case.get("owner") == "Unassigned" else case.get("owner")}
        action_name = "start_investigation"
        message = "Investigation started and case acknowledged."
    elif requested == "escalate":
        to = data.get("to") or "SOC Manager"
        reason = data.get("reason") or "Escalation requested by analyst."
        action_name = "escalate_case"
        message = f"Case escalated to {to}: {reason}"
    elif requested == "close":
        updates = {"status": "closed"}
        action_name = "close_case"
        message = data.get("message") or "Case closed after analyst review."
    else:
        return jsonify({"error": "Unsupported case action"}), 400

    updated_case = ticket_store.update_incident_case(case_id, updates) if updates else case
    payload = {
        "action": action_name,
        "status": status,
        "message": message,
        "case_id": case_id,
        "analyst": analyst,
        "ip": case.get("src_ip", ""),
        "priority": case.get("priority", ""),
        "to": data.get("to", ""),
        "reason": data.get("reason", ""),
    }
    event = ticket_store.record_action_event(
        case_id=case_id,
        action=action_name,
        status=status,
        payload=payload,
    )
    _executive_cache.clear()
    return jsonify({"case": updated_case, "action": event, "message": message})


@spark_bp.route("/spark/fortigate/block-ip", methods=["POST"])
def fortigate_block_ip():
    data = request.get_json() or {}
    ip, error = _validate_block_ip(data.get("ip", ""))
    if error:
        payload, status_code = error
        return jsonify(payload), status_code

    block_cfg = _block_config()
    reason = (data.get("reason") or "Analyst requested containment").strip()
    source = (data.get("source") or "manual").strip().lower()
    if source not in {"manual", "shuffle", "wazuh", "demo"}:
        source = "manual"
    severity = (data.get("severity") or "medium").strip().lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "medium"
    try:
        duration_minutes = int(data.get("duration_minutes", 60))
    except (TypeError, ValueError):
        duration_minutes = 60
    incident_id = (data.get("incident_id") or data.get("case_id") or data.get("caseId") or "").strip()
    ticket_id = (data.get("ticket_id") or data.get("ticketId") or "").strip()

    fg_result = fortigate.block_ip(
        config.FORTIGATE_BASE_URL,
        config.FORTIGATE_API_KEY,
        ip,
        reason,
        source,
        duration_minutes,
        severity,
        incident_id,
        block_cfg["group_name"],
        block_cfg["policy_name"],
        block_cfg["srcintf"],
        block_cfg["dstintf"],
    )
    evidence_payload = {
        **fg_result,
        "action": "block",
        "reason": reason,
        "source": source,
        "severity": severity,
        "incident_id": incident_id,
        "duration_minutes": duration_minutes,
        "fortigate_object": fg_result.get("object", ""),
        "fortigate_group": block_cfg["group_name"],
        "fortigate_policy": block_cfg["policy_name"],
        "api_responses": fg_result.get("api_responses", {}),
    }
    event = _record_fortigate_evidence(
        "fortigate_block_ip",
        "success" if fg_result.get("ok") else "failed",
        evidence_payload,
        case_id=incident_id,
        ticket_id=ticket_id,
    )
    if fg_result.get("ok"):
        ticket_store.block_ip(ip, "", reason, source)
        evidence_id = event.get("id") or event.get("created_at", "")
        ml_score = {"status": "not_scored", "model_type": "deterministic_scoring_v1"}
        try:
            fa_evidence = _fortianalyzer_evidence_for_score(ip)
            ml_payload = {
                "incident": {
                    **data,
                    **evidence_payload,
                    "source_ip": ip,
                    "incident_id": incident_id,
                    "action_taken": "fortigate_block_ip",
                    "action_success": True,
                    "containment_status": "blocked",
                    "evidence_id": evidence_id,
                    "fortianalyzer": fa_evidence,
                }
            }
            ml_score = _score_and_persist_safe(ml_payload)
            evidence_payload["fortianalyzer"] = fa_evidence
            evidence_payload["ml_risk"] = {
                "risk_score": ml_score.get("risk_score"),
                "risk_band": ml_score.get("risk_band"),
                "recommended_action": ml_score.get("recommended_action"),
                "confidence": ml_score.get("confidence"),
                "model_type": ml_score.get("model_type", "deterministic_scoring_v1"),
            }
        except Exception as exc:
            ml_score = {"status": "ml_score_failed", "error": str(exc), "model_type": "deterministic_scoring_v1"}
        return jsonify({
            "status": "blocked",
            "ip": ip,
            "reason": reason,
            "object_name": fg_result.get("object", ""),
            "group_name": block_cfg["group_name"],
            "policy_name": block_cfg["policy_name"],
            "evidence_id": evidence_id,
            "ml_risk": ml_score,
            "fortigate": {
                "object_created_or_updated": bool(fg_result.get("object_created_or_updated")),
                "group_updated": bool(fg_result.get("group_updated") or fg_result.get("already_member")),
                "policy_present": bool(fg_result.get("policy_present")),
                "policy_created": bool(fg_result.get("policy_created")),
            },
            "evidence": event,
        })

    status_map = {
        "invalid_ip": 400,
        "protected_ip": 400,
        "not_configured": 503,
        "auth_failed": 401,
        "timeout": 504,
        "parse_error": 502,
        "fortigate_offline": 503,
        "object_create_failed": 502,
        "group_update_failed": 502,
        "policy_create_failed": 502,
    }
    return jsonify({
        "status": fg_result.get("status", "endpoint_error"),
        "ip": ip,
        "reason": reason,
        "message": fg_result.get("message", "FortiGate block failed."),
        "object_name": fg_result.get("object", ""),
        "group_name": block_cfg["group_name"],
        "policy_name": block_cfg["policy_name"],
        "evidence_id": event.get("id") or event.get("created_at", ""),
        "fortigate": fg_result,
        "evidence": event,
    }), status_map.get(fg_result.get("status"), 502)


@spark_bp.route("/spark/fortigate/unblock-ip", methods=["POST"])
def fortigate_unblock_ip():
    data = request.get_json() or {}
    ip, error = _validate_block_ip(data.get("ip", ""))
    if error:
        payload, status_code = error
        return jsonify(payload), status_code

    block_cfg = _block_config()
    reason = (data.get("reason") or "Analyst requested unblock").strip()
    incident_id = (data.get("incident_id") or data.get("case_id") or data.get("caseId") or "").strip()
    ticket_id = (data.get("ticket_id") or data.get("ticketId") or "").strip()
    fg_result = fortigate.unblock_ip(
        config.FORTIGATE_BASE_URL,
        config.FORTIGATE_API_KEY,
        ip,
        block_cfg["group_name"],
        delete_object=True,
    )
    evidence_payload = {
        **fg_result,
        "action": "unblock",
        "reason": reason,
        "incident_id": incident_id,
        "fortigate_object": fg_result.get("object", ""),
        "fortigate_group": block_cfg["group_name"],
        "fortigate_policy": block_cfg["policy_name"],
        "api_responses": fg_result.get("api_responses", {}),
    }
    event = _record_fortigate_evidence(
        "fortigate_unblock_ip",
        "success" if fg_result.get("ok") else "failed",
        evidence_payload,
        case_id=incident_id,
        ticket_id=ticket_id,
    )
    if fg_result.get("ok"):
        ticket_store.unblock_ip(ip, "", "SOC")
        return jsonify({
            "status": "unblocked",
            "ip": ip,
            "reason": reason,
            "object_name": fg_result.get("object", ""),
            "group_name": block_cfg["group_name"],
            "evidence_id": event.get("id") or event.get("created_at", ""),
            "fortigate": fg_result,
            "evidence": event,
        })
    status_code = 401 if fg_result.get("status") == "auth_failed" else 504 if fg_result.get("status") == "timeout" else 502
    return jsonify({
        "status": fg_result.get("status", "unblock_failed"),
        "ip": ip,
        "reason": reason,
        "message": fg_result.get("message", "FortiGate unblock failed."),
        "object_name": fg_result.get("object", ""),
        "group_name": block_cfg["group_name"],
        "evidence_id": event.get("id") or event.get("created_at", ""),
        "fortigate": fg_result,
        "evidence": event,
    }), status_code


@spark_bp.route("/spark/fortigate/blocklist")
def fortigate_blocklist():
    block_cfg = _block_config()
    try:
        fg_result = fortigate.list_blocklist(
            config.FORTIGATE_BASE_URL,
            config.FORTIGATE_API_KEY,
            block_cfg["group_name"],
        )
    except Exception as exc:
        return jsonify({"status": "endpoint_error", "message": str(exc), "items": []}), 502

    events = ticket_store.list_action_events(limit=500)
    latest_by_ip = {}
    for event in events:
        payload = event.get("payload", {})
        ip = payload.get("ip") or event.get("ip")
        if ip and ip not in latest_by_ip:
            latest_by_ip[ip] = event
    for item in fg_result.get("items", []):
        event = latest_by_ip.get(item.get("ip"), {})
        payload = event.get("payload", {}) if event else {}
        item["reason"] = payload.get("reason") or item.get("reason", "")
        item["created_at"] = event.get("created_at", "")
        item["source"] = payload.get("source", "")
        item["severity"] = payload.get("severity", "")
        item["incident_id"] = payload.get("incident_id", "")
        item["evidence_status"] = event.get("status", "")
    return jsonify(fg_result)


def _decorate_list_with_events(fg_result: dict) -> dict:
    events = ticket_store.list_action_events(limit=500)
    latest_by_ip = {}
    for event in events:
        payload = event.get("payload", {})
        ip = payload.get("ip") or event.get("ip")
        if ip and ip not in latest_by_ip:
            latest_by_ip[ip] = event
    for item in fg_result.get("items", []):
        event = latest_by_ip.get(item.get("ip"), {})
        payload = event.get("payload", {}) if event else {}
        item["reason"] = payload.get("reason") or item.get("reason", "")
        item["created_at"] = event.get("created_at", "")
        item["source"] = payload.get("source", "")
        item["severity"] = payload.get("severity", "")
        item["incident_id"] = payload.get("incident_id", "")
        item["evidence_status"] = event.get("status", "")
    return fg_result


@spark_bp.route("/spark/fortigate/quarantine-ip", methods=["POST"])
def fortigate_quarantine_ip():
    data = request.get_json() or {}
    ip, error = _validate_block_ip(data.get("ip", ""))
    if error:
        payload, status_code = error
        return jsonify(payload), status_code
    reason = (data.get("reason") or "").strip()
    if len(reason) < 10:
        return jsonify({"status": "invalid_reason", "message": "Analyst reason must have at least 10 characters.", "ip": ip}), 400

    quarantine_cfg = _quarantine_config()
    incident_id = (data.get("incident_id") or data.get("case_id") or data.get("caseId") or "").strip()
    ticket_id = (data.get("ticket_id") or data.get("ticketId") or "").strip()
    severity = (data.get("severity") or "medium").strip().lower()
    source = (data.get("source") or "manual").strip().lower()
    try:
        duration_minutes = int(data.get("duration_minutes", 60))
    except (TypeError, ValueError):
        duration_minutes = 60

    fg_result = fortigate.quarantine_ip(
        config.FORTIGATE_BASE_URL,
        config.FORTIGATE_API_KEY,
        ip,
        reason,
        source,
        duration_minutes,
        severity,
        incident_id,
        quarantine_cfg["group_name"],
        quarantine_cfg["policy_name"],
        quarantine_cfg["srcintf"],
        quarantine_cfg["dstintf"],
    )
    evidence_payload = {
        **fg_result,
        "action": "quarantine",
        "reason": reason,
        "source": source,
        "severity": severity,
        "incident_id": incident_id,
        "duration_minutes": duration_minutes,
        "fortigate_object": fg_result.get("object", ""),
        "fortigate_group": quarantine_cfg["group_name"],
        "fortigate_policy": quarantine_cfg["policy_name"],
        "api_responses": fg_result.get("api_responses", {}),
    }
    event = _record_fortigate_evidence(
        "fortigate_quarantine_ip",
        "success" if fg_result.get("ok") else "failed",
        evidence_payload,
        case_id=incident_id,
        ticket_id=ticket_id,
    )
    status_code = 200 if fg_result.get("ok") else 502
    if fg_result.get("status") in {"not_configured", "fortigate_offline"}:
        status_code = 503
    elif fg_result.get("status") == "auth_failed":
        status_code = 401
    return jsonify({
        "status": fg_result.get("status", "quarantine_failed"),
        "ip": ip,
        "reason": reason,
        "object_name": fg_result.get("object", ""),
        "group_name": quarantine_cfg["group_name"],
        "policy_name": quarantine_cfg["policy_name"],
        "evidence_id": event.get("id") or event.get("created_at", ""),
        "fortigate": {
            "object_created_or_updated": bool(fg_result.get("object_created_or_updated")),
            "group_updated": bool(fg_result.get("group_updated") or fg_result.get("already_member")),
            "policy_present": bool(fg_result.get("policy_present")),
            "policy_created": bool(fg_result.get("policy_created")),
            "reason": fg_result.get("reason", ""),
        },
        "message": fg_result.get("message", ""),
        "evidence": event,
    }), status_code


@spark_bp.route("/spark/ml/status")
def ml_status():
    try:
        return jsonify(ml_scoring.get_status())
    except Exception as exc:
        return jsonify({"ready": False, "engine": "deterministic_scoring_v1", "model_type": "deterministic", "trained_model": False, "tables_ready": False, "event_count": 0, "score_count": 0, "status": "unavailable", "message": str(exc)})


@spark_bp.route("/spark/ml/score-incident", methods=["POST"])
def ml_score_incident():
    payload = request.get_json() or {}
    payload = _with_fortianalyzer_evidence(payload, force=bool(payload.get("include_fortianalyzer")))
    score = ml_scoring.score_incident(payload)
    persisted = ml_scoring.persist_score(score)
    return jsonify(persisted), 201


@spark_bp.route("/spark/ml/insights")
def ml_insights():
    try:
        limit = min(100, max(1, int(request.args.get("limit", 25) or 25)))
    except (TypeError, ValueError):
        limit = 25
    data = ml_scoring.get_insights(limit=limit)
    try:
        recent_cases = ticket_store.list_incident_cases(limit=10, include_closed=False, sort="recent")
        data["live_candidates"] = [ml_scoring.score_incident({"case": case}) for case in recent_cases[:5]]
    except Exception:
        data["live_candidates"] = []
    return jsonify(data)


@spark_bp.route("/spark/ml/export")
def ml_export():
    fmt = (request.args.get("format") or "json").lower()
    if fmt not in {"json", "csv"}:
        return jsonify({"error": "format must be json or csv"}), 400
    body, mimetype = ml_scoring.export_dataset(fmt)
    extension = "csv" if fmt == "csv" else "json"
    return Response(body, mimetype=mimetype, headers={"Content-Disposition": f"attachment; filename=spark-ml-dataset.{extension}"})


@spark_bp.route("/spark/fortigate/unquarantine-ip", methods=["POST"])
def fortigate_unquarantine_ip():
    data = request.get_json() or {}
    ip, error = _validate_block_ip(data.get("ip", ""))
    if error:
        payload, status_code = error
        return jsonify(payload), status_code
    reason = (data.get("reason") or "").strip()
    if len(reason) < 10:
        return jsonify({"status": "invalid_reason", "message": "Analyst reason must have at least 10 characters.", "ip": ip}), 400
    quarantine_cfg = _quarantine_config()
    incident_id = (data.get("incident_id") or data.get("case_id") or data.get("caseId") or "").strip()
    fg_result = fortigate.unquarantine_ip(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY, ip, quarantine_cfg["group_name"], delete_object=True)
    event = _record_fortigate_evidence(
        "fortigate_unquarantine_ip",
        "success" if fg_result.get("ok") else "failed",
        {**fg_result, "action": "unquarantine", "reason": reason, "incident_id": incident_id, "fortigate_group": quarantine_cfg["group_name"], "fortigate_policy": quarantine_cfg["policy_name"]},
        case_id=incident_id,
    )
    return jsonify({"status": fg_result.get("status", "unquarantine_failed"), "ip": ip, "reason": reason, "object_name": fg_result.get("object", ""), "group_name": quarantine_cfg["group_name"], "policy_name": quarantine_cfg["policy_name"], "evidence_id": event.get("id"), "fortigate": fg_result, "evidence": event}), 200 if fg_result.get("ok") else 502


@spark_bp.route("/spark/fortigate/quarantine-list")
def fortigate_quarantine_list():
    quarantine_cfg = _quarantine_config()
    try:
        fg_result = fortigate.list_quarantine(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY, quarantine_cfg["group_name"])
    except Exception as exc:
        return jsonify({"status": "endpoint_error", "message": str(exc), "items": []}), 502
    return jsonify(_decorate_list_with_events(fg_result))


def _status_code_for_fortigate(result: dict) -> int:
    status = result.get("status")
    if result.get("ok") or status == "partial_success":
        return 200
    if status in {"not_configured", "fortigate_offline"}:
        return 503
    if status == "auth_failed":
        return 401
    if status == "timeout":
        return 504
    return 502


def _decorate_response_side_effects(data: dict, ip: str, incident_id: str, action_taken: str, evidence_id: str, fg_result: dict) -> dict:
    fortianalyzer_result = {"status": "not_queried", "evidence_status": "not_queried", "log_count": 0, "references": []}
    ml_score = {"status": "not_scored", "model_type": "deterministic_scoring_v1"}
    shuffle_result = {"status": "skipped", "webhook_called": False, "message": "Shuffle dispatch skipped because the FortiGate action did not succeed."}

    try:
        fortianalyzer_result = _fortianalyzer_evidence_for_score(ip)
    except Exception as exc:
        fortianalyzer_result = {"status": "evidence_pending", "evidence_status": "evidence_pending", "log_count": 0, "references": [], "message": "FortiAnalyzer lookup unavailable.", "error": str(exc)}

    try:
        ml_payload = {
            "incident": {
                **data,
                "source_ip": data.get("source_ip") or ip,
                "destination_ip": data.get("destination_ip") or (ip if action_taken == "fortigate_block_destination_ip" else ""),
                "incident_id": incident_id,
                "action_taken": action_taken,
                "action_success": bool(fg_result.get("ok")),
                "containment_status": fg_result.get("status", action_taken),
                "evidence_id": evidence_id,
                "fortigate_object": fg_result.get("object", ""),
                "fortigate_group": fg_result.get("group", ""),
                "fortigate_policy": fg_result.get("policy", ""),
                "fortianalyzer": fortianalyzer_result,
            }
        }
        ml_score = _score_and_persist_safe(ml_payload)
    except Exception as exc:
        ml_score = {"status": "ml_score_failed", "error": str(exc), "model_type": "deterministic_scoring_v1"}

    if getattr(config, "SHUFFLE_INCIDENT_WEBHOOK_URL", ""):
        try:
            soar_payload = {
                **data,
                "incident_id": incident_id,
                "source_ip": data.get("source_ip") or (ip if action_taken != "fortigate_block_destination_ip" else ""),
                "destination_ip": data.get("destination_ip") or (ip if action_taken == "fortigate_block_destination_ip" else ""),
                "recommended_action": action_taken.replace("fortigate_", ""),
                "action_taken": action_taken,
                "fortigate_object": fg_result.get("object", ""),
                "fortigate_group": fg_result.get("group", ""),
                "fortigate_policy": fg_result.get("policy", ""),
                "fortianalyzer_status": fortianalyzer_result.get("status") or fortianalyzer_result.get("evidence_status", ""),
                "fortianalyzer_log_count": fortianalyzer_result.get("log_count", 0),
                "evidence_id": evidence_id,
                "analyst_reason": data.get("analyst_reason") or data.get("reason", ""),
                "risk_score": ml_score.get("risk_score") or ml_score.get("score") or 0,
                "containment_confidence": data.get("containment_confidence", ""),
            }
            shuffle_result, _ = _soar_dispatch(soar_payload, workflow=getattr(config, "SHUFFLE_INCIDENT_WORKFLOW", "SPARK - Incident Response Evidence"))
        except Exception as exc:
            shuffle_result = {"status": "failed", "webhook_called": False, "message": "SOAR evidence dispatch unavailable.", "error": str(exc)}

    return {
        "fortianalyzer": fortianalyzer_result,
        "ml_risk": ml_score,
        "shuffle_result": shuffle_result,
    }


@spark_bp.route("/spark/fortigate/block-destination-ip", methods=["POST"])
def fortigate_block_destination_ip():
    data = request.get_json() or {}
    ip, error = _validate_block_ip(data.get("ip") or data.get("destination_ip", ""))
    if error:
        payload, status_code = error
        return jsonify(payload), status_code
    reason = (data.get("reason") or data.get("analyst_reason") or "").strip()
    if len(reason) < 10:
        return jsonify({"status": "invalid_reason", "message": "Analyst reason must have at least 10 characters.", "ip": ip}), 400

    cfg = _destination_block_config()
    incident_id = (data.get("incident_id") or data.get("case_id") or data.get("caseId") or "").strip()
    ticket_id = (data.get("ticket_id") or data.get("ticketId") or "").strip()
    source = (data.get("source") or "manual").strip().lower()
    severity = (data.get("severity") or "high").strip().lower()
    try:
        duration_minutes = int(data.get("duration_minutes", 60))
    except (TypeError, ValueError):
        duration_minutes = 60

    fg_result = fortigate.block_destination_ip(
        config.FORTIGATE_BASE_URL,
        config.FORTIGATE_API_KEY,
        ip,
        reason,
        source,
        duration_minutes,
        severity,
        incident_id,
        cfg["group_name"],
        cfg["policy_name"],
        cfg["srcaddr_name"],
        cfg["srcintf"],
        cfg["dstintf"],
    )
    evidence_payload = {
        **fg_result,
        "action": "destination_block",
        "reason": reason,
        "source": source,
        "severity": severity,
        "incident_id": incident_id,
        "duration_minutes": duration_minutes,
        "fortigate_object": fg_result.get("object", ""),
        "fortigate_group": cfg["group_name"],
        "fortigate_policy": cfg["policy_name"],
        "enforcement_path": fg_result.get("enforcement_path", ""),
        "api_responses": fg_result.get("api_responses", {}),
    }
    event = _record_fortigate_evidence(
        "fortigate_block_destination_ip",
        "success" if fg_result.get("ok") else "failed",
        evidence_payload,
        case_id=incident_id,
        ticket_id=ticket_id,
    )
    evidence_id = event.get("id") or event.get("created_at", "")
    side_effects = _decorate_response_side_effects(data, ip, incident_id, "fortigate_block_destination_ip", evidence_id, fg_result) if fg_result.get("ok") else {}

    return jsonify({
        "status": fg_result.get("status", "destination_block_failed"),
        "action": "destination_block",
        "fortigate_action": "destination_block",
        "ip": ip,
        "reason": reason,
        "object_name": fg_result.get("object", ""),
        "group_name": cfg["group_name"],
        "policy_name": cfg["policy_name"],
        "fortigate_object": fg_result.get("object", ""),
        "fortigate_group": cfg["group_name"],
        "fortigate_policy": cfg["policy_name"],
        "policy_present": bool(fg_result.get("policy_present")),
        "evidence_id": evidence_id,
        "ml_risk": side_effects.get("ml_risk", {"status": "not_scored"}),
        "fortianalyzer": side_effects.get("fortianalyzer", {"status": "not_queried", "log_count": 0}),
        "shuffle_result": side_effects.get("shuffle_result", {"status": "skipped", "webhook_called": False}),
        "enforcement_path": fg_result.get("enforcement_path", "Policy applied. Runtime enforcement depends on traffic path validation."),
        "fortigate": {
            "object_created_or_updated": bool(fg_result.get("object_created_or_updated")),
            "group_updated": bool(fg_result.get("group_updated") or fg_result.get("already_member")),
            "policy_present": bool(fg_result.get("policy_present")),
            "policy_created": bool(fg_result.get("policy_created")),
            "policy_limit_or_creation_failed": fg_result.get("reason") == "policy_limit_or_creation_failed",
        },
        "message": fg_result.get("message", ""),
        "evidence": event,
    }), _status_code_for_fortigate(fg_result)


@spark_bp.route("/spark/fortigate/unblock-destination-ip", methods=["POST"])
def fortigate_unblock_destination_ip():
    data = request.get_json() or {}
    ip, error = _validate_block_ip(data.get("ip") or data.get("destination_ip", ""))
    if error:
        payload, status_code = error
        return jsonify(payload), status_code
    reason = (data.get("reason") or data.get("analyst_reason") or "").strip()
    if len(reason) < 10:
        return jsonify({"status": "invalid_reason", "message": "Analyst reason must have at least 10 characters.", "ip": ip}), 400
    cfg = _destination_block_config()
    incident_id = (data.get("incident_id") or data.get("case_id") or data.get("caseId") or "").strip()
    fg_result = fortigate.unblock_destination_ip(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY, ip, cfg["group_name"], delete_object=True)
    event = _record_fortigate_evidence(
        "fortigate_unblock_destination_ip",
        "success" if fg_result.get("ok") else "failed",
        {**fg_result, "action": "destination_unblock", "reason": reason, "incident_id": incident_id, "fortigate_group": cfg["group_name"], "fortigate_policy": cfg["policy_name"]},
        case_id=incident_id,
    )
    return jsonify({"status": fg_result.get("status", "destination_unblock_failed"), "ip": ip, "reason": reason, "object_name": fg_result.get("object", ""), "group_name": cfg["group_name"], "policy_name": cfg["policy_name"], "evidence_id": event.get("id"), "fortigate": fg_result, "evidence": event}), _status_code_for_fortigate(fg_result)


@spark_bp.route("/spark/fortigate/destination-blocklist")
def fortigate_destination_blocklist():
    cfg = _destination_block_config()
    try:
        fg_result = fortigate.list_destination_blocklist(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY, cfg["group_name"])
    except Exception as exc:
        status = "not_configured" if "not configured" in str(exc).lower() else "endpoint_error"
        code = 200 if status == "not_configured" else 502
        return jsonify({"status": status, "message": "FortiGate destination blocklist connector is ready for configuration." if status == "not_configured" else str(exc), "items": []}), code
    return jsonify(_decorate_list_with_events(fg_result))


@spark_bp.route("/spark/block-ip", methods=["POST"])
def block_ip():
    return fortigate_block_ip()

    data    = request.get_json() or {}
    ip      = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IP não fornecido"}), 400

    country  = data.get("country", "")
    reason   = data.get("reason", "")
    analyst  = data.get("analyst", "SOC")
    case_id  = data.get("case_id", "") or data.get("caseId", "")
    ticket_id = data.get("ticket_id", "") or data.get("ticketId", "")
    group_name = getattr(config, "FORTIGATE_BLOCKLIST_GROUP", "SPARK_BLOCKLIST")
    policy_name = getattr(config, "FORTIGATE_BLOCKLIST_POLICY", "SPARK_AUTO_BLOCK")
    fg_result = fortigate.add_ip_to_blocklist(
        config.FORTIGATE_BASE_URL,
        config.FORTIGATE_API_KEY,
        ip,
        group_name,
        policy_name,
    )
    if fg_result.get("ok"):
        entry = ticket_store.block_ip(ip, country, reason, analyst)
        entry["fortigate"] = fg_result
    else:
        entry = {
            "ip": ip,
            "country": country,
            "reason": reason,
            "analyst": analyst,
            "status": "Failed",
            "fortigate": fg_result,
        }

    evidence_payload = {
        **fg_result,
        "action": "fortigate_block_ip",
        "analyst": analyst,
        "reason": reason,
        "case_id": case_id,
        "ticket_id": ticket_id,
    }
    action_event = ticket_store.record_action_event(
        case_id=case_id,
        ticket_id=ticket_id,
        action="fortigate_block_ip",
        status="success" if fg_result.get("ok") else "failure",
        payload=evidence_payload,
    )
    workflow = getattr(config, "SHUFFLE_INCIDENT_WORKFLOW", "SPARK - Incident Response Evidence")
    shuffle_result = {
        "ok": False,
        "webhook_called": False,
        "status": "skipped",
        "workflow": workflow,
        "message": "Shuffle dispatch skipped because the FortiGate action did not succeed.",
    }
    shuffle_event = None
    if fg_result.get("ok"):
        shuffle_payload = {
            "success": True,
            "source": "SPARK SOC",
            "workflow": workflow,
            "message": "Incident response evidence registered in Shuffle.",
            "playbook_type": "Block an IP",
            "case_id": case_id,
            "ticket_id": ticket_id,
            "title": data.get("title") or reason or "FortiGate blocklist response",
            "priority": data.get("priority", ""),
            "src_ip": ip,
            "analyst": analyst,
            "action": "fortigate_block_ip",
            "fortigate_object": fg_result.get("object", ""),
            "fortigate_group": fg_result.get("group", group_name),
            "fortigate_policy": fg_result.get("policy", policy_name),
            "enforcement_path": fg_result.get("enforcement_path", "containment pending traffic-path validation"),
        }
        shuffle_result = shuffle.dispatch_incident_evidence(
            getattr(config, "SHUFFLE_INCIDENT_WEBHOOK_URL", ""),
            workflow,
            shuffle_payload,
        )
        shuffle_event = ticket_store.record_action_event(
            case_id=case_id,
            ticket_id=ticket_id,
            action="shuffle_playbook_dispatch",
            status="success" if shuffle_result.get("ok") else "failure",
            payload={
                "action": "shuffle_playbook_dispatch",
                "status": "success" if shuffle_result.get("ok") else "failure",
                "ip": ip,
                "message": shuffle_result.get("message", ""),
                "shuffle_webhook_called": shuffle_result.get("webhook_called", False),
                "shuffle_status_code": shuffle_result.get("status_code"),
                "shuffle_workflow": shuffle_result.get("workflow", ""),
                "shuffle_message": shuffle_result.get("message", ""),
                "sent_payload": shuffle_payload,
                "error": shuffle_result.get("error", ""),
                "enforcement_path": fg_result.get("enforcement_path", "containment pending traffic-path validation"),
            },
        )
    status = 200 if fg_result.get("ok") else 400
    print(f"[SPARK] FortiGate blocklist action for {ip}: {fg_result.get('status')}")
    return jsonify({
        "message": fg_result.get("message") or "FortiGate blocklist action failed.",
        "entry": entry,
        "fortigate": fg_result,
        "shuffle": shuffle_result,
        "action": action_event,
        "shuffle_action": shuffle_event,
    }), status


@spark_bp.route("/spark/unblock-ip", methods=["POST"])
def unblock_ip():
    return fortigate_unblock_ip()

    data    = request.get_json()
    ip      = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IP não fornecido"}), 400

    analyst  = data.get("analyst", "SOC")
    country  = data.get("country", "")
    log_entry = ticket_store.unblock_ip(ip, country, analyst)
    fortigate.delete_address_object(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY, ip)
    print(f"[SPARK] IP desbloqueado: {ip}")
    return jsonify({"message": f"IP {ip} desbloqueado", "entry": log_entry})


@spark_bp.route("/spark/blocked-ips")
def blocked_ips():
    return jsonify(ticket_store.get_blocked_ips())


@spark_bp.route("/spark/ip-block-log")
def ip_block_log():
    return jsonify(ticket_store.get_ip_block_log())


@spark_bp.route("/spark/action-events")
def action_events():
    limit = request.args.get("limit", 25, type=int)
    case_id = request.args.get("case_id", "")
    ticket_id = request.args.get("ticket_id", "")
    return jsonify(ticket_store.list_action_events(limit=limit, case_id=case_id, ticket_id=ticket_id))


def _local_ioc_enrichment(source_ip: str, incident_id: str = "", context: dict | None = None) -> dict:
    context = context or {}
    source_ip = (source_ip or "").strip()
    try:
        parsed = ipaddress.ip_address(source_ip)
        private_ip = parsed.is_private
        if parsed.is_private:
            ip_type = "private"
        elif parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
            ip_type = "reserved"
        else:
            ip_type = "public"
    except ValueError:
        parsed = None
        private_ip = False
        ip_type = "invalid"
    events = ticket_store.list_action_events(limit=1000)
    repeated_source = repeated_destination = previous_blocks = previous_destination_blocks = previous_quarantine = 0
    for event in events:
        payload = event.get("payload", {})
        if (payload.get("ip") or event.get("ip")) != source_ip:
            continue
        action = str(event.get("action") or payload.get("action") or "").lower()
        is_destination = "destination" in action or payload.get("action") == "destination_block"
        if is_destination:
            repeated_destination += 1
            previous_destination_blocks += 1 if "block" in action else 0
        else:
            repeated_source += 1
            previous_blocks += 1 if "block" in action else 0
        previous_quarantine += 1 if "quarantine" in action else 0
    allowlist = {item.strip() for item in str(getattr(config, "SPARK_ALLOWLIST_IPS", "")).split(",") if item.strip()}
    allowlisted = source_ip in allowlist
    severity = str(context.get("severity") or "").lower()
    alert_count = int(context.get("alert_count") or 0) if str(context.get("alert_count") or "").isdigit() else 0
    text_context = " ".join(str(context.get(key, "")) for key in ("title", "mitre", "description", "context", "recommended_action")).lower()
    reasons = []
    if ip_type == "invalid":
        recommended = "monitor"
        direction = "monitor"
        reasons.append("Invalid IP address supplied.")
    elif allowlisted or source_ip in PROTECTED_BLOCK_IPS or ip_type == "reserved":
        recommended = "monitor"
        direction = "monitor"
        reasons.append("IP is allowlisted, reserved, or belongs to protected control-plane scope.")
    elif ip_type == "public" and any(term in text_context for term in ("c2", "phishing", "malicious destination", "egress", "destination", "threat intel", "threat-intel")):
        recommended = "destination_block"
        direction = "destination_block"
        reasons.append("Public IOC appears in destination/threat-intel context; egress containment is preferred.")
    elif ip_type == "public" and severity in {"high", "critical"} and alert_count >= 10:
        recommended = "destination_block"
        direction = "destination_block"
        reasons.append("High severity with repeated alerts against a public IOC supports destination containment.")
    elif previous_destination_blocks:
        recommended = "destination_block"
        direction = "destination_block"
        reasons.append("IOC was previously added to the egress blocklist.")
    elif previous_blocks or repeated_source >= 3:
        recommended = "source_block"
        direction = "source_block"
        reasons.append("Repeated source activity was observed in local action evidence.")
    elif private_ip and any(term in text_context for term in ("brute force", "inbound", "source", "lateral")):
        recommended = "source_block" if severity in {"high", "critical"} else "quarantine"
        direction = "source_block" if recommended == "source_block" else "monitor"
        reasons.append("Private IOC appears in inbound/source response context and requires analyst review.")
    elif previous_quarantine or repeated_source:
        recommended = "quarantine"
        direction = "monitor"
        reasons.append("Local evidence shows prior related activity, but containment confidence is incomplete.")
    else:
        recommended = "monitor"
        direction = "monitor"
        reasons.append("No confirmed local reputation or containment history is available.")
    return {
        "ip": source_ip,
        "source_ip": source_ip,
        "incident_id": incident_id,
        "ip_type": ip_type,
        "private_ip": private_ip,
        "direction_recommendation": direction,
        "repeated_source_count": repeated_source,
        "repeated_destination_count": repeated_destination,
        "previously_blocked": previous_blocks > 0,
        "previously_destination_blocked": previous_destination_blocks > 0,
        "previous_blocks": previous_blocks,
        "previously_quarantined": previous_quarantine > 0,
        "allowlisted": allowlisted,
        "recommended_action": recommended,
        "reasons": reasons,
        "enrichment_source": "local",
        "external_enrichment_ready": bool(getattr(config, "ABUSEIPDB_API_KEY", "") or getattr(config, "OTX_API_KEY", "")),
        "reputation_score": None,
        "abuse_confidence": None,
        "threat_intel_source": None,
        "asn": None,
        "country": None,
        "external": {},
    }


def _soar_dispatch(payload: dict, workflow: str = "", webhook_url: str = "") -> tuple[dict, dict]:
    workflow = workflow or getattr(config, "SHUFFLE_INCIDENT_WORKFLOW", "SPARK - Incident Response Evidence")
    webhook_url = webhook_url or getattr(config, "SHUFFLE_INCIDENT_WEBHOOK_URL", "")
    payload_hash = _payload_hash(payload)
    evidence_id = payload.get("evidence_id") or f"EVD-SOAR-{int(time.time())}"
    if not webhook_url:
        result = {"ok": False, "status": "connector_ready", "dispatch_status": "connector_ready", "workflow": workflow, "webhook_called": False, "payload_hash": payload_hash, "evidence_id": evidence_id, "message": "Shuffle evidence webhook is ready for configuration."}
    else:
        result = shuffle.dispatch_incident_evidence(webhook_url, workflow, {**payload, "workflow": workflow, "payload_hash": payload_hash})
        response = result.get("response") if isinstance(result.get("response"), dict) else {}
        result.update({"dispatch_status": "sent" if result.get("ok") else "failed", "payload_hash": payload_hash, "evidence_id": evidence_id, "execution_id": response.get("execution_id") or response.get("id") or response.get("execution") or ""})
    event = ticket_store.record_action_event(
        case_id=payload.get("incident_id", ""),
        action="shuffle_soar_dispatch",
        status="success" if result.get("ok") else result.get("status", "connector_ready"),
        payload={"action": "shuffle_soar_dispatch", "workflow_name": workflow, "execution_id": result.get("execution_id", ""), "dispatch_status": result.get("dispatch_status") or result.get("status"), "payload_hash": payload_hash, "evidence_id": evidence_id, "ip": payload.get("source_ip", ""), "message": result.get("message", "")},
    )
    return result, event


@spark_bp.route("/spark/soar/status")
def soar_status():
    status = shuffle.get_status(config.SHUFFLE_BASE_URL, config.SHUFFLE_API_KEY, getattr(config, "SHUFFLE_BACKEND_URL", ""))
    status["evidence_webhook_configured"] = bool(getattr(config, "SHUFFLE_INCIDENT_WEBHOOK_URL", ""))
    status["notification_webhook_configured"] = bool(_notification_webhook())
    return jsonify(status)


@spark_bp.route("/spark/soar/dispatch-evidence", methods=["POST"])
def soar_dispatch_evidence():
    try:
        result, event = _soar_dispatch(request.get_json() or {})
        return jsonify({**result, "action_log_id": event.get("id"), "action_log": event})
    except Exception as exc:
        return jsonify({"status": "failed", "message": "SOAR evidence dispatch unavailable.", "error": f"{type(exc).__name__}: {exc}"}), 200


@spark_bp.route("/spark/soar/notify-analyst", methods=["POST"])
def soar_notify_analyst():
    data = request.get_json() or {}
    notification = {
        "type": "analyst_notification",
        "incident_id": data.get("incident_id", ""),
        "title": data.get("title") or "SPARK SOC incident requires analyst review",
        "severity": data.get("severity", "requires review"),
        "risk_score": data.get("risk_score", ""),
        "recommended_action": data.get("recommended_action", "monitor"),
        "source_ip": data.get("source_ip", ""),
        "destination_ip": data.get("destination_ip", ""),
        "target": data.get("target", ""),
        "evidence_id": data.get("evidence_id", ""),
        "fortigate_action": data.get("fortigate_action") or data.get("action_taken") or "",
        "fortianalyzer_status": data.get("fortianalyzer_status", ""),
        "dashboard_link": data.get("dashboard_link") or _dashboard_link(),
        "message": f"{data.get('severity', 'Review').upper()} - {data.get('title', 'Incident')} | Source {data.get('source_ip', '--')} | Destination {data.get('destination_ip', '--')} | Action {data.get('recommended_action', 'monitor')} | Evidence {data.get('evidence_id', '--')}",
    }
    try:
        result, event = _soar_dispatch(notification, workflow="SPARK - Notify Analyst", webhook_url=_notification_webhook())
        raw_status = result.get("status", "connector_ready")
        status = "sent" if result.get("ok") else raw_status if raw_status in {"connector_ready", "auth_required", "auth_failed"} else "failed"
        return jsonify({**result, "status": status, "webhook_called": bool(result.get("webhook_called")), "execution_id": result.get("execution_id", ""), "message": result.get("message", ""), "payload_hash": result.get("payload_hash", ""), "notification": notification, "action_log_id": event.get("id")})
    except Exception as exc:
        return jsonify({"status": "failed", "message": "Analyst notification unavailable.", "error": f"{type(exc).__name__}: {exc}"}), 200


@spark_bp.route("/spark/soar/enrich-ioc", methods=["POST"])
def soar_enrich_ioc():
    data = request.get_json() or {}
    ip = data.get("ip") or data.get("source_ip") or data.get("destination_ip") or ""
    return jsonify(_local_ioc_enrichment(ip, data.get("incident_id", ""), data.get("context") if isinstance(data.get("context"), dict) else data))


@spark_bp.route("/spark/response/recommendation", methods=["GET", "POST"])
def response_recommendation():
    data = request.get_json(silent=True) or request.args.to_dict()
    source_ip = data.get("source_ip", "")
    enrichment = _local_ioc_enrichment(source_ip, data.get("incident_id", ""), data) if source_ip else {}
    recommendation = response_engine.recommend({**data, **enrichment})
    return jsonify({"status": "success", "recommendation": recommendation, "enrichment": enrichment})


@spark_bp.route("/spark/response/execute", methods=["POST"])
def response_execute():
    data = request.get_json() or {}
    action = (data.get("recommended_action") or data.get("action") or "").strip().lower()
    ip = (data.get("source_ip") or data.get("ip") or "").strip()
    reason = (data.get("analyst_reason") or data.get("reason") or "").strip()
    if action not in {"monitor", "quarantine", "block"}:
        return jsonify({"status": "invalid_action", "message": "Action must be monitor, quarantine or block."}), 400
    if data.get("approval_confirmed") is not True:
        return jsonify({"status": "approval_required", "message": "Analyst approval is required before execution."}), 400
    if len(reason) < 10:
        return jsonify({"status": "invalid_reason", "message": "Analyst reason must have at least 10 characters."}), 400
    if action in {"quarantine", "block"}:
        valid_ip, error = _validate_block_ip(ip)
        if error:
            payload, status_code = error
            return jsonify(payload), status_code
        ip = valid_ip
    incident_id = data.get("incident_id", "")
    enrichment = _local_ioc_enrichment(ip, incident_id, data) if ip else {}
    recommendation = response_engine.recommend({**data, **enrichment, "source_ip": ip})
    fortigate_result = {"status": "not_required", "message": "Monitor action recorded; no FortiGate change executed.", "ok": True}
    if action == "quarantine":
        q_cfg = _quarantine_config()
        fortigate_result = fortigate.quarantine_ip(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY, ip, reason, "manual", int(data.get("duration_minutes") or 60), data.get("severity", "medium"), incident_id, q_cfg["group_name"], q_cfg["policy_name"], q_cfg["srcintf"], q_cfg["dstintf"])
    elif action == "block":
        b_cfg = _block_config()
        fortigate_result = fortigate.block_ip(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY, ip, reason, "manual", int(data.get("duration_minutes") or 60), data.get("severity", "high"), incident_id, b_cfg["group_name"], b_cfg["policy_name"], b_cfg["srcintf"], b_cfg["dstintf"])
    fortianalyzer_result = fortianalyzer.get_evidence_for_ip(*_fortianalyzer_config(), ip, limit=10) if ip else {"status": "no_ip", "log_count": 0, "references": []}
    ml_score = _score_and_persist_safe({"incident": {**data, "source_ip": ip, "incident_id": incident_id, "action_taken": action, "action_success": bool(fortigate_result.get("ok")), "containment_status": fortigate_result.get("status", action), "fortigate_object": fortigate_result.get("object", ""), "fortigate_group": fortigate_result.get("group", ""), "fortigate_policy": fortigate_result.get("policy", ""), "fortianalyzer": fortianalyzer_result}})
    event = ticket_store.record_action_event(case_id=incident_id, action=f"response_{action}", status="success" if fortigate_result.get("ok") else "failed", payload={**data, "action": f"response_{action}", "ip": ip, "reason": reason, "recommendation": recommendation, "fortigate": fortigate_result, "fortianalyzer": fortianalyzer_result, "automation_mode": "analyst_approved", "approval_confirmed": True})
    evidence_id = event.get("id") or event.get("created_at", "")
    soar_payload = {**data, "incident_id": incident_id, "source_ip": ip, "recommended_action": action, "action_taken": action, "fortigate_object": fortigate_result.get("object", ""), "fortigate_group": fortigate_result.get("group", ""), "fortigate_policy": fortigate_result.get("policy", ""), "fortianalyzer_status": fortianalyzer_result.get("status", ""), "fortianalyzer_log_count": fortianalyzer_result.get("log_count", 0), "evidence_id": evidence_id, "analyst_reason": reason, "risk_score": recommendation.get("risk_score"), "containment_confidence": data.get("containment_confidence", "")}
    shuffle_result, shuffle_event = _soar_dispatch(soar_payload, workflow=recommendation.get("playbook", "SPARK - Analyst Approved Response"))
    return jsonify({"status": "executed", "recommendation": recommendation, "ml_risk": ml_score, "fortigate_result": fortigate_result, "shuffle_result": shuffle_result, "fortianalyzer_result": fortianalyzer_result, "evidence_id": evidence_id, "action_log_id": event.get("id"), "shuffle_action_log_id": shuffle_event.get("id")})


# ── Escalação ──────────────────────────────────────────────────────────────

@spark_bp.route("/spark/escalate", methods=["POST"])
def escalate():
    data      = request.get_json()
    ticket_id = data.get("ticket_id", "")
    to        = data.get("to", "")
    reason    = data.get("reason", "")
    analyst   = data.get("analyst", "SOC")

    if not ticket_id or not to:
        return jsonify({"error": "ticket_id e to são obrigatórios"}), 400

    entry = ticket_store.escalate(ticket_id, to, reason, analyst)
    print(f"[ESCALATE] {ticket_id} → {to} — {reason[:40]}")
    return jsonify({"message": f"Ticket {ticket_id} escalonado para {to}", "entry": entry})


@spark_bp.route("/spark/escalation-log")
def escalation_log():
    return jsonify(ticket_store.get_escalation_log())


# ── IA Proxy ───────────────────────────────────────────────────────────────

@spark_bp.route("/spark/ai/autofill", methods=["POST"])
def ai_autofill():
    body    = request.get_json()
    context = (body or {}).get("context", "")
    if not context:
        return jsonify({"error": "Campo 'context' obrigatório"}), 400

    result, status = ai_proxy.autofill_anthropic(
        config.ANTHROPIC_API_KEY, config.ANTHROPIC_MODEL, context
    )
    return jsonify(result), status


@spark_bp.route("/spark/ai/autofill-local", methods=["POST"])
def ai_autofill_local():
    body    = request.get_json()
    context = (body or {}).get("context", "")
    if not context:
        return jsonify({"error": "Campo 'context' obrigatório"}), 400

    result, status = ai_proxy.autofill_ollama(
        config.OLLAMA_BASE, config.OLLAMA_MODEL, context
    )
    return jsonify(result), status


@spark_bp.route("/spark/ai/status")
def ai_status():
    return jsonify(
        ai_proxy.check_status(
            config.ANTHROPIC_API_KEY, config.ANTHROPIC_MODEL,
            config.OLLAMA_BASE, config.OLLAMA_MODEL,
            getattr(config, "AI_PROVIDER", "none"),
            getattr(config, "GEMINI_API_KEY", ""),
            getattr(config, "GROQ_API_KEY", ""),
            getattr(config, "DEEPSEEK_API_KEY", ""),
            getattr(config, "GROQ_MODEL", "") or getattr(config, "AI_MODEL", ""),
        )
    )


@spark_bp.route("/spark/ai/incident-briefing", methods=["POST"])
def ai_incident_briefing():
    body = request.get_json(silent=True) or {}
    result = ai_proxy.generate_ai_incident_briefing(
        body,
        provider=getattr(config, "AI_PROVIDER", "none"),
        groq_api_key=getattr(config, "GROQ_API_KEY", ""),
        groq_model=getattr(config, "GROQ_MODEL", "") or getattr(config, "AI_MODEL", "") or "llama-3.1-8b-instant",
    )
    return jsonify(result)


# ── FortiOS Compatibility Endpoints ───────────────────────────────

@spark_bp.route("/api/v2/monitor/firewall/session")
def fortios_sessions_compat():
    sessions = fortigate.get_active_sessions(
        config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY
    )
    return jsonify({"http_method": "GET", "results": sessions, "vdom": "root", "status": "success"})


@spark_bp.route("/api/v2/monitor/system/resource/usage")
def fortios_resources_compat():
    data = fortigate.get_resource_usage(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY)
    return jsonify({"results": {
        "cpu":     [{"current": data["cpu"]}],
        "mem":     [{"current": data["mem"]}],
        "session": [{"current": data["sessions"]}],
    }, "status": "success"})


@spark_bp.route("/api/v2/cmdb/firewall/address", methods=["POST", "GET"])
def fortios_address_compat():
    if request.method == "POST":
        data = request.get_json()
        print(f"[FortiOS Compatibility] Address object: {data}")
        return jsonify({"status": "success", "data": data}), 200
    return jsonify({"status": "success", "blocked": ticket_store.get_blocked_ips()})

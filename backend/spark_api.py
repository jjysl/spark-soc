"""
SPARK SOC — API Blueprint /spark/*
=====================================
Todos os endpoints do dashboard agrupados num Blueprint Flask.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
import json
import time

from flask import Blueprint, jsonify, request

import config
from backend import tickets as ticket_store
from backend import fortigate, wazuh, ai_proxy, shuffle, jira

spark_bp = Blueprint("spark", __name__)

EXECUTIVE_RANGES = {"1h", "6h", "24h", "7d", "30d"}
SLA_POLICY_MINUTES = {"P1": 15, "P2": 45, "P3": 90, "P4": 360}
EXECUTIVE_CACHE_TTL_SECONDS = 20
_executive_cache: dict[str, tuple[float, dict]] = {}


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
    executor = ThreadPoolExecutor(max_workers=3)
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
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    if fortigate_data.get("source") != "fortigate-live":
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
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        futures = {
            "shuffle": executor.submit(
                shuffle.get_status,
                config.SHUFFLE_BASE_URL,
                config.SHUFFLE_API_KEY,
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

    executor = ThreadPoolExecutor(max_workers=4)
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
        if fortigate_data.get("source") != "fortigate-live":
            errors["fortigate"] = fortigate_data.get("error", "offline")

        try:
            shuffle_data = futures["shuffle"].result(timeout=4)
        except TimeoutError:
            shuffle_data = {"connected": False, "source": "shuffle", "error": "timeout"}
        if not shuffle_data.get("connected"):
            errors["shuffle"] = shuffle_data.get("error", "offline")
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


@spark_bp.route("/spark/block-ip", methods=["POST"])
def block_ip():
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
    policy_name = getattr(config, "FORTIGATE_BLOCKLIST_POLICY", "SPARK_BLOCKLIST_DENY")
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
            "enforcement_path": fg_result.get("enforcement_path", "pending network routing validation"),
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
                "enforcement_path": fg_result.get("enforcement_path", "pending network routing validation"),
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
        )
    )


# ── FortiOS Mock Endpoints (compatibilidade) ───────────────────────────────

@spark_bp.route("/api/v2/monitor/firewall/session")
def mock_sessions():
    sessions = fortigate.get_active_sessions(
        config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY
    )
    return jsonify({"http_method": "GET", "results": sessions, "vdom": "root", "status": "success"})


@spark_bp.route("/api/v2/monitor/system/resource/usage")
def mock_resources():
    data = fortigate.get_resource_usage(config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY)
    return jsonify({"results": {
        "cpu":     [{"current": data["cpu"]}],
        "mem":     [{"current": data["mem"]}],
        "session": [{"current": data["sessions"]}],
    }, "status": "success"})


@spark_bp.route("/api/v2/cmdb/firewall/address", methods=["POST", "GET"])
def mock_fw_address():
    if request.method == "POST":
        data = request.get_json()
        print(f"[MOCK FortiGate] Address object: {data}")
        return jsonify({"status": "success", "data": data}), 200
    return jsonify({"status": "success", "blocked": ticket_store.get_blocked_ips()})

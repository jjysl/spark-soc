"""
SPARK SOC — API Blueprint /spark/*
=====================================
Todos os endpoints do dashboard agrupados num Blueprint Flask.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
import time

from flask import Blueprint, jsonify, request

import config
from backend import tickets as ticket_store
from backend import fortigate, wazuh, ai_proxy, shuffle

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

        workqueue.append({
            "id": case.get("case_id") or f"SPARK-INC-{idx:04d}",
            "caseId": case.get("case_id", ""),
            "documentId": case.get("source_alert_id", ""),
            "index": case.get("source_index", ""),
            "time": (case.get("created_at") or "")[11:16] or "--:--",
            "timestamp": case.get("created_at", ""),
            "alertTimestamp": case.get("alert_timestamp", ""),
            "description": case.get("title") or "Wazuh alert",
            "level": "",
            "groups": [],
            "agentId": "",
            "agentName": case.get("agent_name", "unknown"),
            "agentIp": case.get("agent_ip", ""),
            "managerName": "",
            "decoderName": "",
            "location": "",
            "srcIp": case.get("src_ip", ""),
            "dstIp": case.get("dst_ip", ""),
            "srcPort": "",
            "dstPort": "",
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
    return jsonify(data)


@spark_bp.route("/spark/network-endpoint")
def network_endpoint():
    errors: dict[str, str] = {}
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        futures = {
            "fortigate": executor.submit(
                fortigate.get_resource_usage,
                config.FORTIGATE_BASE_URL,
                config.FORTIGATE_API_KEY,
            ),
            "wazuh_agents": executor.submit(
                wazuh.get_agents_summary,
                config.WAZUH_BASE,
                config.WAZUH_USER,
                config.WAZUH_PASS,
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

    agent_items = agents.get("agents", [])
    endpoint_status = {
        "total": agents.get("total", len(agent_items)),
        "active": agents.get("active", 0),
        "disconnected": agents.get("disconnected", 0),
        "pending": agents.get("pending", 0),
        "agents": agent_items,
    }
    blocked = ticket_store.get_blocked_ips()
    return jsonify({
        "source": "live" if not errors else "partial",
        "errors": errors,
        "fortigate": fortigate_data,
        "wazuh": endpoint_status,
        "blocked_ips": blocked,
        "notes": {
            "sessions": "FortiGate session endpoint is not enabled for this page until validated in the lab.",
            "endpoint_agents": "Wazuh agent inventory reflects the Wazuh Manager API. Only real registered agents are shown.",
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
        "timeline": [],
        "actions": [],
        "notes": {
            "playbooks": "Shuffle workflow listing/execution endpoints still need lab validation.",
            "timeline": "Incident lifecycle timestamps are not persisted yet.",
            "actions": "FortiGate/SOAR action execution logs are not persisted yet.",
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
    case_records = ticket_store.list_incident_cases(limit=100)
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
    return jsonify(ticket_store.list_incident_cases(limit=limit, include_closed=include_closed))


@spark_bp.route("/spark/incident-cases/<case_id>", methods=["PUT"])
def update_incident_case(case_id):
    case = ticket_store.update_incident_case(case_id, request.get_json() or {})
    if not case:
        return jsonify({"error": "Incident case not found"}), 404
    _executive_cache.clear()
    return jsonify(case)


@spark_bp.route("/spark/block-ip", methods=["POST"])
def block_ip():
    data    = request.get_json()
    ip      = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IP não fornecido"}), 400

    country  = data.get("country", "")
    reason   = data.get("reason", "")
    analyst  = data.get("analyst", "SOC")

    entry     = ticket_store.block_ip(ip, country, reason, analyst)
    fg_result = fortigate.create_address_object(
        config.FORTIGATE_BASE_URL, config.FORTIGATE_API_KEY, ip
    )
    print(f"[SPARK] IP bloqueado: {ip} — FortiGate: {fg_result}")
    return jsonify({"message": f"IP {ip} bloqueado com sucesso", "entry": entry, "fortigate": fg_result})


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

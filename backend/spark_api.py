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


def _build_workqueue(alerts: list[dict]) -> tuple[list[dict], dict]:
    now = datetime.now(timezone.utc)
    workqueue = []
    within_sla = 0
    measurable = 0

    for idx, alert in enumerate(alerts[:25], start=1):
        level = int(alert.get("level") or 0)
        priority = _priority_from_level(level)
        policy_minutes = SLA_POLICY_MINUTES[priority]
        timestamp = _parse_wazuh_timestamp(alert.get("timestamp", ""))
        age_minutes = 0
        remaining_minutes = policy_minutes
        sla_state = "unknown"
        if timestamp:
            measurable += 1
            age_minutes = max(0, int((now - timestamp).total_seconds() // 60))
            remaining_minutes = policy_minutes - age_minutes
            sla_state = "breached" if remaining_minutes < 0 else "at_risk" if remaining_minutes <= max(5, policy_minutes * 0.25) else "within"
            if remaining_minutes >= 0:
                within_sla += 1

        status = "SLA Breached" if sla_state == "breached" else "Investigating" if priority in {"P1", "P2"} else "New"
        fill_pct = max(5, min(100, int((age_minutes / policy_minutes) * 100))) if policy_minutes else 0
        sla_class = "slbr" if sla_state == "breached" else "slwarn" if sla_state == "at_risk" else "slok"
        fill_class = "fbr" if sla_state == "breached" else "fwarn" if sla_state == "at_risk" else "fok"

        workqueue.append({
            "id": f"WAZUH-{str(alert.get('rule_id') or idx).zfill(4)}",
            "documentId": alert.get("document_id", ""),
            "index": alert.get("index", ""),
            "time": (alert.get("timestamp") or "")[11:16] or "--:--",
            "timestamp": alert.get("timestamp", ""),
            "description": alert.get("description") or "Wazuh alert",
            "level": level,
            "groups": alert.get("groups", []),
            "agentId": alert.get("agent_id", ""),
            "agentName": alert.get("agent_name", "unknown"),
            "agentIp": alert.get("agent_ip", ""),
            "managerName": alert.get("manager_name", ""),
            "decoderName": alert.get("decoder_name", ""),
            "location": alert.get("location", ""),
            "srcIp": alert.get("src_ip", ""),
            "dstIp": alert.get("dst_ip", ""),
            "srcPort": alert.get("src_port", ""),
            "dstPort": alert.get("dst_port", ""),
            "tactic": alert.get("mitre_tactic") or "Detection",
            "technique": alert.get("mitre_technique", ""),
            "priority": priority,
            "badge": _badge_from_priority(priority),
            "analyst": "Unassigned",
            "sla": _fmt_minutes(remaining_minutes),
            "slaPolicy": f"{policy_minutes} min",
            "slaState": sla_state,
            "slaClass": sla_class,
            "fillClass": fill_class,
            "slaPct": fill_pct,
            "status": status,
            "statusBadge": "bcrit" if sla_state == "breached" else "binv" if status == "Investigating" else "bnew",
            "fullLog": alert.get("full_log", ""),
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
        print(f"[OpenSearch] Erro: {exc}")
        data = wazuh.get_alerts_sqlite_fallback(config.DB_PATH)
    return jsonify(data)


@spark_bp.route("/spark/wazuh-debug")
def spark_wazuh_debug():
    return jsonify(
        wazuh.get_wazuh_debug(config.WAZUH_BASE, config.WAZUH_USER, config.WAZUH_PASS)
    )


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
    workqueue, sla_summary = _build_workqueue(alerts)
    posture = _build_posture(alert_data, agents, fortigate_data, shuffle_data, sla_summary)

    top_alert = alerts[0] if alerts else {}
    triage = (
        f"Wazuh Indexer: {alert_data.get('total', 0)} alertas no intervalo {time_range}. "
        f"P1: {alert_data.get('p1', 0)} | P2: {alert_data.get('p2', 0)}. "
        f"FortiGate: CPU {fortigate_data.get('cpu', 0)}%, memoria {fortigate_data.get('mem', 0)}%, "
        f"{fortigate_data.get('sessions', 0)} sessoes ativas."
    )
    if top_alert:
        triage += f" Ultimo alerta: {top_alert.get('description', 'Wazuh alert')}."

    payload = {
        "source": "live",
        "cached": False,
        "range": time_range,
        "errors": errors,
        "kpis": {
            "critical_incidents": alert_data.get("p1", 0),
            "mttd": "N/A",
            "mttd_detail": "Aguardando timestamps de incidente",
            "mttr": "N/A",
            "mttr_detail": "Aguardando fechamento de tickets",
            "sla_compliance": sla_summary.get("compliance"),
            "sla_detail": f"{sla_summary.get('within', 0)}/{sla_summary.get('measurable', 0)} dentro da politica",
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

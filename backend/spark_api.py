"""
SPARK SOC — API Blueprint /spark/*
=====================================
Todos os endpoints do dashboard agrupados num Blueprint Flask.
"""
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, jsonify, request

import config
from backend import tickets as ticket_store
from backend import fortigate, wazuh, ai_proxy, shuffle

spark_bp = Blueprint("spark", __name__)


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
    errors: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            "wazuh_indexer": executor.submit(
                wazuh.get_executive_alerts,
                config.INDEXER_BASE,
                config.INDEXER_USER,
                config.INDEXER_PASS,
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
        alert_data = futures["wazuh_indexer"].result()
    except Exception as exc:
        errors["wazuh_indexer"] = str(exc)
        alert_data = {"total": 0, "p1": 0, "p2": 0, "p3": 0, "alerts": [], "timeline": []}

    try:
        agents = futures["wazuh_api"].result()
    except Exception as exc:
        errors["wazuh_api"] = str(exc)
        agents = {"total": 0, "active": 0, "disconnected": 0, "pending": 0, "agents": []}

    fortigate_data = futures["fortigate"].result()
    if fortigate_data.get("source") != "fortigate-live":
        errors["fortigate"] = fortigate_data.get("error", "offline")

    shuffle_data = futures["shuffle"].result()
    if not shuffle_data.get("connected"):
        errors["shuffle"] = shuffle_data.get("error", "offline")

    alerts = alert_data.get("alerts", [])
    workqueue = []
    for idx, alert in enumerate(alerts[:10], start=1):
        level = int(alert.get("level") or 0)
        priority = "P1" if level >= 12 else "P2" if level >= 7 else "P3"
        badge = "bp1" if priority == "P1" else "bp2" if priority == "P2" else "bp3"
        status = "Investigating" if level >= 7 else "New"
        workqueue.append({
            "id": f"WAZUH-{str(alert.get('rule_id') or idx).zfill(4)}",
            "time": (alert.get("timestamp") or "")[11:16] or "--:--",
            "description": alert.get("description") or "Wazuh alert",
            "tactic": alert.get("mitre_tactic") or "Detection",
            "priority": priority,
            "badge": badge,
            "analyst": "SOC",
            "sla": "15 min" if priority == "P1" else "45 min" if priority == "P2" else "90 min",
            "slaClass": "slbr" if priority == "P1" else "slwarn" if priority == "P2" else "slok",
            "fillClass": "fbr" if priority == "P1" else "fwarn" if priority == "P2" else "fok",
            "slaPct": 80 if priority == "P1" else 45 if priority == "P2" else 20,
            "status": status,
            "statusBadge": "binv" if status == "Investigating" else "bnew",
        })

    top_alert = alerts[0] if alerts else {}
    triage = (
        f"Wazuh Indexer: {alert_data.get('total', 0)} alertas nas ultimas 24h. "
        f"P1: {alert_data.get('p1', 0)} | P2: {alert_data.get('p2', 0)}. "
        f"FortiGate: CPU {fortigate_data.get('cpu', 0)}%, memoria {fortigate_data.get('mem', 0)}%, "
        f"{fortigate_data.get('sessions', 0)} sessoes ativas."
    )
    if top_alert:
        triage += f" Ultimo alerta: {top_alert.get('description', 'Wazuh alert')}."

    return jsonify({
        "source": "live",
        "errors": errors,
        "kpis": {
            "critical_incidents": alert_data.get("p1", 0),
            "mttd": "live",
            "mttr": "live",
            "sla_compliance": 100 if alert_data.get("p1", 0) == 0 else 95,
            "monitored_assets": agents.get("total", 0),
            "assets_alerting": agents.get("disconnected", 0) + agents.get("pending", 0),
            "events_24h": alert_data.get("total", 0),
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
    })


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

"""
SPARK SOC — Tickets Store
==========================
CRUD em memória para tickets de incidentes.
Em produção, substitua por PostgreSQL ou MongoDB.
"""
from datetime import datetime, timezone

# ── Store ──────────────────────────────────────────────────────────────────
_tickets: dict[str, dict] = {}
_blocked_ips: list[dict]  = []
_ip_block_log: list[dict] = []
_escalation_log: list[dict] = []

# ── Seed data ──────────────────────────────────────────────────────────────
_SEED_TICKETS = []

def _seed():
    for t in _SEED_TICKETS:
        _tickets[t["id"]] = dict(t)
    # Seed IP block log (tickets já bloqueados)
    for t in _SEED_TICKETS:
        if t["ipBlocked"]:
            _ip_block_log.append({
                "ip": t["ip"], "country": t["country"],
                "action": "Bloqueado", "reason": t["title"],
                "analyst": t["assignee"], "time": t["created"], "status": "Ativo",
            })
            _blocked_ips.append({
                "ip": t["ip"], "subnet": f"{t['ip']}/32",
                "name": f"SPARK_BLOCK_{t['ip'].replace('.','_')}",
                "country": t["country"], "analyst": t["assignee"],
            })
    # Seed escalation log
    for t in _SEED_TICKETS:
        if t.get("escalatedTo"):
            _escalation_log.append({
                "ticket": t["id"], "incident": t["incidentLink"],
                "to": t["escalatedTo"], "reason": t.get("escalationReason", "—"),
                "time": t["created"], "status": "Aguardando",
            })

_seed()

# ── Helpers ────────────────────────────────────────────────────────────────

def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M UTC")

def _next_id() -> str:
    nums = [int(k.split("-")[1]) for k in _tickets if k.startswith("SPARK-")]
    n = max(nums, default=0) + 1
    return f"SPARK-{n:03d}"

# ── CRUD ───────────────────────────────────────────────────────────────────

def list_tickets(status: str = None, priority: str = None) -> list[dict]:
    result = list(_tickets.values())
    if status:
        result = [t for t in result if t.get("status") == status]
    if priority:
        result = [t for t in result if t.get("priority") == priority]
    result.sort(key=lambda x: x.get("created", ""), reverse=True)
    return result

def get_ticket(ticket_id: str) -> dict | None:
    return _tickets.get(ticket_id)

def create_ticket(data: dict) -> dict:
    now = _now_utc()
    ticket = {
        "id":               _next_id(),
        "title":            data.get("title", ""),
        "status":           data.get("status", "open"),
        "priority":         data.get("priority", "p3"),
        "type":             data.get("type", "incident"),
        "assignee":         data.get("assignee", ""),
        "incidentLink":     data.get("incidentLink", ""),
        "mitre":            data.get("mitre", ""),
        "ip":               data.get("ip", ""),
        "country":          data.get("country", ""),
        "ipBlocked":        data.get("ipBlocked", False),
        "escalatedTo":      data.get("escalatedTo", ""),
        "escalationReason": data.get("escalationReason", ""),
        "desc":             data.get("desc", ""),
        "playbook":         data.get("playbook", ""),
        "aiAnalysis":       data.get("aiAnalysis", ""),
        "aiGenerated":      data.get("aiGenerated", False),
        "created":          now,
        "updated":          now,
    }
    _tickets[ticket["id"]] = ticket
    if ticket["escalatedTo"]:
        _register_escalation(ticket)
    return ticket

def update_ticket(ticket_id: str, data: dict) -> dict | None:
    ticket = _tickets.get(ticket_id)
    if not ticket:
        return None
    old_esc = ticket.get("escalatedTo", "")
    updatable = [
        "title", "status", "priority", "type", "assignee", "incidentLink",
        "mitre", "ip", "country", "ipBlocked", "escalatedTo", "escalationReason",
        "desc", "playbook", "aiAnalysis",
    ]
    for field in updatable:
        if field in data:
            ticket[field] = data[field]
    ticket["updated"] = _now_utc()
    _tickets[ticket_id] = ticket
    if ticket["escalatedTo"] and ticket["escalatedTo"] != old_esc:
        _register_escalation(ticket)
    return ticket

def delete_ticket(ticket_id: str) -> bool:
    if ticket_id not in _tickets:
        return False
    del _tickets[ticket_id]
    return True

# ── IP Block / Unblock ─────────────────────────────────────────────────────

def block_ip(ip: str, country: str, reason: str, analyst: str) -> dict:
    now = _now_utc()
    entry = {
        "ip": ip, "subnet": f"{ip}/32",
        "name": f"SPARK_BLOCK_{ip.replace('.','_')}",
        "country": country, "reason": reason,
        "analyst": analyst, "time": now, "status": "Ativo",
    }
    _blocked_ips[:] = [b for b in _blocked_ips if b.get("ip") != ip]
    _blocked_ips.append(entry)
    log_entry = dict(entry); log_entry["action"] = "Bloqueado"
    _ip_block_log.insert(0, log_entry)
    return entry

def unblock_ip(ip: str, country: str, analyst: str) -> dict:
    now = _now_utc()
    _blocked_ips[:] = [b for b in _blocked_ips if b.get("ip") != ip]
    log_entry = {
        "ip": ip, "action": "Desbloqueado",
        "analyst": analyst, "time": now,
        "status": "Removido", "country": country,
    }
    _ip_block_log.insert(0, log_entry)
    return log_entry

def get_blocked_ips() -> list[dict]:
    return list(_blocked_ips)

def get_ip_block_log() -> list[dict]:
    return list(_ip_block_log)

# ── Escalation ─────────────────────────────────────────────────────────────

def escalate(ticket_id: str, to: str, reason: str, analyst: str) -> dict:
    ticket = _tickets.get(ticket_id)
    if ticket:
        ticket["escalatedTo"]      = to
        ticket["escalationReason"] = reason
        ticket["updated"] = _now_utc()
    return _register_escalation_manual(ticket_id, ticket, to, reason, analyst)

def _register_escalation(ticket: dict) -> dict:
    now = _now_utc()
    entry = {
        "ticket":   ticket["id"],
        "incident": ticket.get("incidentLink", "—"),
        "to":       ticket["escalatedTo"],
        "reason":   ticket.get("escalationReason", "—"),
        "time":     now,
        "status":   "Aguardando",
    }
    _escalation_log[:] = [e for e in _escalation_log if e["ticket"] != ticket["id"]]
    _escalation_log.insert(0, entry)
    return entry

def _register_escalation_manual(ticket_id: str, ticket: dict | None, to: str, reason: str, analyst: str) -> dict:
    now = _now_utc()
    entry = {
        "ticket":   ticket_id,
        "incident": ticket.get("incidentLink", "—") if ticket else "—",
        "to":       to,
        "reason":   reason or "—",
        "analyst":  analyst,
        "time":     now,
        "status":   "Aguardando",
    }
    _escalation_log[:] = [e for e in _escalation_log if e["ticket"] != ticket_id]
    _escalation_log.insert(0, entry)
    return entry

def get_escalation_log() -> list[dict]:
    return list(_escalation_log)

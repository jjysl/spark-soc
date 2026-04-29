"""SPARK SOC ticket, block-list and incident lifecycle store."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import config

_tickets: dict[str, dict] = {}
_blocked_ips: list[dict] = []
_ip_block_log: list[dict] = []
_escalation_log: list[dict] = []


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_case_store() -> None:
    conn = _db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            source TEXT NOT NULL DEFAULT 'wazuh',
            source_alert_id TEXT UNIQUE,
            source_index TEXT,
            rule_id TEXT,
            rule_level INTEGER,
            rule_groups TEXT,
            title TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            owner TEXT NOT NULL DEFAULT 'Unassigned',
            sla_minutes INTEGER NOT NULL,
            alert_timestamp TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            due_at TEXT NOT NULL,
            acknowledged_at TEXT,
            closed_at TEXT,
            agent_name TEXT,
            agent_id TEXT,
            agent_ip TEXT,
            manager_name TEXT,
            decoder_name TEXT,
            location TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port TEXT,
            dst_port TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            raw_summary TEXT,
            raw_json TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_action_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            ticket_id TEXT,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            ip TEXT,
            object_name TEXT,
            group_name TEXT,
            policy_name TEXT,
            policy_found INTEGER NOT NULL DEFAULT 0,
            enforcement_path TEXT,
            message TEXT,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(incident_cases)").fetchall()}
    migrations = {
        "rule_level": "INTEGER",
        "rule_groups": "TEXT",
        "agent_id": "TEXT",
        "manager_name": "TEXT",
        "decoder_name": "TEXT",
        "location": "TEXT",
        "src_port": "TEXT",
        "dst_port": "TEXT",
        "raw_json": "TEXT",
    }
    for column, definition in migrations.items():
        if column not in existing_columns:
            conn.execute(f"ALTER TABLE incident_cases ADD COLUMN {column} {definition}")
    conn.commit()
    conn.close()


init_case_store()


def init_ticket_store() -> None:
    conn = _db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            ticket_id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    rows = conn.execute("SELECT payload FROM tickets").fetchall()
    _tickets.clear()
    for row in rows:
        try:
            ticket = json.loads(row["payload"])
        except (TypeError, ValueError):
            continue
        if ticket.get("id"):
            _tickets[ticket["id"]] = ticket
    conn.close()


def _persist_ticket(ticket: dict) -> None:
    conn = _db()
    now = _iso_now()
    conn.execute(
        """
        INSERT INTO tickets (ticket_id, payload, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ticket_id) DO UPDATE SET
            payload = excluded.payload,
            updated_at = excluded.updated_at
        """,
        (
            ticket["id"],
            json.dumps(ticket, ensure_ascii=False, sort_keys=True),
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()


def _delete_persisted_ticket(ticket_id: str) -> None:
    conn = _db()
    conn.execute("DELETE FROM tickets WHERE ticket_id = ?", (ticket_id,))
    conn.commit()
    conn.close()


def _now_label() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M UTC")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


init_ticket_store()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _fmt_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "N/A"
    minutes = max(0, int(seconds // 60))
    if minutes < 60:
        return f"{minutes}m"
    hours, rem = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {rem:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def _next_id() -> str:
    nums = [int(k.split("-")[1]) for k in _tickets if k.startswith("SPARK-") and k.split("-")[1].isdigit()]
    return f"SPARK-{max(nums, default=0) + 1:03d}"


def list_tickets(status: str = None, priority: str = None) -> list[dict]:
    result = list(_tickets.values())
    if status:
        result = [ticket for ticket in result if ticket.get("status") == status]
    if priority:
        result = [ticket for ticket in result if ticket.get("priority") == priority]
    result.sort(key=lambda ticket: ticket.get("created", ""), reverse=True)
    return result


def get_ticket(ticket_id: str) -> dict | None:
    return _tickets.get(ticket_id)


def create_ticket(data: dict) -> dict:
    now = _now_label()
    ticket = {
        "id": _next_id(),
        "title": data.get("title", ""),
        "status": data.get("status", "open"),
        "priority": data.get("priority", "p3"),
        "type": data.get("type", "incident"),
        "assignee": data.get("assignee", ""),
        "incidentLink": data.get("incidentLink", ""),
        "mitre": data.get("mitre", ""),
        "ip": data.get("ip", ""),
        "country": data.get("country", ""),
        "ipBlocked": data.get("ipBlocked", False),
        "escalatedTo": data.get("escalatedTo", ""),
        "escalationReason": data.get("escalationReason", ""),
        "desc": data.get("desc", ""),
        "playbook": data.get("playbook", ""),
        "aiAnalysis": data.get("aiAnalysis", ""),
        "aiGenerated": data.get("aiGenerated", False),
        "externalProvider": data.get("externalProvider", ""),
        "externalKey": data.get("externalKey", ""),
        "externalUrl": data.get("externalUrl", ""),
        "syncStatus": data.get("syncStatus", "local"),
        "syncMessage": data.get("syncMessage", ""),
        "created": now,
        "updated": now,
    }
    _tickets[ticket["id"]] = ticket
    _persist_ticket(ticket)
    if ticket["escalatedTo"]:
        _register_escalation(ticket)
    return ticket


def update_ticket(ticket_id: str, data: dict) -> dict | None:
    ticket = _tickets.get(ticket_id)
    if not ticket:
        return None
    old_escalation = ticket.get("escalatedTo", "")
    updatable = [
        "title", "status", "priority", "type", "assignee", "incidentLink",
        "mitre", "ip", "country", "ipBlocked", "escalatedTo", "escalationReason",
        "desc", "playbook", "aiAnalysis", "externalProvider", "externalKey",
        "externalUrl", "syncStatus", "syncMessage",
    ]
    for field in updatable:
        if field in data:
            ticket[field] = data[field]
    ticket["updated"] = _now_label()
    if ticket["escalatedTo"] and ticket["escalatedTo"] != old_escalation:
        _register_escalation(ticket)
    _persist_ticket(ticket)
    return ticket


def mark_ticket_sync(ticket_id: str, provider: str, key: str, url: str, status: str, message: str = "") -> dict | None:
    ticket = _tickets.get(ticket_id)
    if not ticket:
        return None
    ticket["externalProvider"] = provider
    ticket["externalKey"] = key
    ticket["externalUrl"] = url
    ticket["syncStatus"] = status
    ticket["syncMessage"] = message
    ticket["updated"] = _now_label()
    _persist_ticket(ticket)
    return ticket


def delete_ticket(ticket_id: str) -> bool:
    if ticket_id not in _tickets:
        return False
    del _tickets[ticket_id]
    _delete_persisted_ticket(ticket_id)
    return True


def block_ip(ip: str, country: str, reason: str, analyst: str) -> dict:
    now = _now_label()
    entry = {
        "ip": ip,
        "subnet": f"{ip}/32",
        "name": f"SPARK_BLOCK_{ip.replace('.', '_')}",
        "country": country,
        "reason": reason,
        "analyst": analyst,
        "time": now,
        "status": "Active",
    }
    _blocked_ips[:] = [item for item in _blocked_ips if item.get("ip") != ip]
    _blocked_ips.append(entry)
    log_entry = dict(entry)
    log_entry["action"] = "Blocked"
    _ip_block_log.insert(0, log_entry)
    return entry


def unblock_ip(ip: str, country: str, analyst: str) -> dict:
    now = _now_label()
    _blocked_ips[:] = [item for item in _blocked_ips if item.get("ip") != ip]
    log_entry = {
        "ip": ip,
        "action": "Unblocked",
        "analyst": analyst,
        "time": now,
        "status": "Removed",
        "country": country,
    }
    _ip_block_log.insert(0, log_entry)
    return log_entry


def get_blocked_ips() -> list[dict]:
    return list(_blocked_ips)


def get_ip_block_log() -> list[dict]:
    return list(_ip_block_log)


def record_action_event(case_id: str = "", ticket_id: str = "", action: str = "", status: str = "", payload: dict | None = None) -> dict:
    payload = payload or {}
    created_at = _iso_now()
    event = {
        "case_id": case_id or "",
        "ticket_id": ticket_id or "",
        "action": action or payload.get("action", ""),
        "status": status or payload.get("status", ""),
        "ip": payload.get("ip", ""),
        "object_name": payload.get("object", ""),
        "group_name": payload.get("group", ""),
        "policy_name": payload.get("policy", ""),
        "policy_found": bool(payload.get("policy_found")),
        "enforcement_path": payload.get("enforcement_path", ""),
        "message": payload.get("message", ""),
        "payload": payload,
        "created_at": created_at,
    }
    conn = _db()
    conn.execute(
        """
        INSERT INTO case_action_events (
            case_id, ticket_id, action, status, ip, object_name, group_name,
            policy_name, policy_found, enforcement_path, message, payload, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["case_id"],
            event["ticket_id"],
            event["action"],
            event["status"],
            event["ip"],
            event["object_name"],
            event["group_name"],
            event["policy_name"],
            1 if event["policy_found"] else 0,
            event["enforcement_path"],
            event["message"],
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            created_at,
        ),
    )
    conn.commit()
    conn.close()
    return event


def list_action_events(limit: int = 25, case_id: str = "", ticket_id: str = "") -> list[dict]:
    init_case_store()
    clauses = []
    params = []
    if case_id:
        clauses.append("case_id = ?")
        params.append(case_id)
    if ticket_id:
        clauses.append("ticket_id = ?")
        params.append(ticket_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    conn = _db()
    rows = conn.execute(
        f"""
        SELECT * FROM case_action_events
        {where}
        ORDER BY created_at DESC
        LIMIT ?
        """,
        params + [limit],
    ).fetchall()
    conn.close()
    events = []
    for row in rows:
        event = dict(row)
        event["policy_found"] = bool(event.get("policy_found"))
        try:
            event["payload"] = json.loads(event.get("payload") or "{}")
        except (TypeError, ValueError):
            event["payload"] = {}
        events.append(event)
    return events


def escalate(ticket_id: str, to: str, reason: str, analyst: str) -> dict:
    ticket = _tickets.get(ticket_id)
    if ticket:
        ticket["escalatedTo"] = to
        ticket["escalationReason"] = reason
        ticket["updated"] = _now_label()
    return _register_escalation_manual(ticket_id, ticket, to, reason, analyst)


def _register_escalation(ticket: dict) -> dict:
    entry = {
        "ticket": ticket["id"],
        "incident": ticket.get("incidentLink", "-"),
        "to": ticket["escalatedTo"],
        "reason": ticket.get("escalationReason", "-"),
        "time": _now_label(),
        "status": "Pending",
    }
    _escalation_log[:] = [item for item in _escalation_log if item["ticket"] != ticket["id"]]
    _escalation_log.insert(0, entry)
    return entry


def _register_escalation_manual(ticket_id: str, ticket: dict | None, to: str, reason: str, analyst: str) -> dict:
    entry = {
        "ticket": ticket_id,
        "incident": ticket.get("incidentLink", "-") if ticket else "-",
        "to": to,
        "reason": reason or "-",
        "analyst": analyst,
        "time": _now_label(),
        "status": "Pending",
    }
    _escalation_log[:] = [item for item in _escalation_log if item["ticket"] != ticket_id]
    _escalation_log.insert(0, entry)
    return entry


def get_escalation_log() -> list[dict]:
    return list(_escalation_log)


def _priority_from_level(level: int) -> str:
    if level >= 12:
        return "P1"
    if level >= 7:
        return "P2"
    if level >= 4:
        return "P3"
    return "P4"


def _new_case_id(rule_id: str | int | None, number: int) -> str:
    return f"SPARK-INC-{str(rule_id or number).zfill(4)}-{number:04d}"


def promote_alerts_to_cases(alerts: list[dict], sla_policy: dict[str, int]) -> list[dict]:
    """Promote Wazuh alert candidates into persistent SOC case/workqueue records."""
    init_case_store()
    conn = _db()
    now = datetime.now(timezone.utc)
    cases: list[dict] = []

    for alert in alerts:
        level = int(alert.get("level") or 0)
        priority = _priority_from_level(level)
        sla_minutes = int(sla_policy.get(priority, 360))
        source_alert_id = alert.get("document_id") or ":".join([
            str(alert.get("rule_id", "")),
            str(alert.get("timestamp", "")),
            str(alert.get("agent_id", "")),
            str(alert.get("agent_name", "")),
            str(alert.get("src_ip", "")),
            str(alert.get("description", ""))[:120],
        ])
        rule_groups = ", ".join(alert.get("groups") or []) if isinstance(alert.get("groups"), list) else str(alert.get("groups") or "")
        raw_json = json.dumps(alert.get("raw") or alert, ensure_ascii=False, sort_keys=True)
        existing = conn.execute(
            "SELECT * FROM incident_cases WHERE source_alert_id = ?",
            (source_alert_id,),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE incident_cases
                   SET priority = ?, updated_at = ?, raw_summary = ?, raw_json = ?,
                       rule_level = ?, rule_groups = ?, agent_id = ?, agent_ip = ?,
                       manager_name = ?, decoder_name = ?, location = ?,
                       src_ip = ?, dst_ip = ?, src_port = ?, dst_port = ?,
                       mitre_tactic = ?, mitre_technique = ?
                 WHERE source_alert_id = ?
                """,
                (
                    priority,
                    now.isoformat(),
                    alert.get("full_log", ""),
                    raw_json,
                    level,
                    rule_groups,
                    alert.get("agent_id", ""),
                    alert.get("agent_ip", ""),
                    alert.get("manager_name", ""),
                    alert.get("decoder_name", ""),
                    alert.get("location", ""),
                    alert.get("src_ip", ""),
                    alert.get("dst_ip", ""),
                    str(alert.get("src_port", "") or ""),
                    str(alert.get("dst_port", "") or ""),
                    alert.get("mitre_tactic") or "Detection",
                    alert.get("mitre_technique", ""),
                    source_alert_id,
                ),
            )
        else:
            next_number = int(conn.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM incident_cases").fetchone()[0])
            case_id = _new_case_id(alert.get("rule_id"), next_number)
            due_at = now + timedelta(minutes=sla_minutes)
            conn.execute(
                """
                INSERT INTO incident_cases (
                    case_id, source_alert_id, source_index, rule_id, rule_level, rule_groups, title, priority,
                    status, owner, sla_minutes, alert_timestamp, created_at, updated_at,
                    due_at, agent_name, agent_id, agent_ip, manager_name, decoder_name,
                    location, src_ip, dst_ip, src_port, dst_port, mitre_tactic,
                    mitre_technique, raw_summary, raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', 'Unassigned', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    source_alert_id,
                    alert.get("index", ""),
                    str(alert.get("rule_id", "")),
                    level,
                    rule_groups,
                    alert.get("description") or "Wazuh alert",
                    priority,
                    sla_minutes,
                    alert.get("timestamp", ""),
                    now.isoformat(),
                    now.isoformat(),
                    due_at.isoformat(),
                    alert.get("agent_name", "unknown"),
                    alert.get("agent_id", ""),
                    alert.get("agent_ip", ""),
                    alert.get("manager_name", ""),
                    alert.get("decoder_name", ""),
                    alert.get("location", ""),
                    alert.get("src_ip", ""),
                    alert.get("dst_ip", ""),
                    str(alert.get("src_port", "") or ""),
                    str(alert.get("dst_port", "") or ""),
                    alert.get("mitre_tactic") or "Detection",
                    alert.get("mitre_technique", ""),
                    alert.get("full_log", ""),
                    raw_json,
                ),
            )

        row = conn.execute(
            "SELECT * FROM incident_cases WHERE source_alert_id = ?",
            (source_alert_id,),
        ).fetchone()
        if row:
            cases.append(dict(row))

    conn.commit()
    conn.close()
    return cases


def list_incident_cases(limit: int = 25, include_closed: bool = False, sort: str = "recent") -> list[dict]:
    init_case_store()
    where = "" if include_closed else "WHERE status != 'closed'"
    if sort == "sla":
        order_by = """
        ORDER BY
          CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END,
          due_at ASC
        """
    else:
        order_by = """
        ORDER BY
          COALESCE(NULLIF(alert_timestamp, ''), created_at) DESC,
          id DESC
        """
    conn = _db()
    rows = conn.execute(
        f"""
        SELECT * FROM incident_cases
        {where}
        {order_by}
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_incident_case(case_id: str) -> dict | None:
    init_case_store()
    conn = _db()
    row = conn.execute("SELECT * FROM incident_cases WHERE case_id = ?", (case_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_incident_case(case_id: str, data: dict) -> dict | None:
    allowed = {"status", "owner"}
    updates = {key: value for key, value in (data or {}).items() if key in allowed}
    if not updates:
        return get_incident_case(case_id)

    now = _iso_now()
    if updates.get("status") in {"investigating", "acknowledged"}:
        updates["acknowledged_at"] = now
    if updates.get("status") in {"closed", "resolved"}:
        updates["status"] = "closed"
        updates["closed_at"] = now
    updates["updated_at"] = now

    assignments = ", ".join(f"{key} = ?" for key in updates)
    conn = _db()
    conn.execute(
        f"UPDATE incident_cases SET {assignments} WHERE case_id = ?",
        list(updates.values()) + [case_id],
    )
    conn.commit()
    row = conn.execute("SELECT * FROM incident_cases WHERE case_id = ?", (case_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_incident_lifecycle_metrics() -> dict:
    init_case_store()
    conn = _db()
    rows = conn.execute("SELECT * FROM incident_cases").fetchall()
    conn.close()

    detection_deltas = []
    response_deltas = []
    resolution_deltas = []
    total = len(rows)
    open_cases = 0
    closed_cases = 0

    for row in rows:
        item = dict(row)
        alert_ts = _parse_iso(item.get("alert_timestamp"))
        created_at = _parse_iso(item.get("created_at"))
        acknowledged_at = _parse_iso(item.get("acknowledged_at"))
        closed_at = _parse_iso(item.get("closed_at"))
        if item.get("status") == "closed":
            closed_cases += 1
        else:
            open_cases += 1
        if alert_ts and created_at:
            detection_deltas.append((created_at - alert_ts).total_seconds())
        if created_at and acknowledged_at:
            response_deltas.append((acknowledged_at - created_at).total_seconds())
        if created_at and closed_at:
            resolution_deltas.append((closed_at - created_at).total_seconds())

    def avg(values: list[float]) -> float | None:
        return sum(values) / len(values) if values else None

    mttd = avg(detection_deltas)
    mttr_response = avg(response_deltas)
    mttr_resolution = avg(resolution_deltas)
    return {
        "total_cases": total,
        "open_cases": open_cases,
        "closed_cases": closed_cases,
        "mttd": _fmt_duration(mttd),
        "mttd_detail": f"{len(detection_deltas)} cases with alert-to-case timestamps" if detection_deltas else "No alert-to-case timestamps yet",
        "mttr": _fmt_duration(mttr_resolution) if resolution_deltas else _fmt_duration(mttr_response),
        "mttr_detail": (
            f"{len(resolution_deltas)} closed cases measured"
            if resolution_deltas
            else f"{len(response_deltas)} acknowledged cases measured"
            if response_deltas
            else "No acknowledged or closed cases yet"
        ),
    }

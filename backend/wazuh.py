"""
SPARK SOC — Integração Wazuh / OpenSearch
==========================================
Consulta alertas via OpenSearch (Wazuh Indexer).
Fallback para SQLite quando o indexer não está disponível.
"""
import time
import sqlite3
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_token_cache: dict = {"token": None, "time": 0}
_agents_cache: dict = {"data": None, "time": 0}
THREAT_FILTER_FIELDS = {
    "rule.id": "rule.id",
    "rule.level": "rule.level",
    "rule.groups": "rule.groups",
    "agent.id": "agent.id",
    "agent.name": "agent.name",
    "agent.ip": "agent.ip",
    "manager.name": "manager.name",
    "decoder.name": "decoder.name",
    "location": "location",
    "data.srcip": "data.srcip",
    "data.dstip": "data.dstip",
    "data.src_ip": "data.src_ip",
    "data.dst_ip": "data.dst_ip",
    "mitre.tactic": "rule.mitre.tactic",
    "mitre.technique": "rule.mitre.id",
}


# ── Token Wazuh Manager API ────────────────────────────────────────────────

def get_wazuh_token(base: str, user: str, password: str) -> str:
    """Obtém (ou reutiliza do cache) o JWT do Wazuh Manager."""
    if _token_cache["token"] and (time.time() - _token_cache["time"]) < 3300:
        return _token_cache["token"]
    r = requests.get(
        f"{base}/security/user/authenticate?raw=true",
        auth=(user, password),
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    token = r.text.strip()
    _token_cache["token"] = token
    _token_cache["time"]  = time.time()
    return token


def clear_wazuh_token() -> None:
    _token_cache["token"] = None
    _token_cache["time"] = 0


def wazuh_request(base: str, path: str, token: str) -> dict:
    r = requests.get(
        f"{base}{path}",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def wazuh_authenticated_request(base: str, user: str, password: str, path: str) -> dict:
    token = get_wazuh_token(base, user, password)
    try:
        return wazuh_request(base, path, token)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status != 401:
            raise
        clear_wazuh_token()
        token = get_wazuh_token(base, user, password)
        return wazuh_request(base, path, token)


# ── OpenSearch Alerts ──────────────────────────────────────────────────────

def get_alerts_opensearch(indexer_base: str, user: str, password: str) -> dict:
    """
    Consulta os últimos 50 alertas no OpenSearch.
    Retorna dict com 'source', 'levels', 'alerts', 'stats'.
    """
    query = {
        "size": 50,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp", "rule.id", "rule.description", "rule.level",
            "rule.mitre.tactic", "rule.mitre.id", "agent.name", "agent.ip",
            "data.srcip", "data.dstip",
        ],
        "query": {"range": {"timestamp": {"gte": "now-7d/d", "lte": "now"}}},
    }
    r = requests.post(
        f"{indexer_base}/wazuh-alerts-4.x-*/_search",
        json=query,
        auth=(user, password),
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    raw = r.json()
    hits = raw.get("hits", {}).get("hits", [])

    alerts, levels = [], {}
    for hit in hits:
        src    = hit.get("_source", {})
        rule   = src.get("rule", {})
        agent  = src.get("agent", {})
        mitre  = rule.get("mitre", {})
        tactics = mitre.get("tactic", [])
        techs   = mitre.get("id", [])
        lv = rule.get("level", 0)
        levels[str(lv)] = levels.get(str(lv), 0) + 1
        alerts.append({
            "timestamp":       src.get("timestamp", ""),
            "rule_id":         rule.get("id", ""),
            "description":     rule.get("description", ""),
            "level":           lv,
            "agent_name":      agent.get("name", "unknown"),
            "agent_ip":        agent.get("ip", ""),
            "src_ip":          src.get("data", {}).get("srcip", ""),
            "dst_ip":          src.get("data", {}).get("dstip", ""),
            "mitre_tactic":    tactics[0] if tactics else "",
            "mitre_technique": techs[0]   if techs   else "",
        })

    total    = raw.get("hits", {}).get("total", {}).get("value", 0)
    critical = sum(1 for a in alerts if a["level"] >= 12)
    auth_fail = sum(
        1 for a in alerts
        if str(a.get("rule_id", "")) in {"5710", "5711", "5712", "18113"}
    )
    auth_ok = sum(
        1 for a in alerts
        if str(a.get("rule_id", "")) in {"5715", "18137"}
    )
    return {
        "source":  "opensearch-live",
        "levels":  levels,
        "alerts":  alerts,
        "stats":   {
            "total":         total,
            "critical":      critical,
            "auth_failures": auth_fail,
            "auth_success":  auth_ok,
        },
    }


def get_alerts_sqlite_fallback(db_path: str) -> dict:
    """Fallback: lê contagens do SQLite quando o OpenSearch não responde."""
    conn = sqlite3.connect(db_path)
    mal = conn.execute("SELECT COUNT(*) FROM events WHERE status='MALICIOUS'").fetchone()[0]
    sus = conn.execute("SELECT COUNT(*) FROM events WHERE status='SUSPICIOUS'").fetchone()[0]
    cln = conn.execute("SELECT COUNT(*) FROM events WHERE status='CLEAN'").fetchone()[0]
    conn.close()
    return {
        "source": "sqlite-fallback",
        "levels": {"10": mal, "3": cln},
        "alerts": [],
        "stats":  {"total": mal + sus + cln, "critical": 0, "auth_failures": 0, "auth_success": 0},
    }


# ── SQLite Queries (usadas pelo spark_api) ─────────────────────────────────

def get_agents_summary(wazuh_base: str, wazuh_user: str, wazuh_pass: str) -> dict:
    try:
        data = wazuh_authenticated_request(
            wazuh_base,
            wazuh_user,
            wazuh_pass,
            "/agents?select=id,name,ip,status,version&limit=500",
        )
    except Exception as exc:
        cached = _agents_cache.get("data")
        if cached and (time.time() - _agents_cache.get("time", 0)) < 300:
            fallback = dict(cached)
            fallback["stale"] = True
            fallback["warning"] = str(exc)
            return fallback
        raise

    agents = data.get("data", {}).get("affected_items", [])
    by_status: dict[str, int] = {}
    for agent in agents:
        status = agent.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    summary = {
        "total": data.get("data", {}).get("total_affected_items", len(agents)),
        "active": by_status.get("active", 0),
        "disconnected": by_status.get("disconnected", 0),
        "pending": by_status.get("pending", 0),
        "agents": agents,
        "stale": False,
    }
    _agents_cache["data"] = summary
    _agents_cache["time"] = time.time()
    return summary


def get_executive_alerts(indexer_base: str, user: str, password: str, time_range: str = "24h") -> dict:
    allowed_ranges = {"1h", "6h", "24h", "7d", "30d"}
    if time_range not in allowed_ranges:
        time_range = "24h"
    interval = "hour" if time_range in {"1h", "6h", "24h"} else "day"
    query = {
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp", "rule.id", "rule.description", "rule.level",
            "rule.groups", "rule.mitre.tactic", "rule.mitre.id",
            "agent.id", "agent.name", "agent.ip",
            "manager.name", "decoder.name", "location", "full_log",
            "data.srcip", "data.dstip", "data.src_ip", "data.dst_ip", "data.srcport", "data.dstport",
        ],
        "query": {"range": {"timestamp": {"gte": f"now-{time_range}", "lte": "now"}}},
        "aggs": {
            "levels": {"terms": {"field": "rule.level", "size": 20}},
            "hourly": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": interval,
                    "min_doc_count": 0,
                },
                "aggs": {"levels": {"terms": {"field": "rule.level", "size": 20}}},
            },
        },
    }
    resp = requests.post(
        f"{indexer_base}/wazuh-alerts-4.x-*/_search",
        json=query,
        auth=(user, password),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    raw = resp.json()
    hits = raw.get("hits", {}).get("hits", [])

    alerts = []
    for hit in hits:
        src = hit.get("_source", {})
        rule = src.get("rule", {})
        agent = src.get("agent", {})
        data = src.get("data", {})
        manager = src.get("manager", {})
        decoder = src.get("decoder", {})
        mitre = rule.get("mitre", {})
        tactics = mitre.get("tactic", [])
        techniques = mitre.get("id", [])
        alerts.append({
            "document_id": hit.get("_id", ""),
            "index": hit.get("_index", ""),
            "timestamp": src.get("timestamp", ""),
            "rule_id": rule.get("id", ""),
            "description": rule.get("description", ""),
            "level": rule.get("level", 0),
            "groups": rule.get("groups", []),
            "agent_id": agent.get("id", ""),
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", ""),
            "manager_name": manager.get("name", ""),
            "decoder_name": decoder.get("name", ""),
            "location": src.get("location", ""),
            "src_ip": data.get("srcip") or data.get("src_ip") or agent.get("ip", ""),
            "dst_ip": data.get("dstip") or data.get("dst_ip") or "",
            "src_port": data.get("srcport", ""),
            "dst_port": data.get("dstport", ""),
            "mitre_tactic": tactics[0] if tactics else "",
            "mitre_technique": techniques[0] if techniques else "",
            "full_log": src.get("full_log", ""),
            "raw": src,
        })

    level_buckets = raw.get("aggregations", {}).get("levels", {}).get("buckets", [])
    levels = {str(bucket.get("key")): bucket.get("doc_count", 0) for bucket in level_buckets}
    p1 = sum(count for level, count in levels.items() if int(level) >= 12)
    p2 = sum(count for level, count in levels.items() if 7 <= int(level) < 12)
    p3 = sum(count for level, count in levels.items() if int(level) < 7)

    timeline = []
    for bucket in raw.get("aggregations", {}).get("hourly", {}).get("buckets", []):
        bucket_levels = {
            str(item.get("key")): item.get("doc_count", 0)
            for item in bucket.get("levels", {}).get("buckets", [])
        }
        timeline.append({
            "hour": bucket.get("key_as_string", ""),
            "p1": sum(v for k, v in bucket_levels.items() if int(k) >= 12),
            "p2": sum(v for k, v in bucket_levels.items() if 7 <= int(k) < 12),
            "p3": sum(v for k, v in bucket_levels.items() if int(k) < 7),
        })

    total = raw.get("hits", {}).get("total", {})
    return {
        "source": "opensearch-live",
        "range": time_range,
        "bucket_interval": interval,
        "total": total.get("value", len(alerts)) if isinstance(total, dict) else total,
        "levels": levels,
        "p1": p1,
        "p2": p2,
        "p3": p3,
        "alerts": alerts,
        "timeline": timeline,
    }


def _list_first(value) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


def _severity_from_level(level: int) -> dict:
    if level >= 12:
        return {"label": "Critical", "class": "bcrit", "priority": "P1"}
    if level >= 7:
        return {"label": "High", "class": "bhigh", "priority": "P2"}
    if level >= 4:
        return {"label": "Medium", "class": "bmed", "priority": "P3"}
    return {"label": "Low", "class": "blow", "priority": "P4"}


def _normalize_threat_hit(hit: dict) -> dict:
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    data = src.get("data", {})
    manager = src.get("manager", {})
    decoder = src.get("decoder", {})
    mitre = rule.get("mitre", {})
    level = int(rule.get("level") or 0)
    severity = _severity_from_level(level)
    src_ip = data.get("srcip") or data.get("src_ip") or agent.get("ip") or ""
    dst_ip = data.get("dstip") or data.get("dst_ip") or ""
    tactic = _list_first(mitre.get("tactic", [])) or "Detection"
    technique = _list_first(mitre.get("id", []))
    description = rule.get("description") or src.get("full_log") or "Wazuh alert"
    return {
        "document_id": hit.get("_id", ""),
        "index": hit.get("_index", ""),
        "timestamp": src.get("timestamp", ""),
        "rule_id": rule.get("id", ""),
        "description": description,
        "level": level,
        "severity": severity["label"],
        "severity_class": severity["class"],
        "priority": severity["priority"],
        "groups": rule.get("groups", []),
        "agent_id": agent.get("id", ""),
        "agent_name": agent.get("name", "unknown"),
        "agent_ip": agent.get("ip", ""),
        "manager_name": manager.get("name", ""),
        "decoder_name": decoder.get("name", ""),
        "location": src.get("location", ""),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": data.get("srcport", ""),
        "dst_port": data.get("dstport", ""),
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "full_log": src.get("full_log", ""),
        "status": "Investigating" if level >= 7 else "New",
        "status_class": "binv" if level >= 7 else "bnew",
        "summary": f"{description} on {agent.get('name', 'unknown')} ({src_ip or 'no source IP'})",
        "raw": src,
    }


KILL_CHAIN_STAGES = [
    {
        "name": "Reconnaissance",
        "terms": ["reconnaissance", "scan", "portscan", "probe", "service detection"],
        "technique": "T1595",
        "fallback": "No reconnaissance signal in current filter",
    },
    {
        "name": "Initial Access",
        "terms": ["initial access", "authentication failed", "invalid user", "sshd", "login", "phishing"],
        "technique": "T1566",
        "fallback": "No initial access signal in current filter",
    },
    {
        "name": "Execution",
        "terms": ["execution", "command", "powershell", "shell", "process", "script"],
        "technique": "T1059",
        "fallback": "No execution signal in current filter",
    },
    {
        "name": "Lateral Movement",
        "terms": ["lateral movement", "pass-the-hash", "remote", "rdp", "smb", "ssh"],
        "technique": "T1550",
        "fallback": "No lateral movement signal in current filter",
    },
    {
        "name": "Exfiltration",
        "terms": ["exfiltration", "upload", "data transfer", "tunnel", "dns tunneling"],
        "technique": "T1041",
        "fallback": "No exfiltration signal in current filter",
    },
]


def _alert_text(alert: dict) -> str:
    fields = [
        alert.get("description", ""),
        alert.get("mitre_tactic", ""),
        alert.get("mitre_technique", ""),
        " ".join(alert.get("groups") or []),
        alert.get("decoder_name", ""),
        alert.get("full_log", ""),
    ]
    return " ".join(str(item) for item in fields if item).lower()


def _best_stage_alert(alerts: list[dict], stage: dict) -> dict | None:
    for alert in alerts:
        tactic = str(alert.get("mitre_tactic") or "").lower()
        technique = str(alert.get("mitre_technique") or "")
        text = _alert_text(alert)
        if tactic == stage["name"].lower() or technique == stage["technique"]:
            return alert
        if any(term in text for term in stage["terms"]):
            return alert
    return None


def _build_kill_chain(alerts: list[dict], total_value: int, time_range: str, counts: dict) -> dict:
    active_alert = alerts[0] if alerts else None
    incident_id = f"INC-2026-{str(abs(hash((active_alert or {}).get('document_id', time_range))) % 10000).zfill(4)}"
    highest_priority = "P1" if counts.get("p1") else "P2" if counts.get("p2") else "P3" if counts.get("p3") else "P4"
    confidence = 0
    stages = []

    for index, stage in enumerate(KILL_CHAIN_STAGES):
        alert = _best_stage_alert(alerts, stage)
        if alert:
            confidence += 1
            technique = alert.get("mitre_technique") or stage["technique"]
            subject = alert.get("src_ip") or alert.get("agent_name") or alert.get("location") or "observed asset"
            detail = f"{alert.get('description') or 'Wazuh detection'} - {subject} - {technique}"
            state = "active" if active_alert and alert.get("document_id") == active_alert.get("document_id") else "done"
        else:
            detail = stage["fallback"]
            state = "pending" if index >= confidence else "done"
        stages.append({
            "name": stage["name"],
            "detail": detail,
            "state": state,
            "technique": stage["technique"],
            "document_id": alert.get("document_id", "") if alert else "",
            "rule_id": alert.get("rule_id", "") if alert else "",
            "src_ip": alert.get("src_ip", "") if alert else "",
            "agent_name": alert.get("agent_name", "") if alert else "",
        })

    if active_alert and not any(stage["state"] == "active" for stage in stages):
        tactic = active_alert.get("mitre_tactic") or "Detection"
        technique = active_alert.get("mitre_technique") or ""
        subject = active_alert.get("src_ip") or active_alert.get("agent_name") or active_alert.get("location") or "observed asset"
        stages[0] = {
            "name": tactic,
            "detail": f"{active_alert.get('description') or 'Wazuh detection'} - {subject} - {technique or 'no MITRE technique'}",
            "state": "active",
            "technique": technique,
            "document_id": active_alert.get("document_id", ""),
            "rule_id": active_alert.get("rule_id", ""),
            "src_ip": active_alert.get("src_ip", ""),
            "agent_name": active_alert.get("agent_name", ""),
        }

    return {
        "incident_id": incident_id,
        "title": f"Kill Chain - {incident_id}",
        "subtitle": f"Active incident - Wazuh/FortiAnalyzer-style correlation - {total_value} detections in {time_range}",
        "priority": highest_priority,
        "confidence": round((confidence / len(KILL_CHAIN_STAGES)) * 100),
        "stages": stages,
    }


def get_threat_detection_alerts(
    indexer_base: str,
    user: str,
    password: str,
    time_range: str = "24h",
    search: str = "",
    filters: list[tuple[str, str]] | None = None,
    size: int = 100,
) -> dict:
    allowed_ranges = {"1h", "6h", "24h", "7d", "30d"}
    if time_range not in allowed_ranges:
        time_range = "24h"
    size = max(1, min(int(size or 100), 250))
    filters = filters or []

    must = [{"range": {"timestamp": {"gte": f"now-{time_range}", "lte": "now"}}}]
    if search:
        must.append({
            "simple_query_string": {
                "query": f"*{search}*",
                "fields": [
                    "rule.description", "rule.id", "rule.groups",
                    "agent.name", "agent.ip", "decoder.name", "location",
                    "full_log", "data.srcip", "data.dstip",
                    "data.src_ip", "data.dst_ip",
                ],
                "default_operator": "AND",
            }
        })
    for field, value in filters:
        if value == "":
            continue
        if field == "src_ip":
            must.append({"bool": {"should": [
                {"term": {"data.srcip": value}},
                {"term": {"data.src_ip": value}},
                {"term": {"agent.ip": value}},
            ], "minimum_should_match": 1}})
            continue
        if field == "dst_ip":
            must.append({"bool": {"should": [
                {"term": {"data.dstip": value}},
                {"term": {"data.dst_ip": value}},
            ], "minimum_should_match": 1}})
            continue
        os_field = THREAT_FILTER_FIELDS.get(field)
        if os_field:
            must.append({"term": {os_field: value}})

    interval = "hour" if time_range in {"1h", "6h", "24h"} else "day"
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "aggs": {
            "levels": {"terms": {"field": "rule.level", "size": 20}},
            "tactics": {"terms": {"field": "rule.mitre.tactic", "size": 20}},
            "groups": {"terms": {"field": "rule.groups", "size": 20}},
            "decoders": {"terms": {"field": "decoder.name", "size": 20}},
            "timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": interval,
                    "min_doc_count": 0,
                },
                "aggs": {"levels": {"terms": {"field": "rule.level", "size": 20}}},
            },
        },
    }
    resp = requests.post(
        f"{indexer_base}/wazuh-alerts-4.x-*/_search",
        json=query,
        auth=(user, password),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    raw = resp.json()
    hits = raw.get("hits", {}).get("hits", [])
    alerts = [_normalize_threat_hit(hit) for hit in hits]

    aggs = raw.get("aggregations", {})
    level_buckets = aggs.get("levels", {}).get("buckets", [])
    levels = {str(bucket.get("key")): bucket.get("doc_count", 0) for bucket in level_buckets}
    p1 = sum(count for level, count in levels.items() if int(level) >= 12)
    p2 = sum(count for level, count in levels.items() if 7 <= int(level) < 12)
    p3 = sum(count for level, count in levels.items() if 4 <= int(level) < 7)
    p4 = sum(count for level, count in levels.items() if int(level) < 4)

    timeline = []
    for bucket in aggs.get("timeline", {}).get("buckets", []):
        bucket_levels = {
            str(item.get("key")): item.get("doc_count", 0)
            for item in bucket.get("levels", {}).get("buckets", [])
        }
        timeline.append({
            "time": bucket.get("key_as_string", ""),
            "critical": sum(v for k, v in bucket_levels.items() if int(k) >= 12),
            "high": sum(v for k, v in bucket_levels.items() if 7 <= int(k) < 12),
            "medium": sum(v for k, v in bucket_levels.items() if 4 <= int(k) < 7),
            "low": sum(v for k, v in bucket_levels.items() if int(k) < 4),
        })

    total = raw.get("hits", {}).get("total", {})
    total_value = total.get("value", len(alerts)) if isinstance(total, dict) else total
    counts = {"p1": p1, "p2": p2, "p3": p3, "p4": p4}
    top_alert = alerts[0] if alerts else None
    kill_chain = _build_kill_chain(alerts, total_value, time_range, counts)
    if top_alert:
        triage = (
            f"Wazuh Indexer returned {total_value} alerts in {time_range}. "
            f"P1: {p1} | P2: {p2}. Active chain: {kill_chain['incident_id']}."
        )
    else:
        triage = f"Wazuh Indexer returned no alerts in {time_range} for the current filters."
    return {
        "source": "opensearch-live",
        "range": time_range,
        "total": total_value,
        "returned": len(alerts),
        "filters": [{"field": field, "value": value} for field, value in filters],
        "search": search,
        "counts": counts,
        "levels": levels,
        "facets": {
            "tactics": aggs.get("tactics", {}).get("buckets", []),
            "groups": aggs.get("groups", {}).get("buckets", []),
            "decoders": aggs.get("decoders", {}).get("buckets", []),
        },
        "timeline": timeline,
        "alerts": alerts,
        "kill_chain": kill_chain,
        "triage": triage,
    }


def get_compliance_risk_events(
    indexer_base: str,
    user: str,
    password: str,
    time_range: str = "7d",
    size: int = 50,
) -> dict:
    allowed_ranges = {"1h", "6h", "24h", "7d", "30d"}
    if time_range not in allowed_ranges:
        time_range = "7d"
    size = max(1, min(int(size or 50), 150))
    compliance_groups = [
        "sca",
        "syscheck",
        "rootcheck",
        "vulnerability-detector",
        "audit",
        "policy_monitoring",
        "osquery",
    ]
    should = [{"term": {"rule.groups": group}} for group in compliance_groups]
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [{"range": {"timestamp": {"gte": f"now-{time_range}", "lte": "now"}}}],
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "groups": {"terms": {"field": "rule.groups", "size": 30}},
            "levels": {"terms": {"field": "rule.level", "size": 20}},
            "agents": {"terms": {"field": "agent.name", "size": 20}},
        },
    }
    resp = requests.post(
        f"{indexer_base}/wazuh-alerts-4.x-*/_search",
        json=query,
        auth=(user, password),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    raw = resp.json()
    hits = raw.get("hits", {}).get("hits", [])
    findings = [_normalize_threat_hit(hit) for hit in hits]
    aggs = raw.get("aggregations", {})
    group_counts = {
        str(bucket.get("key")): bucket.get("doc_count", 0)
        for bucket in aggs.get("groups", {}).get("buckets", [])
    }
    level_counts = {
        str(bucket.get("key")): bucket.get("doc_count", 0)
        for bucket in aggs.get("levels", {}).get("buckets", [])
    }
    total = raw.get("hits", {}).get("total", {})
    total_value = total.get("value", len(findings)) if isinstance(total, dict) else total
    modules = {
        "sca": sum(v for k, v in group_counts.items() if "sca" in k),
        "fim": sum(v for k, v in group_counts.items() if "syscheck" in k),
        "rootcheck": sum(v for k, v in group_counts.items() if "rootcheck" in k),
        "vulnerability": sum(v for k, v in group_counts.items() if "vulnerability" in k),
        "audit": sum(v for k, v in group_counts.items() if "audit" in k or "policy" in k),
    }
    return {
        "source": "opensearch-live",
        "range": time_range,
        "total": total_value,
        "returned": len(findings),
        "modules": modules,
        "groups": group_counts,
        "levels": level_counts,
        "agents": aggs.get("agents", {}).get("buckets", []),
        "findings": findings,
    }


def _db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_stats(db_path: str) -> dict:
    conn = _db(db_path)
    c = conn.cursor()
    mal  = c.execute("SELECT COUNT(*) FROM events WHERE status='MALICIOUS'").fetchone()[0]
    sus  = c.execute("SELECT COUNT(*) FROM events WHERE status='SUSPICIOUS'").fetchone()[0]
    cln  = c.execute("SELECT COUNT(*) FROM events WHERE status='CLEAN'").fetchone()[0]
    inte = c.execute("SELECT COUNT(*) FROM events WHERE status='INTERNAL'").fetchone()[0]
    tot  = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    from backend.tickets import get_blocked_ips
    return {
        "malicious": mal, "suspicious": sus, "clean": cln,
        "internal": inte, "total": tot,
        "blocked": len(get_blocked_ips()),
    }


def get_top_ips(db_path: str) -> list[dict]:
    conn = _db(db_path)
    rows = conn.execute("""
        SELECT src_ip, status,
               COUNT(*) as hits,
               MAX(timestamp) as last_seen,
               MAX(abuse_score) as abuse_score,
               MAX(country_code) as country_code
        FROM events
        WHERE status IN ('MALICIOUS','SUSPICIOUS')
        GROUP BY src_ip
        ORDER BY hits DESC
        LIMIT 10
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_timeline(db_path: str) -> list[dict]:
    conn = _db(db_path)
    rows = conn.execute("""
        SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
               status, COUNT(*) as count
        FROM events
        WHERE timestamp >= datetime('now', '-24 hours')
          AND status IN ('MALICIOUS','SUSPICIOUS','CLEAN')
        GROUP BY hour, status
        ORDER BY hour ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_events(db_path: str) -> list[dict]:
    conn = _db(db_path)
    rows = conn.execute("""
        SELECT timestamp, src_ip, dst_ip, dst_port, protocol,
               status, action, abuse_score, country_code, isp
        FROM events
        ORDER BY timestamp DESC
        LIMIT 50
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_incidents(db_path: str) -> list[dict]:
    conn = _db(db_path)
    rows = conn.execute("""
        SELECT
          'INC-2026-' || printf('%04d', id) as incident_id,
          strftime('%H:%M', timestamp)       as ts,
          src_ip, dst_ip, dst_port,
          status, abuse_score, country_code, action, timestamp
        FROM events
        WHERE status IN ('MALICIOUS', 'SUSPICIOUS')
        ORDER BY timestamp DESC
        LIMIT 20
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_wazuh_debug(wazuh_base: str, wazuh_user: str, wazuh_pass: str) -> dict:
    """Endpoint de diagnóstico Wazuh Manager API."""
    results: dict = {}
    try:
        token = get_wazuh_token(wazuh_base, wazuh_user, wazuh_pass)
        results["auth"] = "OK"
        results["token_preview"] = token[:20] + "..."
    except Exception as exc:
        results["auth"] = f"ERRO: {exc}"
        return results

    for label, path in [
        ("alerts_simples",  "/alerts?limit=3"),
        ("alerts_select",   "/alerts?limit=3&select=timestamp,rule.id,rule.description,rule.level,agent.name"),
        ("query_level",     "/alerts?limit=1&q=rule.level>11"),
        ("mitre_query",     "/alerts?limit=3&q=rule.mitre.tactic=Persistence,Execution,Discovery"),
    ]:
        try:
            data = wazuh_request(wazuh_base, path, token)
            results[label] = "OK"
            results[f"{label}_count"] = data.get("data", {}).get("total_affected_items", 0)
        except Exception as exc:
            results[label] = f"ERRO: {exc}"
    return results

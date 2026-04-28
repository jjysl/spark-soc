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


def wazuh_request(base: str, path: str, token: str) -> dict:
    r = requests.get(
        f"{base}{path}",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


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
    token = get_wazuh_token(wazuh_base, wazuh_user, wazuh_pass)
    data = wazuh_request(
        wazuh_base,
        "/agents?select=id,name,ip,status,version&limit=500",
        token,
    )
    agents = data.get("data", {}).get("affected_items", [])
    by_status: dict[str, int] = {}
    for agent in agents:
        status = agent.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "total": data.get("data", {}).get("total_affected_items", len(agents)),
        "active": by_status.get("active", 0),
        "disconnected": by_status.get("disconnected", 0),
        "pending": by_status.get("pending", 0),
        "agents": agents,
    }


def get_executive_alerts(indexer_base: str, user: str, password: str) -> dict:
    query = {
        "size": 50,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp", "rule.id", "rule.description", "rule.level",
            "rule.mitre.tactic", "rule.mitre.id", "agent.name", "agent.ip",
            "data.srcip", "data.dstip", "data.src_ip", "data.dst_ip",
        ],
        "query": {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
        "aggs": {
            "levels": {"terms": {"field": "rule.level", "size": 20}},
            "hourly": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "hour",
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
        mitre = rule.get("mitre", {})
        tactics = mitre.get("tactic", [])
        techniques = mitre.get("id", [])
        alerts.append({
            "timestamp": src.get("timestamp", ""),
            "rule_id": rule.get("id", ""),
            "description": rule.get("description", ""),
            "level": rule.get("level", 0),
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", ""),
            "src_ip": data.get("srcip") or data.get("src_ip") or agent.get("ip", ""),
            "dst_ip": data.get("dstip") or data.get("dst_ip") or "",
            "mitre_tactic": tactics[0] if tactics else "",
            "mitre_technique": techniques[0] if techniques else "",
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
        "total": total.get("value", len(alerts)) if isinstance(total, dict) else total,
        "levels": levels,
        "p1": p1,
        "p2": p2,
        "p3": p3,
        "alerts": alerts,
        "timeline": timeline,
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

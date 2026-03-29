# mock_fortios.py — SPARK SOC Backend
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import requests
import urllib3
import random, sqlite3, os, json
from config import FORTIGATE_BASE_URL, FORTIGATE_API_KEY, INDEXER_BASE, INDEXER_USER, INDEXER_PASS

# Suprime warnings de SSL para certificados autoassinados do Wazuh
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder='.')
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'events.db')

IPS_SIMULADOS = [
    "192.168.1.100", "192.168.1.101",
    "185.220.101.45", "193.32.162.157",
    "45.155.205.233", "192.168.1.102",
]

blocked_ips = []

# ── Serve dashboard ────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'dashboard.html')

# ── FortiOS Mock Endpoints ─────────────────────────────────────────────────

@app.route('/api/v2/monitor/firewall/session', methods=['GET'])
def get_sessions():
    sessions = []
    for _ in range(5):
        ip = random.choice(IPS_SIMULADOS)
        sessions.append({
            "srcip":    ip,
            "dstip":    f"10.0.0.{random.randint(1,50)}",
            "proto":    random.choice(["tcp","udp"]),
            "dstport":  random.choice([80, 443, 22, 3389]),
            "bytes":    random.randint(1000, 50000),
            "duration": random.randint(1, 300)
        })
    return jsonify({"http_method":"GET","results":sessions,"vdom":"root","status":"success"})

@app.route('/api/v2/monitor/system/resource/usage', methods=['GET'])
def get_resources():
    # Tenta buscar do FortiGate real primeiro
    try:
        url = f"{FORTIGATE_BASE_URL}/api/v2/monitor/system/resource/usage"
        params = {"access_token": FORTIGATE_API_KEY, "interval": "1-min"}
        r = requests.get(url, params=params, timeout=10, verify=False)
        r.raise_for_status()
        return jsonify(r.json())
    except Exception as e:
        print(f"[FortiGate] Fallback mock: {e}")
        return jsonify({"results":{
            "cpu":     [{"current": random.randint(10,85)}],
            "mem":     [{"current": random.randint(30,75)}],
            "session": [{"current": random.randint(5,25)}]
        },"status":"success"})
    

@app.route('/api/v2/cmdb/firewall/address', methods=['POST', 'GET'])
def firewall_address():
    if request.method == 'POST':
        data = request.get_json()
        blocked_ips.append(data)
        print(f"[BLOCK] IP added: {data}")
        return jsonify({"status": "success", "data": data}), 200
    return jsonify({"status": "success", "blocked": blocked_ips})

# ── SPARK SOC Dashboard API ────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/spark/fortigate-status')
def fortigate_status():
    url = f"{FORTIGATE_BASE_URL}/api/v2/monitor/system/resource/usage"
    params = {"access_token": FORTIGATE_API_KEY, "interval": "1-min"}
    try:
        r = requests.get(url, params=params, timeout=10, verify=False)
        results = r.json().get("results", {})
        return jsonify({
            "source": "fortigate-live",
            "cpu":      results.get("cpu",     [{}])[0].get("current", 0),
            "mem":      results.get("mem",     [{}])[0].get("current", 0),
            "sessions": results.get("session", [{}])[0].get("current", 0),
        })
    except Exception as e:
        return jsonify({"source": "error", "error": str(e)})

@app.route('/spark/stats')
def spark_stats():
    conn = get_db()
    c = conn.cursor()
    mal  = c.execute("SELECT COUNT(*) FROM events WHERE status='MALICIOUS'").fetchone()[0]
    sus  = c.execute("SELECT COUNT(*) FROM events WHERE status='SUSPICIOUS'").fetchone()[0]
    cln  = c.execute("SELECT COUNT(*) FROM events WHERE status='CLEAN'").fetchone()[0]
    inte = c.execute("SELECT COUNT(*) FROM events WHERE status='INTERNAL'").fetchone()[0]
    tot  = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    return jsonify({
        "malicious": mal, "suspicious": sus, "clean": cln,
        "internal": inte, "total": tot, "blocked": len(blocked_ips)
    })

@app.route('/spark/top-ips')
def spark_top_ips():
    conn = get_db()
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
    return jsonify([dict(r) for r in rows])

@app.route('/spark/timeline')
def spark_timeline():
    conn = get_db()
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
    return jsonify([dict(r) for r in rows])

@app.route('/spark/recent-events')
def spark_recent_events():
    conn = get_db()
    rows = conn.execute("""
        SELECT timestamp, src_ip, dst_ip, dst_port, protocol,
               status, action, abuse_score, country_code, isp
        FROM events
        ORDER BY timestamp DESC
        LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/spark/blocked-ips')
def spark_blocked_ips():
    return jsonify(blocked_ips)

@app.route('/spark/block-ip', methods=['POST'])
def spark_block_ip():
    data = request.get_json()
    ip = data.get('ip', '')
    if not ip:
        return jsonify({"error": "IP não fornecido"}), 400
    entry = {"subnet": f"{ip}/32", "name": f"SPARK_BLOCK_{ip}", "ip": ip}
    blocked_ips.append(entry)
    print(f"[SPARK] IP bloqueado via dashboard: {ip}")
    return jsonify({"message": f"IP {ip} bloqueado com sucesso", "entry": entry})

# ── Wazuh API Helper ───────────────────────────────────────────────────────
# Usa requests (não urllib) para contornar problema de SSL no Windows
# com certificados autoassinados do Wazuh.

WAZUH_BASE = "https://localhost:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "Spark.SOC+2026"

_wazuh_token_cache = {"token": None, "time": 0}

def wazuh_get_token():
    """Autentica na API do Wazuh e retorna o JWT token com cache de 55min."""
    import time
    if _wazuh_token_cache["token"] and (time.time() - _wazuh_token_cache["time"]) < 3300:
        return _wazuh_token_cache["token"]
    r = requests.get(
        f"{WAZUH_BASE}/security/user/authenticate?raw=true",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False,
        timeout=15
    )
    r.raise_for_status()
    token = r.text.strip()
    _wazuh_token_cache["token"] = token
    _wazuh_token_cache["time"]  = time.time()
    print(f"[Wazuh] Token obtido: {token[:20]}...")
    return token

def wazuh_request(path, token):
    """Faz uma requisição GET autenticada à API do Wazuh."""
    r = requests.get(
        f"{WAZUH_BASE}{path}",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=15
    )
    r.raise_for_status()
    return r.json()

# ── Wazuh Endpoints ────────────────────────────────────────────────────────

@app.route('/spark/wazuh-alerts')
def spark_wazuh_alerts():
    try:
        # Busca nos últimos 7 dias — índice wildcard
        query = {
            "size": 50,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": [
                "timestamp", "rule.id", "rule.description", "rule.level",
                "rule.mitre.tactic", "rule.mitre.id",
                "agent.name", "agent.ip",
                "data.srcip", "data.dstip"
            ],
            "query": {
                "range": {
                    "timestamp": {
                        "gte": "now-7d/d",
                        "lte": "now"
                    }
                }
            }
        }

        r = requests.post(
            f"{INDEXER_BASE}/wazuh-alerts-4.x-*/_search",
            json=query,
            auth=(INDEXER_USER, INDEXER_PASS),
            verify=False,
            timeout=15
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])

        alerts = []
        levels = {}
        for hit in hits:
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            agent = src.get("agent", {})
            mitre = rule.get("mitre", {})
            tactics = mitre.get("tactic", [])
            techs = mitre.get("id", [])
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
                "mitre_technique": techs[0] if techs else "",
            })

        # Stats
        total = r.json().get("hits", {}).get("total", {}).get("value", 0)
        critical = sum(1 for a in alerts if a["level"] >= 12)
        auth_fail = sum(1 for a in alerts if str(a.get("rule_id","")) in ["5710","5711","5712","18113"])
        auth_ok   = sum(1 for a in alerts if str(a.get("rule_id","")) in ["5715","18137"])

        return jsonify({
            "source": "opensearch-live",
            "levels": levels,
            "alerts": alerts,
            "stats": {
                "total":         total,
                "critical":      critical,
                "auth_failures": auth_fail,
                "auth_success":  auth_ok,
            }
        })

    except Exception as e:
        print(f"[OpenSearch] Erro: {e}")
        # fallback SQLite
        conn = get_db()
        mal = conn.execute("SELECT COUNT(*) FROM events WHERE status='MALICIOUS'").fetchone()[0]
        sus = conn.execute("SELECT COUNT(*) FROM events WHERE status='SUSPICIOUS'").fetchone()[0]
        cln = conn.execute("SELECT COUNT(*) FROM events WHERE status='CLEAN'").fetchone()[0]
        conn.close()
        return jsonify({
            "source": "sqlite-fallback",
            "levels": {"10": mal, "3": cln},
            "alerts": [],
            "stats": {"total": mal+sus+cln, "critical": 0, "auth_failures": 0, "auth_success": 0}
        })

@app.route('/spark/wazuh-debug')
def wazuh_debug():
    """
    Endpoint de diagnóstico — verifica conectividade com a API do Wazuh
    passo a passo. Remover após confirmar que tudo funciona.
    """
    results = {}

    # Passo 1: autenticação
    try:
        token = wazuh_get_token()
        results["auth"] = "OK"
        results["token_preview"] = token[:20] + "..."
    except Exception as e:
        results["auth"] = f"ERRO: {e}"
        return jsonify(results)

    # Passo 2: alertas simples (sem filtros)
    try:
        data = wazuh_request("/alerts?limit=3", token)
        results["alerts_simples"] = "OK"
        results["total_alerts"]   = data.get("data", {}).get("total_affected_items", 0)
        results["amostra"]        = data.get("data", {}).get("affected_items", [])[:2]
    except Exception as e:
        results["alerts_simples"] = f"ERRO: {e}"

    # Passo 3: alertas com select de campos específicos
    try:
        data = wazuh_request(
            "/alerts?limit=3&select=timestamp,rule.id,rule.description,rule.level,agent.name",
            token
        )
        results["alerts_select"]  = "OK"
        results["amostra_select"] = data.get("data", {}).get("affected_items", [])[:2]
    except Exception as e:
        results["alerts_select"] = f"ERRO: {e}"

    # Passo 4: query por level crítico
    try:
        data = wazuh_request("/alerts?limit=1&q=rule.level>11", token)
        results["query_level"]   = "OK"
        results["critical_count"] = data.get("data", {}).get("total_affected_items", 0)
    except Exception as e:
        results["query_level"] = f"ERRO: {e}"

    # Passo 5: MITRE — verifica se campo existe
    try:
        data = wazuh_request(
            "/alerts?limit=3&q=rule.mitre.tactic=Persistence,Execution,Discovery",
            token
        )
        results["mitre_query"]  = "OK"
        results["mitre_count"]  = data.get("data", {}).get("total_affected_items", 0)
        results["mitre_sample"] = data.get("data", {}).get("affected_items", [])[:1]
    except Exception as e:
        results["mitre_query"] = f"ERRO (pode ser normal se nao houver alertas MITRE): {e}"

    return jsonify(results)

@app.route('/spark/incidents')
def spark_incidents():
    conn = get_db()
    rows = conn.execute('''
        SELECT
          'INC-2026-' || printf('%04d', id) as incident_id,
          strftime('%H:%M', timestamp)       as ts,
          src_ip                             as src_ip,
          dst_ip                             as dst_ip,
          dst_port,
          status,
          abuse_score,
          country_code,
          action,
          timestamp
        FROM events
        WHERE status IN ('MALICIOUS', 'SUSPICIOUS')
        ORDER BY timestamp DESC
        LIMIT 20
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

if __name__ == '__main__':
    print("=" * 55)
    print("  SPARK SOC — Backend + Dashboard")
    print("  http://localhost:5000  →  Dashboard")
    print("  http://localhost:5000/spark/stats  →  API")
    print("  http://localhost:5000/spark/wazuh-debug  →  Diagnóstico Wazuh")
    print("=" * 55)
    app.run(host='0.0.0.0', port=5000, debug=True)
"""
SPARK SOC — Integração FortiGate
==================================
Encapsula todas as chamadas à FortiOS REST API.
Quando o FortiGate está offline, retorna dados mock para a PoC.
"""
import random
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IPS_SIMULADOS = [
    "192.168.1.100", "192.168.1.101",
    "185.220.101.45", "193.32.162.157",
    "45.155.205.233", "192.168.1.102",
]


def _headers(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


# ── Monitor APIs ───────────────────────────────────────────────────────────

def get_resource_usage(base_url: str, api_key: str) -> dict:
    """Retorna CPU, memória e sessões do FortiGate. Fallback para mock."""
    try:
        url = f"{base_url}/api/v2/monitor/system/resource/usage"
        r = requests.get(
            url,
            params={"access_token": api_key, "interval": "1-min"},
            timeout=10,
            verify=False,
        )
        r.raise_for_status()
        results = r.json().get("results", {})
        return {
            "source":   "fortigate-live",
            "cpu":      results.get("cpu",     [{}])[0].get("current", 0),
            "mem":      results.get("mem",     [{}])[0].get("current", 0),
            "sessions": results.get("session", [{}])[0].get("current", 0),
        }
    except Exception as exc:
        return {
            "source":   "mock",
            "cpu":      random.randint(10, 85),
            "mem":      random.randint(30, 75),
            "sessions": random.randint(5000, 25000),
            "error":    str(exc),
        }


def get_active_sessions(base_url: str, api_key: str) -> list[dict]:
    """Retorna sessões ativas. Fallback mock."""
    try:
        url = f"{base_url}/api/v2/monitor/firewall/session"
        r = requests.get(url, params={"access_token": api_key}, timeout=10, verify=False)
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception:
        return [
            {
                "srcip":    random.choice(IPS_SIMULADOS),
                "dstip":    f"10.0.0.{random.randint(1, 50)}",
                "proto":    random.choice(["tcp", "udp"]),
                "dstport":  random.choice([80, 443, 22, 3389]),
                "bytes":    random.randint(1000, 50000),
                "duration": random.randint(1, 300),
            }
            for _ in range(5)
        ]


# ── Configuration APIs ─────────────────────────────────────────────────────

def create_address_object(base_url: str, api_key: str, ip: str) -> str:
    """Cria objeto de endereço no FortiGate para bloquear IP. Retorna status."""
    try:
        url = f"{base_url}/api/v2/cmdb/firewall/address"
        payload = {
            "name":    f"SPARK_BLOCK_{ip.replace('.', '_')}",
            "subnet":  f"{ip}/32",
            "comment": "Bloqueado automaticamente pelo SPARK SOC",
        }
        r = requests.post(
            url,
            params={"access_token": api_key},
            json=payload,
            verify=False,
            timeout=8,
        )
        return "ok" if r.ok else f"http_{r.status_code}"
    except Exception as exc:
        return f"offline ({type(exc).__name__})"


def delete_address_object(base_url: str, api_key: str, ip: str) -> str:
    """Remove objeto de endereço do FortiGate. Retorna status."""
    name = f"SPARK_BLOCK_{ip.replace('.', '_')}"
    try:
        url = f"{base_url}/api/v2/cmdb/firewall/address/{name}"
        r = requests.delete(
            url,
            params={"access_token": api_key},
            verify=False,
            timeout=8,
        )
        return "ok" if r.ok else f"http_{r.status_code}"
    except Exception as exc:
        return f"offline ({type(exc).__name__})"
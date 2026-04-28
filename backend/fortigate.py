"""
FortiGate REST API client for SPARK SOC.

All functions return live FortiGate data or an explicit offline/error state.
They do not generate synthetic telemetry.
"""
from __future__ import annotations

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _request(method: str, base_url: str, path: str, api_key: str, **kwargs) -> requests.Response:
    if not base_url:
        raise ValueError("FORTIGATE_BASE_URL is not configured")
    if not api_key:
        raise ValueError("FORTIGATE_API_KEY is not configured")

    params = kwargs.pop("params", {}) or {}
    params.setdefault("access_token", api_key)
    return requests.request(
        method,
        f"{base_url.rstrip('/')}{path}",
        params=params,
        verify=False,
        timeout=kwargs.pop("timeout", 10),
        **kwargs,
    )


def get_resource_usage(base_url: str, api_key: str) -> dict:
    """Return live CPU, memory, disk and session counters from FortiGate."""
    try:
        response = _request(
            "GET",
            base_url,
            "/api/v2/monitor/system/resource/usage",
            api_key,
            params={"interval": "1-min"},
            timeout=10,
        )
        response.raise_for_status()
        results = response.json().get("results", {})
        return {
            "source": "fortigate-live",
            "cpu": results.get("cpu", [{}])[0].get("current", 0),
            "mem": results.get("mem", [{}])[0].get("current", 0),
            "disk": results.get("disk", [{}])[0].get("current", 0),
            "sessions": results.get("session", [{}])[0].get("current", 0),
            "serial": response.json().get("serial", ""),
            "version": response.json().get("version", ""),
        }
    except Exception as exc:
        return {
            "source": "offline",
            "cpu": 0,
            "mem": 0,
            "disk": 0,
            "sessions": 0,
            "error": str(exc),
        }


def get_active_sessions(base_url: str, api_key: str) -> list[dict]:
    """Return live FortiGate firewall sessions when the endpoint is available."""
    response = _request(
        "GET",
        base_url,
        "/api/v2/monitor/firewall/session",
        api_key,
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") == "error":
        raise RuntimeError(payload.get("message") or "FortiGate session endpoint returned error")
    results = payload.get("results", [])
    return results if isinstance(results, list) else []


def create_address_object(base_url: str, api_key: str, ip: str) -> str:
    """Create a FortiGate address object for a blocked IP."""
    try:
        payload = {
            "name": f"SPARK_BLOCK_{ip.replace('.', '_')}",
            "subnet": f"{ip}/32",
            "comment": "Blocked by SPARK SOC",
        }
        response = _request(
            "POST",
            base_url,
            "/api/v2/cmdb/firewall/address",
            api_key,
            json=payload,
            timeout=8,
        )
        return "ok" if response.ok else f"http_{response.status_code}"
    except Exception as exc:
        return f"offline ({type(exc).__name__})"


def delete_address_object(base_url: str, api_key: str, ip: str) -> str:
    """Delete a FortiGate address object for a blocked IP."""
    try:
        name = f"SPARK_BLOCK_{ip.replace('.', '_')}"
        response = _request(
            "DELETE",
            base_url,
            f"/api/v2/cmdb/firewall/address/{name}",
            api_key,
            timeout=8,
        )
        return "ok" if response.ok else f"http_{response.status_code}"
    except Exception as exc:
        return f"offline ({type(exc).__name__})"

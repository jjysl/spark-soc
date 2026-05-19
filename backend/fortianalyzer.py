"""FortiAnalyzer JSON-RPC client for SPARK SOC evidence readiness.

FortiAnalyzer uses a JSON-RPC API that varies by version, ADOM and token
permissions. This module intentionally keeps calls defensive: status uses the
validated ``/sys/status`` endpoint, while evidence search is best-effort and
never returns synthetic log records.
"""
from __future__ import annotations

import ipaddress
from typing import Any

import requests
import urllib3
from requests import exceptions as request_exceptions

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _connector_ready() -> dict:
    return {
        "configured": False,
        "connected": False,
        "status": "connector_ready",
        "source": "fortianalyzer",
        "message": "FortiAnalyzer connector ready for configuration.",
        "endpoint_used": "",
        "error": "",
    }


def _auth_header(api_key: str) -> dict:
    token = (api_key or "").removeprefix("Bearer ").strip()
    return {"Authorization": f"Bearer {token}"}


def _jsonrpc(base_url: str, api_key: str, method: str, params: list[dict], timeout: int = 8) -> tuple[dict, int, str]:
    endpoint = f"{base_url.rstrip('/')}/jsonrpc"
    response = requests.post(
        endpoint,
        headers={"Content-Type": "application/json", **_auth_header(api_key)},
        json={"id": 1, "method": method, "params": params},
        verify=False,
        timeout=timeout,
    )
    status_code = response.status_code
    if status_code in (401, 403):
        return {"status": {"code": status_code, "message": "authentication failed"}}, status_code, endpoint
    if status_code >= 500:
        return {"status": {"code": status_code, "message": "FortiAnalyzer endpoint error"}}, status_code, endpoint
    try:
        return response.json(), status_code, endpoint
    except ValueError:
        return {"status": {"code": status_code, "message": "FortiAnalyzer returned a non-JSON response"}}, status_code, endpoint


def _result_item(payload: dict) -> dict:
    result = payload.get("result")
    if isinstance(result, list) and result:
        first = result[0]
        return first if isinstance(first, dict) else {}
    if isinstance(result, dict):
        return result
    return payload if isinstance(payload, dict) else {}


def _status_code(payload: dict, http_status: int) -> int:
    item = _result_item(payload)
    status = item.get("status") if isinstance(item, dict) else {}
    if isinstance(status, dict):
        try:
            return int(status.get("code", http_status))
        except (TypeError, ValueError):
            return http_status
    try:
        return int(payload.get("status", {}).get("code", http_status))
    except (AttributeError, TypeError, ValueError):
        return http_status


def _status_message(payload: dict, default: str = "") -> str:
    item = _result_item(payload)
    status = item.get("status") if isinstance(item, dict) else {}
    if isinstance(status, dict):
        return str(status.get("message") or status.get("desc") or default)
    status = payload.get("status") if isinstance(payload, dict) else {}
    if isinstance(status, dict):
        return str(status.get("message") or status.get("desc") or default)
    return default


def _data(payload: dict) -> dict:
    item = _result_item(payload)
    data = item.get("data") if isinstance(item, dict) else {}
    return data if isinstance(data, dict) else {}


def _lookup(data: dict, *keys: str) -> Any:
    lowered = {str(key).strip().lower().replace("_", " "): value for key, value in data.items()}
    for key in keys:
        normalized = key.strip().lower().replace("_", " ")
        if normalized in lowered:
            return lowered[normalized]
    return ""


def _request_error(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, (request_exceptions.Timeout, request_exceptions.ConnectTimeout, request_exceptions.ReadTimeout)):
        return "timeout", "FortiAnalyzer connector timed out."
    if isinstance(exc, request_exceptions.ConnectionError):
        return "unavailable", "FortiAnalyzer endpoint is unreachable."
    return "endpoint_error", "FortiAnalyzer connector returned an endpoint error."


def get_status(base_url: str, api_key: str) -> dict:
    """Return FortiAnalyzer connectivity and platform metadata.

    Uses JSON-RPC ``get`` against ``/sys/status``, matching the validated cloud
    command. The function is safe for dashboard use and never raises.
    """
    if not base_url or not api_key:
        return _connector_ready()

    try:
        payload, http_status, endpoint = _jsonrpc(base_url, api_key, "get", [{"url": "/sys/status"}], timeout=8)
    except Exception as exc:
        status, message = _request_error(exc)
        return {
            "configured": True,
            "connected": False,
            "status": status,
            "source": "fortianalyzer",
            "message": message,
            "endpoint_used": f"{base_url.rstrip('/')}/jsonrpc",
            "error": f"{type(exc).__name__}: {exc}",
        }

    rpc_code = _status_code(payload, http_status)
    message = _status_message(payload, "FortiAnalyzer status check completed.")
    if http_status in (401, 403) or rpc_code in (401, 403, -11):
        return {
            "configured": True,
            "connected": False,
            "status": "auth_failed",
            "source": "fortianalyzer",
            "message": "FortiAnalyzer authentication failed.",
            "endpoint_used": endpoint,
            "http_status": http_status,
            "error": message,
        }
    if http_status >= 400 or rpc_code not in (0, 200):
        return {
            "configured": True,
            "connected": False,
            "status": "unavailable" if http_status >= 500 else "endpoint_error",
            "source": "fortianalyzer",
            "message": message or "FortiAnalyzer status endpoint returned an error.",
            "endpoint_used": endpoint,
            "http_status": http_status,
            "rpc_code": rpc_code,
            "error": message,
        }

    data = _data(payload)
    version = str(_lookup(data, "Version", "version") or "")
    build = ""
    if "-build" in version:
        version, build = version.split("-build", 1)
        build = f"build{build}"
    return {
        "configured": True,
        "connected": True,
        "status": "online",
        "source": "fortianalyzer-live",
        "message": "FortiAnalyzer Online",
        "endpoint_used": endpoint,
        "http_status": http_status,
        "rpc_code": rpc_code,
        "platform": _lookup(data, "Platform Full Name", "Platform Type", "platform") or "",
        "platform_type": _lookup(data, "Platform Type") or "",
        "version": version,
        "build": build,
        "serial": _lookup(data, "Serial Number", "serial") or "",
        "hostname": _lookup(data, "Hostname", "host name") or "",
        "license_status": _lookup(data, "License Status", "license") or "",
        "error": "",
    }


def _extract_items(payload: dict) -> list[dict]:
    data = _data(payload)
    for key in ("logs", "items", "entries", "data"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if isinstance(data.get("result"), list):
        return [item for item in data["result"] if isinstance(item, dict)]
    if isinstance(data, dict) and data:
        return [data] if any(key in data for key in ("srcip", "dstip", "policyid", "itime", "date", "time")) else []
    return []


def get_evidence_for_ip(base_url: str, api_key: str, ip: str, limit: int = 10) -> dict:
    """Search FortiAnalyzer for IP evidence without fabricating records.

    The first phase confirms connector health through ``/sys/status``. The log
    query is intentionally conservative because FortiAnalyzer log endpoints vary
    by ADOM and role. Unsupported endpoints return ``evidence_pending`` with the
    exact endpoint used so operators can tune the connector safely.
    """
    target_ip = (ip or "").strip()
    try:
        target_ip = str(ipaddress.ip_address(target_ip))
    except ValueError:
        return {
            "configured": bool(base_url and api_key),
            "connected": False,
            "status": "invalid_ip",
            "source": "fortianalyzer",
            "ip": ip or "",
            "message": "A valid IP address is required for FortiAnalyzer evidence search.",
            "log_count": 0,
            "items": [],
            "references": [],
            "error": "invalid_ip",
        }

    status = get_status(base_url, api_key)
    if not status.get("configured"):
        return {**status, "ip": target_ip, "evidence_status": "connector_ready", "log_count": 0, "items": [], "references": []}
    if status.get("status") == "auth_failed":
        return {**status, "ip": target_ip, "evidence_status": "auth_failed", "log_count": 0, "items": [], "references": []}
    if not status.get("connected"):
        return {**status, "ip": target_ip, "evidence_status": status.get("status", "unavailable"), "log_count": 0, "items": [], "references": []}

    query = {
        "url": "/logview/adom/root/logsearch",
        "filter": [["srcip", "==", target_ip]],
        "limit": max(1, min(int(limit or 10), 50)),
    }
    try:
        payload, http_status, endpoint = _jsonrpc(base_url, api_key, "get", [query], timeout=10)
    except Exception as exc:
        failure, message = _request_error(exc)
        return {
            "configured": True,
            "connected": True,
            "status": failure,
            "source": "fortianalyzer-live",
            "ip": target_ip,
            "evidence_status": "evidence_pending",
            "message": message,
            "endpoint_used": f"{base_url.rstrip('/')}/jsonrpc",
            "log_count": 0,
            "items": [],
            "references": [],
            "error": f"{type(exc).__name__}: {exc}",
        }

    rpc_code = _status_code(payload, http_status)
    message = _status_message(payload, "FortiAnalyzer evidence query completed.")
    if http_status in (401, 403) or rpc_code in (401, 403, -11):
        return {
            "configured": True,
            "connected": True,
            "status": "auth_failed",
            "source": "fortianalyzer-live",
            "ip": target_ip,
            "evidence_status": "auth_failed",
            "message": "FortiAnalyzer authentication failed for evidence search.",
            "endpoint_used": endpoint,
            "log_count": 0,
            "items": [],
            "references": [],
            "error": message,
        }
    if http_status >= 400 or rpc_code not in (0, 200):
        return {
            "configured": True,
            "connected": True,
            "status": "evidence_pending",
            "source": "fortianalyzer-live",
            "ip": target_ip,
            "evidence_status": "evidence_pending",
            "message": message or "FortiAnalyzer evidence query requires ADOM/log endpoint tuning.",
            "endpoint_used": endpoint,
            "query_url": query["url"],
            "log_count": 0,
            "items": [],
            "references": [],
            "error": message,
        }

    items = _extract_items(payload)[: query["limit"]]
    references = [
        {
            "policyid": item.get("policyid") or item.get("policy_id") or "",
            "logid": item.get("logid") or item.get("id") or "",
            "timestamp": item.get("itime") or f"{item.get('date', '')} {item.get('time', '')}".strip(),
            "srcip": item.get("srcip") or item.get("src_ip") or "",
            "dstip": item.get("dstip") or item.get("dst_ip") or "",
            "action": item.get("action") or "",
        }
        for item in items
    ]
    return {
        "configured": True,
        "connected": True,
        "status": "evidence_collected" if items else "no_results",
        "source": "fortianalyzer-live",
        "ip": target_ip,
        "evidence_status": "evidence_collected" if items else "no_results",
        "message": f"FortiAnalyzer returned {len(items)} log record(s)." if items else "No FortiAnalyzer log records matched this IP.",
        "endpoint_used": endpoint,
        "query_url": query["url"],
        "log_count": len(items),
        "items": items,
        "references": references,
        "error": "",
    }

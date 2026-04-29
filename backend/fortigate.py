"""
FortiGate REST API client for SPARK SOC.

All functions return live FortiGate data or an explicit offline/error state.
They do not generate synthetic telemetry.
"""
from __future__ import annotations

import ipaddress
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_BLOCKLIST_GROUP = "SPARK_BLOCKLIST"
DEFAULT_BLOCKLIST_POLICY = "SPARK_BLOCKLIST_DENY"


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


def _json_request(method: str, base_url: str, path: str, api_key: str, **kwargs) -> dict:
    response = _request(method, base_url, path, api_key, **kwargs)
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") == "error":
        raise RuntimeError(payload.get("message") or payload.get("error") or f"FortiGate API error on {path}")
    return payload


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


def _object_name_for_ip(ip: str) -> str:
    return f"SPARK_BLOCK_{ip.replace('.', '_')}"


def _member_names(items) -> list[str]:
    names = []
    for item in _as_list(items):
        if isinstance(item, dict):
            name = item.get("name") or item.get("q_origin_key")
        else:
            name = str(item)
        if name and name not in names:
            names.append(name)
    return names


def _safe_call(label: str, func, *args, **kwargs) -> dict:
    try:
        return {"source": "fortigate-live", "label": label, "items": func(*args, **kwargs), "error": ""}
    except Exception as exc:
        return {"source": "offline", "label": label, "items": [], "error": str(exc)}


def get_interfaces(base_url: str, api_key: str) -> list[dict]:
    """Return FortiGate interface inventory from Monitor API, falling back to CMDB."""
    try:
        payload = _json_request("GET", base_url, "/api/v2/monitor/system/interface", api_key, timeout=8)
        rows = _as_list(payload.get("results"))
        return [
            {
                "name": item.get("name") or item.get("interface") or item.get("q_origin_key") or "unknown",
                "alias": item.get("alias", ""),
                "ip": item.get("ip") or item.get("ipaddr") or item.get("address") or "",
                "status": item.get("status") or item.get("link") or item.get("state") or "unknown",
                "speed": item.get("speed") or item.get("link_speed") or "",
                "role": item.get("role") or item.get("type") or "",
                "rx_bytes": item.get("rx_bytes") or item.get("rx-byte") or item.get("rx_bytes_rate") or 0,
                "tx_bytes": item.get("tx_bytes") or item.get("tx-byte") or item.get("tx_bytes_rate") or 0,
            }
            for item in rows
        ]
    except Exception:
        payload = _json_request("GET", base_url, "/api/v2/cmdb/system/interface", api_key, timeout=8)
        rows = _as_list(payload.get("results"))
        return [
            {
                "name": item.get("name") or item.get("q_origin_key") or "unknown",
                "alias": item.get("alias", ""),
                "ip": item.get("ip") or item.get("ipaddr") or "",
                "status": item.get("status", "unknown"),
                "speed": item.get("speed", ""),
                "role": item.get("role") or item.get("type") or "",
                "rx_bytes": 0,
                "tx_bytes": 0,
            }
            for item in rows
        ]


def get_firewall_policies(base_url: str, api_key: str) -> list[dict]:
    """Return firewall policy objects from FortiOS CMDB API."""
    payload = _json_request("GET", base_url, "/api/v2/cmdb/firewall/policy", api_key, timeout=8)
    rows = _as_list(payload.get("results"))
    policies = []
    for item in rows:
        srcintf = item.get("srcintf") or []
        dstintf = item.get("dstintf") or []
        srcaddr = item.get("srcaddr") or []
        dstaddr = item.get("dstaddr") or []
        service = item.get("service") or []
        policies.append({
            "policyid": item.get("policyid") or item.get("q_origin_key") or item.get("id") or "",
            "name": item.get("name") or item.get("comments") or "Unnamed policy",
            "status": item.get("status", "unknown"),
            "action": item.get("action", ""),
            "nat": item.get("nat", ""),
            "srcintf": ", ".join(obj.get("name", str(obj)) for obj in srcintf) if isinstance(srcintf, list) else str(srcintf),
            "dstintf": ", ".join(obj.get("name", str(obj)) for obj in dstintf) if isinstance(dstintf, list) else str(dstintf),
            "srcaddr": ", ".join(obj.get("name", str(obj)) for obj in srcaddr) if isinstance(srcaddr, list) else str(srcaddr),
            "dstaddr": ", ".join(obj.get("name", str(obj)) for obj in dstaddr) if isinstance(dstaddr, list) else str(dstaddr),
            "service": ", ".join(obj.get("name", str(obj)) for obj in service) if isinstance(service, list) else str(service),
            "schedule": item.get("schedule", ""),
            "comments": item.get("comments", ""),
        })
    return policies


def get_address_objects(base_url: str, api_key: str) -> list[dict]:
    """Return FortiGate firewall address objects from the CMDB API."""
    payload = _json_request("GET", base_url, "/api/v2/cmdb/firewall/address", api_key, timeout=8)
    rows = _as_list(payload.get("results"))
    return [
        {
            "name": item.get("name") or item.get("q_origin_key") or "",
            "type": item.get("type", ""),
            "subnet": item.get("subnet", ""),
            "comment": item.get("comment", ""),
        }
        for item in rows
    ]


def get_address_group(base_url: str, api_key: str, group_name: str = DEFAULT_BLOCKLIST_GROUP) -> dict:
    """Return one FortiGate address group and its existing members."""
    payload = _json_request(
        "GET",
        base_url,
        f"/api/v2/cmdb/firewall/addrgrp/{group_name}",
        api_key,
        timeout=8,
    )
    results = payload.get("results", {})
    if isinstance(results, list):
        results = results[0] if results else {}
    members = _member_names(results.get("member"))
    return {
        "name": results.get("name") or results.get("q_origin_key") or group_name,
        "members": members,
        "member_count": len(members),
        "comment": results.get("comment", ""),
    }


def get_static_routes(base_url: str, api_key: str) -> list[dict]:
    """Return configured static routes from FortiOS CMDB API."""
    payload = _json_request("GET", base_url, "/api/v2/cmdb/router/static", api_key, timeout=8)
    rows = _as_list(payload.get("results"))
    return [
        {
            "seq_num": item.get("seq-num") or item.get("seq_num") or item.get("q_origin_key") or "",
            "dst": item.get("dst", ""),
            "gateway": item.get("gateway", ""),
            "device": item.get("device", ""),
            "distance": item.get("distance", ""),
            "status": item.get("status", "unknown"),
        }
        for item in rows
    ]


def get_policy_statistics(base_url: str, api_key: str) -> list[dict]:
    """Return policy hit counters when the FortiOS monitor endpoint is available."""
    payload = _json_request("GET", base_url, "/api/v2/monitor/firewall/policy", api_key, timeout=8)
    rows = _as_list(payload.get("results"))
    return [
        {
            "policyid": item.get("policyid") or item.get("id") or item.get("q_origin_key") or "",
            "bytes": item.get("bytes") or item.get("byte") or item.get("traffic") or 0,
            "packets": item.get("packets") or item.get("packet") or 0,
            "sessions": item.get("sessions") or item.get("session") or 0,
            "hit_count": item.get("hit_count") or item.get("hit-count") or item.get("count") or 0,
        }
        for item in rows
    ]


def get_system_status(base_url: str, api_key: str) -> dict:
    """Return FortiGate system status from Monitor API when available."""
    payload = _json_request("GET", base_url, "/api/v2/monitor/system/status", api_key, timeout=8)
    results = payload.get("results", {})
    if not isinstance(results, dict):
        results = {}
    return {
        "hostname": results.get("hostname", ""),
        "serial": payload.get("serial") or results.get("serial", ""),
        "version": payload.get("version") or results.get("version", ""),
        "build": payload.get("build") or results.get("build", ""),
        "uptime": results.get("uptime", ""),
        "ha_mode": results.get("ha_mode") or results.get("ha-mode") or "",
    }


def get_network_inventory(base_url: str, api_key: str) -> dict:
    """Collect Monitor/CMDB API data for Network & Endpoint without synthetic fallback."""
    resource = get_resource_usage(base_url, api_key)
    interfaces = _safe_call("interfaces", get_interfaces, base_url, api_key)
    policies = _safe_call("policies", get_firewall_policies, base_url, api_key)
    routes = _safe_call("routes", get_static_routes, base_url, api_key)
    policy_stats = _safe_call("policy_stats", get_policy_statistics, base_url, api_key)
    system = _safe_call("system_status", lambda b, k: [get_system_status(b, k)], base_url, api_key)
    address_objects = _safe_call("address_objects", get_address_objects, base_url, api_key)
    blocklist = _safe_call("blocklist_group", lambda b, k: [get_address_group(b, k)], base_url, api_key)
    policy_names = {str(item.get("name", "")) for item in policies["items"]}

    return {
        **resource,
        "system": system["items"][0] if system["items"] else {},
        "interfaces": interfaces["items"],
        "policies": policies["items"],
        "routes": routes["items"],
        "policy_stats": policy_stats["items"],
        "address_objects": address_objects["items"],
        "blocklist_group": blocklist["items"][0] if blocklist["items"] else {},
        "blocklist_policy_present": DEFAULT_BLOCKLIST_POLICY in policy_names,
        "api_status": {
            "resource_usage": {"endpoint": "/api/v2/monitor/system/resource/usage", "ok": resource.get("source") == "fortigate-live", "error": resource.get("error", "")},
            "interfaces": {"endpoint": "/api/v2/monitor/system/interface or /api/v2/cmdb/system/interface", "ok": interfaces["source"] == "fortigate-live", "error": interfaces["error"]},
            "policies": {"endpoint": "/api/v2/cmdb/firewall/policy", "ok": policies["source"] == "fortigate-live", "error": policies["error"]},
            "routes": {"endpoint": "/api/v2/cmdb/router/static", "ok": routes["source"] == "fortigate-live", "error": routes["error"]},
            "policy_stats": {"endpoint": "/api/v2/monitor/firewall/policy", "ok": policy_stats["source"] == "fortigate-live", "error": policy_stats["error"]},
            "system_status": {"endpoint": "/api/v2/monitor/system/status", "ok": system["source"] == "fortigate-live", "error": system["error"]},
            "address_objects": {"endpoint": "/api/v2/cmdb/firewall/address", "ok": address_objects["source"] == "fortigate-live", "error": address_objects["error"]},
            "blocklist_group": {"endpoint": f"/api/v2/cmdb/firewall/addrgrp/{DEFAULT_BLOCKLIST_GROUP}", "ok": blocklist["source"] == "fortigate-live", "error": blocklist["error"]},
        },
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
        ipaddress.IPv4Address(ip)
        payload = {
            "name": _object_name_for_ip(ip),
            "subnet": f"{ip} 255.255.255.255",
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


def add_ip_to_blocklist(
    base_url: str,
    api_key: str,
    ip: str,
    group_name: str = DEFAULT_BLOCKLIST_GROUP,
    policy_name: str = DEFAULT_BLOCKLIST_POLICY,
) -> dict:
    """Create/use a /32 address object and add it to the SPARK blocklist group."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return {"ok": False, "status": "invalid_ip", "message": "Invalid IPv4 address.", "ip": ip}

    object_name = _object_name_for_ip(ip)
    evidence = {
        "ok": False,
        "status": "pending",
        "ip": ip,
        "object": object_name,
        "group": group_name,
        "policy": policy_name,
        "object_created": False,
        "object_existed": False,
        "group_updated": False,
        "already_member": False,
        "policy_found": False,
        "enforcement_path": "pending network routing validation",
        "message": "",
    }

    try:
        try:
            _json_request("GET", base_url, f"/api/v2/cmdb/firewall/address/{object_name}", api_key, timeout=8)
            evidence["object_existed"] = True
        except Exception:
            payload = {
                "name": object_name,
                "subnet": f"{ip} 255.255.255.255",
                "comment": "Blocked by SPARK SOC",
            }
            created = _request("POST", base_url, "/api/v2/cmdb/firewall/address", api_key, json=payload, timeout=8)
            if not created.ok:
                evidence.update({"status": f"http_{created.status_code}", "message": created.text[:500]})
                return evidence
            evidence["object_created"] = True

        group = get_address_group(base_url, api_key, group_name)
        members = group.get("members", [])
        if object_name in members:
            evidence["already_member"] = True
        else:
            next_members = members + [object_name]
            response = _request(
                "PUT",
                base_url,
                f"/api/v2/cmdb/firewall/addrgrp/{group_name}",
                api_key,
                json={"member": [{"name": name} for name in next_members]},
                timeout=8,
            )
            if not response.ok:
                evidence.update({"status": f"http_{response.status_code}", "message": response.text[:500]})
                return evidence
            evidence["group_updated"] = True

        policies = get_firewall_policies(base_url, api_key)
        evidence["policy_found"] = any(policy.get("name") == policy_name for policy in policies)
        evidence["ok"] = True
        evidence["status"] = "success"
        evidence["message"] = (
            "IP added to FortiGate blocklist via FortiOS REST API. "
            "Runtime enforcement pending network routing validation."
        )
        return evidence
    except Exception as exc:
        evidence.update({"status": "error", "message": str(exc)})
        return evidence


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

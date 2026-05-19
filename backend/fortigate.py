"""
FortiGate REST API client for SPARK SOC.

All functions return live FortiGate data or an explicit offline/error state.
They do not generate synthetic telemetry.
"""
from __future__ import annotations

import ipaddress
import requests
import urllib3
from requests import exceptions as request_exceptions

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_BLOCKLIST_GROUP = "SPARK_BLOCKLIST"
DEFAULT_BLOCKLIST_POLICY = "SPARK_AUTO_BLOCK"
DEFAULT_QUARANTINE_GROUP = "SPARK_QUARANTINE_LIST"
DEFAULT_QUARANTINE_POLICY = "SPARK_QUARANTINE_REVIEW"
DEFAULT_DESTINATION_BLOCK_GROUP = "SPARK_EGRESS_BLOCKLIST"
DEFAULT_DESTINATION_BLOCK_POLICY = "SPARK_EGRESS_AUTO_BLOCK"


def _not_configured() -> dict:
    return {
        "source": "not_configured",
        "status": "not_configured",
        "cpu": 0,
        "mem": 0,
        "disk": 0,
        "sessions": 0,
        "error": "",
        "message": "Set FORTIGATE_BASE_URL and FORTIGATE_API_KEY when the FortiGate VM is ready.",
    }


def _error_state(exc: Exception, endpoint: str) -> dict:
    status = "endpoint_error"
    if isinstance(exc, (request_exceptions.Timeout, request_exceptions.ConnectTimeout, request_exceptions.ReadTimeout)):
        status = "timeout"
    elif isinstance(exc, ValueError) and "not configured" in str(exc).lower():
        status = "not_configured"
    elif isinstance(exc, (ValueError, request_exceptions.JSONDecodeError)):
        status = "parse_error"
    elif isinstance(exc, requests.HTTPError):
        code = exc.response.status_code if exc.response is not None else None
        if code in (401, 403):
            status = "auth_failed"
    return {
        "source": "offline",
        "status": status,
        "cpu": 0,
        "mem": 0,
        "disk": 0,
        "sessions": 0,
        "error": str(exc),
        "endpoint": endpoint,
    }


def _request(method: str, base_url: str, path: str, api_key: str, **kwargs) -> requests.Response:
    if not base_url:
        raise ValueError("FORTIGATE_BASE_URL is not configured")
    if not api_key:
        raise ValueError("FORTIGATE_API_KEY is not configured")

    params = kwargs.pop("params", {}) or {}
    headers = kwargs.pop("headers", {}) or {}
    token = api_key.removeprefix("Bearer ").strip()
    headers.setdefault("Authorization", f"Bearer {token}")
    return requests.request(
        method,
        f"{base_url.rstrip('/')}{path}",
        params=params,
        headers=headers,
        verify=False,
        timeout=kwargs.pop("timeout", 10),
        **kwargs,
    )


def get_resource_usage(base_url: str, api_key: str) -> dict:
    """Return live FortiGate status plus resource counters when available."""
    if not base_url or not api_key:
        return _not_configured()

    status_endpoint = "/api/v2/monitor/system/status"
    try:
        system = get_system_status(base_url, api_key)
    except Exception as exc:
        return _error_state(exc, status_endpoint)

    resource_endpoint = "/api/v2/monitor/system/resource/usage"
    payload = {
        "source": "fortigate-live",
        "status": "online",
        "cpu": 0,
        "mem": 0,
        "disk": 0,
        "sessions": 0,
        "serial": system.get("serial", ""),
        "version": system.get("version", ""),
        "system": system,
        "health_endpoint": status_endpoint,
        "resource_endpoint": resource_endpoint,
        "resource_status": "not_queried",
        "error": "",
    }

    try:
        response = _request(
            "GET",
            base_url,
            resource_endpoint,
            api_key,
            params={"interval": "1-min"},
            timeout=10,
        )
        response.raise_for_status()
        resource_payload = response.json()
        results = resource_payload.get("results", {})
        payload.update({
            "cpu": _metric_current(results, "cpu"),
            "mem": _metric_current(results, "mem"),
            "disk": _metric_current(results, "disk"),
            "sessions": _metric_current(results, "session"),
            "serial": resource_payload.get("serial", "") or payload["serial"],
            "version": resource_payload.get("version", "") or payload["version"],
            "resource_status": "online",
        })
    except Exception as exc:
        resource_error = _error_state(exc, resource_endpoint)
        payload["resource_status"] = resource_error["status"]
        payload["resource_error"] = resource_error["error"]
    return payload


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


def _metric_current(results: dict, key: str) -> int:
    values = results.get(key) or []
    if isinstance(values, list) and values and isinstance(values[0], dict):
        return values[0].get("current", 0) or 0
    return 0


def _object_name_for_ip(ip: str, prefix: str = "SPARK_BLOCK") -> str:
    return f"{prefix}_{ip.replace('.', '_')}"


def block_object_name(ip: str) -> str:
    return _object_name_for_ip(ip)


def quarantine_object_name(ip: str) -> str:
    return _object_name_for_ip(ip, "SPARK_QUARANTINE")


def destination_block_object_name(ip: str) -> str:
    return _object_name_for_ip(ip, "SPARK_DST_BLOCK")


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


def ensure_address_group(base_url: str, api_key: str, group_name: str = DEFAULT_BLOCKLIST_GROUP) -> dict:
    try:
        group = get_address_group(base_url, api_key, group_name)
        return {**group, "created": False}
    except Exception:
        payload = {
            "name": group_name,
            "member": [],
            "comment": "SPARK SOC automated containment blocklist",
        }
        response = _request("POST", base_url, "/api/v2/cmdb/firewall/addrgrp", api_key, json=payload, timeout=8)
        response.raise_for_status()
        return {"name": group_name, "members": [], "member_count": 0, "comment": payload["comment"], "created": True}


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


def get_firewall_policy_by_name(base_url: str, api_key: str, policy_name: str) -> dict | None:
    payload = _json_request("GET", base_url, "/api/v2/cmdb/firewall/policy", api_key, timeout=8)
    for item in _as_list(payload.get("results")):
        if item.get("name") == policy_name:
            return item
    return None


def ensure_deny_policy(
    base_url: str,
    api_key: str,
    srcaddr_name: str,
    dstaddr_name: str,
    policy_name: str = DEFAULT_BLOCKLIST_POLICY,
    srcintf: str = "any",
    dstintf: str = "any",
    comments: str = "SPARK SOC automated containment policy",
) -> dict:
    existing = get_firewall_policy_by_name(base_url, api_key, policy_name)
    if existing:
        return {
            "present": True,
            "created": False,
            "policyid": existing.get("policyid") or existing.get("q_origin_key") or "",
            "name": policy_name,
        }

    payload = {
        "name": policy_name,
        "srcintf": [{"name": srcintf}],
        "dstintf": [{"name": dstintf}],
        "srcaddr": [{"name": srcaddr_name}],
        "dstaddr": [{"name": dstaddr_name}],
        "action": "deny",
        "schedule": "always",
        "service": [{"name": "ALL"}],
        "logtraffic": "all",
        "nat": "disable",
        "status": "enable",
        "comments": comments,
    }
    response = _request("POST", base_url, "/api/v2/cmdb/firewall/policy", api_key, json=payload, timeout=8)
    response.raise_for_status()
    body = response.json()
    return {
        "present": True,
        "created": True,
        "policyid": body.get("mkey") or body.get("serial") or "",
        "name": policy_name,
        "response": _summarize_response(response),
    }


def ensure_block_policy(
    base_url: str,
    api_key: str,
    group_name: str = DEFAULT_BLOCKLIST_GROUP,
    policy_name: str = DEFAULT_BLOCKLIST_POLICY,
    srcintf: str = "any",
    dstintf: str = "any",
) -> dict:
    return ensure_deny_policy(
        base_url,
        api_key,
        srcaddr_name=group_name,
        dstaddr_name="all",
        policy_name=policy_name,
        srcintf=srcintf,
        dstintf=dstintf,
        comments="SPARK SOC automated source containment policy",
    )


def ensure_destination_block_policy(
    base_url: str,
    api_key: str,
    group_name: str = DEFAULT_DESTINATION_BLOCK_GROUP,
    policy_name: str = DEFAULT_DESTINATION_BLOCK_POLICY,
    srcaddr_name: str = "all",
    srcintf: str = "any",
    dstintf: str = "any",
) -> dict:
    return ensure_deny_policy(
        base_url,
        api_key,
        srcaddr_name=srcaddr_name or "all",
        dstaddr_name=group_name,
        policy_name=policy_name,
        srcintf=srcintf,
        dstintf=dstintf,
        comments="SPARK SOC automated destination containment policy",
    )


def ensure_quarantine_policy(
    base_url: str,
    api_key: str,
    group_name: str = DEFAULT_QUARANTINE_GROUP,
    policy_name: str = DEFAULT_QUARANTINE_POLICY,
    srcintf: str = "any",
    dstintf: str = "any",
) -> dict:
    """Ensure one reusable review policy for quarantine group traffic."""
    return ensure_block_policy(base_url, api_key, group_name, policy_name, srcintf, dstintf)


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
    if not base_url or not api_key:
        return {
            **_not_configured(),
            "system": {},
            "interfaces": [],
            "policies": [],
            "routes": [],
            "policy_stats": [],
            "address_objects": [],
            "blocklist_group": {},
            "blocklist_policy_present": False,
            "api_status": {},
        }

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
            "resource_usage": {"endpoint": "/api/v2/monitor/system/resource/usage", "ok": resource.get("resource_status") == "online", "error": resource.get("resource_error", "")},
            "interfaces": {"endpoint": "/api/v2/monitor/system/interface or /api/v2/cmdb/system/interface", "ok": interfaces["source"] == "fortigate-live", "error": interfaces["error"]},
            "policies": {"endpoint": "/api/v2/cmdb/firewall/policy", "ok": policies["source"] == "fortigate-live", "error": policies["error"]},
            "routes": {"endpoint": "/api/v2/cmdb/router/static", "ok": routes["source"] == "fortigate-live", "error": routes["error"]},
            "policy_stats": {"endpoint": "/api/v2/monitor/firewall/policy", "ok": policy_stats["source"] == "fortigate-live", "error": policy_stats["error"]},
            "system_status": {"endpoint": "/api/v2/monitor/system/status", "ok": resource.get("source") == "fortigate-live", "error": resource.get("error", "")},
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
    """Backward-compatible wrapper for the product block workflow."""
    return block_ip(
        base_url,
        api_key,
        ip,
        reason="Legacy SPARK block action",
        source="manual",
        duration_minutes=None,
        severity="medium",
        incident_id="",
        group_name=group_name,
        policy_name=policy_name,
        srcintf="any",
        dstintf="any",
    )


def block_ip(
    base_url: str,
    api_key: str,
    ip: str,
    reason: str,
    source: str,
    duration_minutes: int | None,
    severity: str,
    incident_id: str = "",
    group_name: str = DEFAULT_BLOCKLIST_GROUP,
    policy_name: str = DEFAULT_BLOCKLIST_POLICY,
    srcintf: str = "any",
    dstintf: str = "any",
    object_prefix: str = "SPARK_BLOCK",
    allow_partial_policy: bool = False,
    action_label: str = "blocked",
    policy_direction: str = "source",
    policy_srcaddr_name: str = "all",
) -> dict:
    object_name = _object_name_for_ip(ip, object_prefix)
    evidence = {
        "ok": False,
        "status": "pending",
        "ip": ip,
        "object": object_name,
        "group": group_name,
        "policy": policy_name,
        "object_created_or_updated": False,
        "group_updated": False,
        "already_member": False,
        "policy_present": False,
        "policy_created": False,
        "api_responses": {},
        "message": "",
        "enforcement_path": f"FortiGate deny/review policy using {group_name}; runtime impact depends on traffic path.",
    }
    timestamp = _utc_now()
    comment = " | ".join([
        "SPARK SOC",
        reason or "No reason provided",
        source or "manual",
        timestamp,
        f"duration={duration_minutes or 0}m",
        f"severity={severity or 'medium'}",
        f"incident={incident_id}" if incident_id else "incident=",
    ])

    try:
        status = get_resource_usage(base_url, api_key)
        if status.get("source") != "fortigate-live":
            evidence.update({"status": status.get("status", "fortigate_offline"), "message": status.get("error") or status.get("message", "")})
            return evidence

        address_payload = {
            "name": object_name,
            "type": "ipmask",
            "subnet": f"{ip} 255.255.255.255",
            "comment": comment[:255],
        }
        existed = True
        try:
            _json_request("GET", base_url, f"/api/v2/cmdb/firewall/address/{object_name}", api_key, timeout=8)
            response = _request("PUT", base_url, f"/api/v2/cmdb/firewall/address/{object_name}", api_key, json=address_payload, timeout=8)
        except Exception:
            existed = False
            response = _request("POST", base_url, "/api/v2/cmdb/firewall/address", api_key, json=address_payload, timeout=8)
        if not response.ok:
            evidence.update({"status": "object_create_failed", "message": response.text[:500]})
            return evidence
        evidence["object_created_or_updated"] = True
        evidence["object_existed"] = existed
        evidence["api_responses"]["address_object"] = _summarize_response(response)

        group = ensure_address_group(base_url, api_key, group_name)
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
                evidence.update({"status": "group_update_failed", "message": response.text[:500]})
                return evidence
            evidence["group_updated"] = True
            evidence["api_responses"]["address_group"] = _summarize_response(response)

        try:
            if policy_direction == "destination":
                policy = ensure_destination_block_policy(base_url, api_key, group_name, policy_name, policy_srcaddr_name, srcintf, dstintf)
            else:
                policy = ensure_block_policy(base_url, api_key, group_name, policy_name, srcintf, dstintf)
        except Exception as exc:
            status = _error_state(exc, "/api/v2/cmdb/firewall/policy")
            if allow_partial_policy and (evidence.get("object_created_or_updated") and (evidence.get("group_updated") or evidence.get("already_member"))):
                evidence.update({
                    "ok": True,
                    "status": "partial_success",
                    "reason": "policy_limit_or_creation_failed",
                    "message": status.get("error", "") or "FortiGate policy creation failed after object/group update.",
                    "policy_present": False,
                })
                return evidence
            evidence.update({"status": "policy_create_failed", "message": status.get("error", "")})
            return evidence
        evidence["policy_present"] = bool(policy.get("present"))
        evidence["policy_created"] = bool(policy.get("created"))
        evidence["policyid"] = policy.get("policyid", "")
        if policy.get("response"):
            evidence["api_responses"]["policy"] = policy["response"]

        evidence["ok"] = True
        evidence["status"] = action_label
        evidence["message"] = f"IP added to FortiGate {group_name} and policy is present."
        return evidence
    except Exception as exc:
        status = _error_state(exc, "/api/v2/cmdb/firewall/address")
        evidence.update({"status": status.get("status", "endpoint_error"), "message": status.get("error", "")})
        return evidence


def unblock_ip(base_url: str, api_key: str, ip: str, group_name: str = DEFAULT_BLOCKLIST_GROUP, delete_object: bool = True, object_prefix: str = "SPARK_BLOCK") -> dict:
    object_name = _object_name_for_ip(ip, object_prefix)
    evidence = {
        "ok": False,
        "status": "pending",
        "ip": ip,
        "object": object_name,
        "group": group_name,
        "removed_from_group": False,
        "object_deleted": False,
        "api_responses": {},
        "message": "",
    }
    try:
        group = ensure_address_group(base_url, api_key, group_name)
        members = [name for name in group.get("members", []) if name != object_name]
        if len(members) != len(group.get("members", [])):
            response = _request(
                "PUT",
                base_url,
                f"/api/v2/cmdb/firewall/addrgrp/{group_name}",
                api_key,
                json={"member": [{"name": name} for name in members]},
                timeout=8,
            )
            if not response.ok:
                evidence.update({"status": "unblock_failed", "message": response.text[:500]})
                return evidence
            evidence["removed_from_group"] = True
            evidence["api_responses"]["address_group"] = _summarize_response(response)

        if delete_object:
            response = _request("DELETE", base_url, f"/api/v2/cmdb/firewall/address/{object_name}", api_key, timeout=8)
            if response.ok or response.status_code == 404:
                evidence["object_deleted"] = response.ok
                evidence["api_responses"]["address_object"] = _summarize_response(response)
            else:
                evidence["object_delete_error"] = response.text[:500]

        evidence["ok"] = True
        evidence["status"] = "unblocked"
        evidence["message"] = "IP removed from FortiGate blocklist."
        return evidence
    except Exception as exc:
        status = _error_state(exc, f"/api/v2/cmdb/firewall/addrgrp/{group_name}")
        evidence.update({"status": "unblock_failed" if status["status"] == "endpoint_error" else status["status"], "message": status.get("error", "")})
        return evidence


def quarantine_ip(
    base_url: str,
    api_key: str,
    ip: str,
    reason: str,
    source: str,
    duration_minutes: int | None,
    severity: str,
    incident_id: str = "",
    group_name: str = DEFAULT_QUARANTINE_GROUP,
    policy_name: str = DEFAULT_QUARANTINE_POLICY,
    srcintf: str = "any",
    dstintf: str = "any",
) -> dict:
    return block_ip(
        base_url,
        api_key,
        ip,
        reason,
        source,
        duration_minutes,
        severity,
        incident_id,
        group_name,
        policy_name,
        srcintf,
        dstintf,
        object_prefix="SPARK_QUARANTINE",
        allow_partial_policy=True,
        action_label="quarantined",
    )


def block_destination_ip(
    base_url: str,
    api_key: str,
    ip: str,
    reason: str,
    source: str,
    duration_minutes: int | None,
    severity: str,
    incident_id: str = "",
    group_name: str = DEFAULT_DESTINATION_BLOCK_GROUP,
    policy_name: str = DEFAULT_DESTINATION_BLOCK_POLICY,
    srcaddr_name: str = "all",
    srcintf: str = "any",
    dstintf: str = "any",
) -> dict:
    result = block_ip(
        base_url,
        api_key,
        ip,
        reason,
        source,
        duration_minutes,
        severity,
        incident_id,
        group_name,
        policy_name,
        srcintf,
        dstintf,
        object_prefix="SPARK_DST_BLOCK",
        allow_partial_policy=True,
        action_label="destination_blocked",
        policy_direction="destination",
        policy_srcaddr_name=srcaddr_name,
    )
    result["enforcement_path"] = "FortiGate egress deny policy using SPARK_EGRESS_BLOCKLIST as destination address; runtime enforcement depends on traffic path validation."
    return result


def unblock_destination_ip(base_url: str, api_key: str, ip: str, group_name: str = DEFAULT_DESTINATION_BLOCK_GROUP, delete_object: bool = True) -> dict:
    result = unblock_ip(base_url, api_key, ip, group_name, delete_object=delete_object, object_prefix="SPARK_DST_BLOCK")
    if result.get("ok"):
        result["status"] = "destination_unblocked"
        result["message"] = "IP removed from FortiGate egress blocklist."
    return result


def unquarantine_ip(base_url: str, api_key: str, ip: str, group_name: str = DEFAULT_QUARANTINE_GROUP, delete_object: bool = True) -> dict:
    result = unblock_ip(base_url, api_key, ip, group_name, delete_object=delete_object, object_prefix="SPARK_QUARANTINE")
    if result.get("ok"):
        result["status"] = "unquarantined"
        result["message"] = "IP removed from FortiGate quarantine list."
    return result


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


def list_blocklist(base_url: str, api_key: str, group_name: str = DEFAULT_BLOCKLIST_GROUP) -> dict:
    group = ensure_address_group(base_url, api_key, group_name)
    objects = {item.get("name"): item for item in get_address_objects(base_url, api_key)}
    items = []
    for name in group.get("members", []):
        item = objects.get(name, {})
        subnet = str(item.get("subnet", ""))
        ip = subnet.split()[0] if subnet else ""
        items.append({
            "ip": ip,
            "object_name": name,
            "reason": item.get("comment", ""),
            "comment": item.get("comment", ""),
            "created_at": "",
            "source": "",
            "present": True,
            "status": "blocked",
        })
    return {"status": "success", "group_name": group_name, "items": items}


def list_quarantine(base_url: str, api_key: str, group_name: str = DEFAULT_QUARANTINE_GROUP) -> dict:
    result = list_blocklist(base_url, api_key, group_name)
    result["status"] = "success"
    result["group_name"] = group_name
    for item in result.get("items", []):
        item["status"] = "quarantined"
    return result


def list_destination_blocklist(base_url: str, api_key: str, group_name: str = DEFAULT_DESTINATION_BLOCK_GROUP) -> dict:
    result = list_blocklist(base_url, api_key, group_name)
    result["status"] = "success"
    result["group_name"] = group_name
    for item in result.get("items", []):
        item["status"] = "destination_blocked"
    return result


def _summarize_response(response: requests.Response) -> dict:
    content_type = response.headers.get("content-type", "")
    body = {}
    if "json" in content_type:
        try:
            body = response.json()
        except ValueError:
            body = {}
    return {
        "status_code": response.status_code,
        "ok": response.ok,
        "status": body.get("status", ""),
        "mkey": body.get("mkey", ""),
        "message": body.get("message", "") or body.get("error", ""),
    }


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

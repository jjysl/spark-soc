"""Small Shuffle SOAR client used by the executive overview and IR playbooks."""
from __future__ import annotations

import requests


def _candidate_bases(base_url: str, backend_url: str | None = None) -> list[str]:
    bases = []
    for item in (backend_url, base_url):
        if item:
            base = item.rstrip("/")
            if base not in bases:
                bases.append(base)
    return bases


def get_status(base_url: str, api_key: str, backend_url: str | None = None) -> dict:
    frontend = (base_url or "").rstrip("/")
    backend = (backend_url or "").rstrip("/")
    if not frontend and not backend:
        return {
            "connected": False,
            "status": "not_configured",
            "frontend_reachable": False,
            "backend_reachable": False,
            "api_authenticated": False,
            "message": "Shuffle connector is not configured.",
            "source": "not_configured",
        }

    def probe(url: str, ok_statuses: set[int]) -> tuple[bool, int | None, str]:
        if not url:
            return False, None, "not_configured"
        try:
            resp = requests.get(url, timeout=3)
            return resp.status_code in ok_statuses, resp.status_code, ""
        except requests.exceptions.Timeout:
            return False, None, "timeout"
        except requests.exceptions.ConnectionError:
            return False, None, "connection_error"
        except requests.exceptions.RequestException as exc:
            return False, None, f"{type(exc).__name__}: {exc}"

    frontend_reachable, frontend_status, frontend_error = probe(frontend, {200, 301, 302, 401, 403, 404})
    backend_root = backend or frontend
    backend_reachable, backend_status, backend_error = probe(backend_root, {200, 301, 302, 401, 403, 404})

    api_authenticated = False
    auth_required = False
    auth_failed = False
    items = 0
    api_status = None
    api_source = f"{backend_root}/api/v1/getinfo" if backend_root else "shuffle"
    headers_to_try = []
    if api_key:
        headers_to_try.extend([
            {"Authorization": f"Bearer {api_key}"},
            {"Authorization": api_key},
            {"X-API-Key": api_key},
        ])
    headers_to_try.append({})

    if backend_root:
        for headers in headers_to_try:
            try:
                resp = requests.get(api_source, headers=headers, timeout=3)
                api_status = resp.status_code
                content_type = resp.headers.get("content-type", "")
                payload = resp.json() if "json" in content_type else {}
                if resp.ok and payload.get("success") is not False:
                    api_authenticated = True
                    data = payload.get("data") or payload.get("workflows") or payload.get("apps") or []
                    items = len(data) if isinstance(data, list) else 0
                    break
                if resp.status_code == 401:
                    auth_required = True
                elif resp.status_code == 403:
                    auth_failed = True
            except requests.exceptions.Timeout:
                backend_error = "timeout"
            except requests.exceptions.ConnectionError:
                backend_error = "connection_error"
            except requests.exceptions.RequestException as exc:
                backend_error = f"{type(exc).__name__}: {exc}"

    reachable = frontend_reachable or backend_reachable
    if api_authenticated:
        status = "online"
        message = "Shuffle Online"
    elif reachable and api_key and (auth_required or auth_failed):
        status = "auth_failed"
        message = "Shuffle Auth Required"
    elif reachable:
        status = "auth_required"
        message = "Shuffle Auth Required"
    else:
        status = "offline"
        message = "Shuffle Offline"

    return {
        "connected": reachable,
        "status": status,
        "frontend_reachable": frontend_reachable,
        "backend_reachable": backend_reachable,
        "api_authenticated": api_authenticated,
        "message": message,
        "source": api_source if backend_root else frontend or "shuffle",
        "status_code": api_status or backend_status or frontend_status,
        "frontend_status_code": frontend_status,
        "backend_status_code": backend_status,
        "items": items,
        "error": "" if reachable else (backend_error or frontend_error or "unavailable"),
    }


def dispatch_incident_evidence(webhook_url: str, workflow: str, payload: dict) -> dict:
    """Send SPARK response evidence to a Shuffle webhook without waiting for a callback."""
    if not webhook_url:
        return {
            "ok": False,
            "webhook_called": False,
            "status": "not_configured",
            "workflow": workflow,
            "message": "Shuffle incident webhook is not configured.",
        }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=8)
        content_type = resp.headers.get("content-type", "")
        if "json" in content_type:
            response_payload = resp.json()
            message = (
                response_payload.get("message")
                or response_payload.get("reason")
                or response_payload.get("status")
                or ""
            )
            success_flag = response_payload.get("success")
        else:
            response_payload = {"raw": resp.text[:500]}
            message = resp.text[:160]
            success_flag = None

        ok = resp.ok and success_flag is not False
        return {
            "ok": ok,
            "webhook_called": True,
            "status": "success" if ok else f"http_{resp.status_code}",
            "status_code": resp.status_code,
            "workflow": workflow,
            "message": message or ("Shuffle workflow accepted evidence." if ok else "Shuffle webhook returned an error."),
            "response": response_payload,
        }
    except Exception as exc:
        return {
            "ok": False,
            "webhook_called": False,
            "status": "error",
            "workflow": workflow,
            "message": str(exc),
            "error": f"{type(exc).__name__}: {exc}",
        }

"""Small Shuffle SOAR client used by the executive overview and IR playbooks."""
from __future__ import annotations

import requests


def get_status(base_url: str, api_key: str) -> dict:
    if not base_url:
        return {"connected": False, "source": "not_configured"}

    base = base_url.rstrip("/")

    try:
        resp = requests.get(f"{base}/api/v1/health", timeout=3)
        content_type = resp.headers.get("content-type", "")
        payload = resp.json() if "json" in content_type else {}
        if resp.ok and payload.get("success") is not False:
            return {
                "connected": True,
                "source": "/api/v1/health",
                "status_code": resp.status_code,
                "items": 0,
            }
    except Exception:
        pass

    headers_to_try = [
        {"Authorization": f"Bearer {api_key}"} if api_key else {},
        {"Authorization": api_key} if api_key else {},
        {"X-API-Key": api_key} if api_key else {},
        {},
    ]
    paths = ["/api/v1/workflows", "/api/v1/apps", "/api/v1/users"]

    last_error = ""
    for path in paths:
        for headers in headers_to_try:
            try:
                resp = requests.get(f"{base}{path}", headers=headers, timeout=3)
                content_type = resp.headers.get("content-type", "")
                payload = resp.json() if "json" in content_type else {}
                if resp.ok and payload.get("success") is not False:
                    items = payload.get("workflows") or payload.get("data") or payload.get("apps") or []
                    return {
                        "connected": True,
                        "source": path,
                        "status_code": resp.status_code,
                        "items": len(items) if isinstance(items, list) else 0,
                    }
                if resp.status_code in (401, 403):
                    last_error = f"auth_{resp.status_code}"
                elif payload:
                    last_error = payload.get("reason") or payload.get("message") or str(payload)[:120]
                else:
                    last_error = f"http_{resp.status_code}"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"

    return {"connected": False, "source": "shuffle", "error": last_error or "unavailable"}


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

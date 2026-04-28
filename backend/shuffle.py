"""Small Shuffle SOAR client used by the executive overview."""
from __future__ import annotations

import requests


def get_status(base_url: str, api_key: str) -> dict:
    if not base_url:
        return {"connected": False, "source": "not_configured"}

    headers_to_try = [
        {"Authorization": f"Bearer {api_key}"} if api_key else {},
        {"Authorization": api_key} if api_key else {},
        {"X-API-Key": api_key} if api_key else {},
        {},
    ]
    paths = ["/api/v1/workflows", "/api/v1/apps", "/api/v1/health", "/api/v1/users"]

    last_error = ""
    for path in paths:
        for headers in headers_to_try:
            try:
                resp = requests.get(f"{base_url.rstrip('/')}{path}", headers=headers, timeout=8)
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

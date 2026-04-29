"""Jira REST client for SPARK SOC tickets.

The browser never receives Jira API tokens. All Jira calls go through Flask.
"""
from __future__ import annotations

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


PRIORITY_MAP = {
    "p1": "Highest",
    "p2": "High",
    "p3": "Medium",
    "p4": "Low",
}


def configured(base_url: str, email: str, api_token: str, project_key: str) -> bool:
    return bool(base_url and email and api_token and project_key)


def _auth(email: str, api_token: str) -> tuple[str, str]:
    return email, api_token


def _url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}{path}"


def status(base_url: str, email: str, api_token: str, project_key: str) -> dict:
    if not configured(base_url, email, api_token, project_key):
        return {
            "configured": False,
            "connected": False,
            "project": project_key or "",
            "message": "Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN and JIRA_PROJECT_KEY.",
        }

    try:
        user_resp = requests.get(
            _url(base_url, "/rest/api/3/myself"),
            auth=_auth(email, api_token),
            headers={"Accept": "application/json"},
            timeout=8,
        )
        project_resp = requests.get(
            _url(base_url, f"/rest/api/3/project/{project_key}"),
            auth=_auth(email, api_token),
            headers={"Accept": "application/json"},
            timeout=8,
        )
        return {
            "configured": True,
            "connected": user_resp.ok and project_resp.ok,
            "project": project_key,
            "user_status": user_resp.status_code,
            "project_status": project_resp.status_code,
            "account": (user_resp.json() if user_resp.ok else {}).get("displayName", ""),
            "message": "Jira connected" if user_resp.ok and project_resp.ok else "Jira credentials or project are not valid.",
        }
    except Exception as exc:
        return {
            "configured": True,
            "connected": False,
            "project": project_key,
            "message": str(exc),
        }


def _description_doc(ticket: dict) -> dict:
    lines = [
        ticket.get("desc") or ticket.get("title") or "SPARK SOC ticket",
        "",
        f"SPARK ID: {ticket.get('id', 'pending')}",
        f"Priority: {(ticket.get('priority') or 'p3').upper()}",
        f"Type: {ticket.get('type') or 'incident'}",
        f"Linked incident: {ticket.get('incidentLink') or '-'}",
        f"MITRE: {ticket.get('mitre') or '-'}",
        f"Source IP: {ticket.get('ip') or '-'}",
        "",
        "Response playbook:",
        ticket.get("playbook") or "Not defined yet.",
    ]
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line or " "}]}
            for line in lines
        ],
    }


def create_issue(
    base_url: str,
    email: str,
    api_token: str,
    project_key: str,
    default_issue_type: str,
    ticket: dict,
) -> dict:
    if not configured(base_url, email, api_token, project_key):
        return {"ok": False, "status": "not_configured", "message": "Jira is not configured."}

    priority = PRIORITY_MAP.get((ticket.get("priority") or "p3").lower(), "Medium")
    issue_type = "Bug" if ticket.get("type") in {"incident", "threat", "vuln"} else default_issue_type
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": ticket.get("title") or "SPARK SOC ticket",
            "description": _description_doc(ticket),
            "issuetype": {"name": issue_type},
            "priority": {"name": priority},
            "labels": ["spark-soc", ticket.get("type") or "incident"],
        }
    }

    try:
        response = requests.post(
            _url(base_url, "/rest/api/3/issue"),
            auth=_auth(email, api_token),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json=payload,
            timeout=12,
        )
        if not response.ok:
            return {
                "ok": False,
                "status": f"http_{response.status_code}",
                "message": response.text[:500],
            }
        data = response.json()
        key = data.get("key", "")
        return {
            "ok": True,
            "status": "created",
            "key": key,
            "url": f"{base_url.rstrip('/')}/browse/{key}" if key else "",
            "raw": data,
        }
    except Exception as exc:
        return {"ok": False, "status": "error", "message": str(exc)}

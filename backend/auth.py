"""
SPARK SOC authentication.

Supports local lab accounts plus optional Microsoft Entra ID and Google OAuth2.
"""
import hashlib
import secrets
import urllib.parse
from datetime import datetime, timezone
from functools import wraps

import requests
from flask import Blueprint, jsonify, redirect, request, session

auth_bp = Blueprint("auth", __name__)


def require_login(f):
    """Protect routes with either JSON 401 responses or browser redirects."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            if (
                request.is_json
                or request.path.startswith("/spark/")
                or request.path.startswith("/api/")
            ):
                return jsonify({"error": "not authenticated", "redirect": "/login"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


def _set_session(username: str, name: str, role: str, email: str, avatar: str, provider: str):
    session.permanent = True
    session["user"] = {
        "username": username,
        "name": name,
        "role": role,
        "email": email,
        "avatar": avatar,
        "provider": provider,
        "login_at": datetime.now(timezone.utc).isoformat(),
    }


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    from config import LOCAL_USERS

    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    user = LOCAL_USERS.get(username)
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401

    if hashlib.sha256(password.encode()).hexdigest() != user["password_hash"]:
        return jsonify({"error": "Invalid username or password"}), 401

    _set_session(username, user["name"], user["role"], user["email"], user["avatar"], "local")
    print(f"[AUTH] Local login: {username} ({user['role']})")
    return jsonify({"ok": True, "user": session["user"]})


@auth_bp.route("/auth/logout", methods=["POST", "GET"])
def logout():
    user = session.get("user", {})
    print(f"[AUTH] Logout: {user.get('username', '?')}")
    session.clear()
    return redirect("/login")


@auth_bp.route("/auth/me")
def me():
    user = session.get("user")
    if not user:
        return jsonify({"error": "not authenticated"}), 401
    return jsonify(user)


@auth_bp.route("/auth/microsoft")
def ms_start():
    from config import MICROSOFT_CLIENT_ID, MICROSOFT_TENANT_ID, MICROSOFT_REDIRECT_URI

    if not MICROSOFT_CLIENT_ID:
        return "Microsoft SSO is not configured. Set MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET.", 501

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    params = {
        "client_id": MICROSOFT_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": MICROSOFT_REDIRECT_URI,
        "scope": "openid profile email User.Read",
        "state": state,
        "response_mode": "query",
    }
    return redirect(
        f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize?"
        + urllib.parse.urlencode(params)
    )


@auth_bp.route("/auth/microsoft/callback")
def ms_callback():
    from config import (
        MICROSOFT_CLIENT_ID,
        MICROSOFT_CLIENT_SECRET,
        MICROSOFT_TENANT_ID,
        MICROSOFT_REDIRECT_URI,
    )

    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", "Unknown error")
        return f"<h3>Microsoft SSO error</h3><pre>{desc}</pre><a href='/login'>Back</a>", 400

    if request.args.get("state") != session.pop("oauth_state", None):
        return "Invalid OAuth state. Possible CSRF.", 400

    code = request.args.get("code", "")
    if not code:
        return "Missing authorization code.", 400

    token_resp = requests.post(
        f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/token",
        data={
            "client_id": MICROSOFT_CLIENT_ID,
            "client_secret": MICROSOFT_CLIENT_SECRET,
            "code": code,
            "redirect_uri": MICROSOFT_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return f"<h3>Token exchange failed</h3><pre>{token_data}</pre><a href='/login'>Back</a>", 400

    profile = requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()
    email = profile.get("mail") or profile.get("userPrincipalName", "")
    name = profile.get("displayName", email)
    initials = "".join(p[0].upper() for p in name.split()[:2]) if name else "MS"

    _set_session(email, name, "analyst", email, initials, "microsoft")
    print(f"[AUTH] Microsoft login: {email}")
    return redirect("/")


@auth_bp.route("/auth/google")
def google_start():
    from config import GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI

    if not GOOGLE_CLIENT_ID:
        return "Google SSO is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.", 501

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
    }
    return redirect(
        "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    )


@auth_bp.route("/auth/google/callback")
def google_callback():
    from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI

    error = request.args.get("error")
    if error:
        return f"<h3>Google SSO error</h3><pre>{error}</pre><a href='/login'>Back</a>", 400

    if request.args.get("state") != session.pop("oauth_state", None):
        return "Invalid OAuth state. Possible CSRF.", 400

    token_resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": request.args.get("code", ""),
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return f"<h3>Google token exchange failed</h3><pre>{token_data}</pre><a href='/login'>Back</a>", 400

    userinfo = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()
    email = userinfo.get("email", "")
    name = userinfo.get("name", email)
    initials = "".join(p[0].upper() for p in name.split()[:2]) if name else "GG"

    _set_session(email, name, "analyst", email, initials, "google")
    print(f"[AUTH] Google login: {email}")
    return redirect("/")

"""
SPARK SOC - Flask application factory.

This is the main backend entrypoint. It registers the authentication and
dashboard API blueprints while serving the frontend from ../frontend.
"""
from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path
import sys

import urllib3
from flask import Flask, redirect, send_from_directory, session
from flask_cors import CORS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from backend.auth import auth_bp, require_login
from backend.spark_api import spark_bp


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder=str(FRONTEND_DIR),
        static_url_path="",
    )
    app.secret_key = config.SECRET_KEY
    app.permanent_session_lifetime = timedelta(hours=8)
    CORS(app, supports_credentials=True)

    app.register_blueprint(auth_bp)
    app.register_blueprint(spark_bp)

    @app.route("/login")
    def login_page():
        if session.get("user"):
            return redirect("/")
        return send_from_directory(FRONTEND_DIR, "login.html")

    @app.route("/")
    @require_login
    def dashboard():
        return send_from_directory(FRONTEND_DIR, "dashboard.html")

    return app


def _print_banner() -> None:
    print("=" * 62)
    print("  SPARK SOC - NG-SOC as a Service - powered by Fortinet")
    print("=" * 62)
    print("  Dashboard:   http://localhost:5000/")
    print("  Stats API:   http://localhost:5000/spark/stats")
    print("  Tickets API: http://localhost:5000/spark/tickets")
    print("  AI Status:   http://localhost:5000/spark/ai/status")
    print("  Wazuh Debug: http://localhost:5000/spark/wazuh-debug")
    print()
    if config.ANTHROPIC_API_KEY:
        print(f"  [IA] Anthropic Claude: CONFIGURADO ({config.ANTHROPIC_MODEL})")
    else:
        print("  [IA] Anthropic Claude: KEY NAO CONFIGURADA")
        print("       -> defina ANTHROPIC_API_KEY no ambiente ou em config.py")
    print(f"  [IA] Ollama local: {config.OLLAMA_BASE} (modelo: {config.OLLAMA_MODEL})")
    print(f"  [DB] SQLite: {config.DB_PATH}")
    print("=" * 62)


if __name__ == "__main__":
    application = create_app()
    _print_banner()
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    application.run(host="0.0.0.0", port=5000, debug=debug, use_reloader=False)

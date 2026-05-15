"""
SPARK SOC - example configuration.

Copy this file to config.py and fill the values for your lab, or export the
same variables in the shell before starting Flask.
"""
from pathlib import Path
import hashlib
import os

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SPARK_PROFILE = os.environ.get("SPARK_PROFILE", "local")
WAZUH_MANAGER_IP = os.environ.get("WAZUH_MANAGER_IP", "127.0.0.1")
WAZUH_AGENT_IP = os.environ.get("WAZUH_AGENT_IP", "")
DEFAULT_INDEXER_BASE = "https://localhost:9200" if SPARK_PROFILE == "vmware-lab" else "https://localhost:19200"
DEFAULT_FORTIGATE_BASE_URL = "https://192.168.50.40" if SPARK_PROFILE == "vmware-lab" else ""

FORTIGATE_BASE_URL = os.environ.get("FORTIGATE_BASE_URL", DEFAULT_FORTIGATE_BASE_URL)
FORTIGATE_API_KEY = os.environ.get("FORTIGATE_API_KEY", "")
FORTIGATE_BLOCKLIST_GROUP = os.environ.get("FORTIGATE_BLOCKLIST_GROUP", "SPARK_BLOCKLIST")
FORTIGATE_BLOCKLIST_POLICY = os.environ.get("FORTIGATE_BLOCKLIST_POLICY", "SPARK_AUTO_BLOCK")
FORTIGATE_BLOCK_SRCINTF = os.environ.get("FORTIGATE_BLOCK_SRCINTF", "any")
FORTIGATE_BLOCK_DSTINTF = os.environ.get("FORTIGATE_BLOCK_DSTINTF", "any")

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

INDEXER_BASE = os.environ.get("INDEXER_BASE", DEFAULT_INDEXER_BASE)
INDEXER_USER = os.environ.get("INDEXER_USER", "admin")
INDEXER_PASS = os.environ.get("INDEXER_PASS", "")

WAZUH_BASE = os.environ.get("WAZUH_BASE", f"https://{WAZUH_MANAGER_IP}:55000")
WAZUH_USER = os.environ.get("WAZUH_USER", "wazuh")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "")

SHUFFLE_BASE_URL = os.environ.get("SHUFFLE_BASE_URL", f"http://{WAZUH_MANAGER_IP}:3001")
SHUFFLE_BACKEND_URL = os.environ.get("SHUFFLE_BACKEND_URL", "")
SHUFFLE_API_KEY = os.environ.get("SHUFFLE_API_KEY", "")
SHUFFLE_INCIDENT_WEBHOOK_URL = os.environ.get("SHUFFLE_INCIDENT_WEBHOOK_URL", "")
SHUFFLE_INCIDENT_WORKFLOW = os.environ.get("SHUFFLE_INCIDENT_WORKFLOW", "SPARK - Incident Response Evidence")

JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SPARK")
JIRA_DEFAULT_ISSUE_TYPE = os.environ.get("JIRA_DEFAULT_ISSUE_TYPE", "Task")

AI_PROVIDER = os.environ.get("AI_PROVIDER", "none").lower()
AI_MODEL = os.environ.get("AI_MODEL", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

OLLAMA_BASE = os.environ.get("OLLAMA_BASE", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

SECRET_KEY = os.environ.get("SECRET_KEY", "spark-soc-dev-key-change-me")

MICROSOFT_CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")
MICROSOFT_CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
MICROSOFT_TENANT_ID = os.environ.get("MICROSOFT_TENANT_ID", "")
MICROSOFT_REDIRECT_URI = os.environ.get(
    "MICROSOFT_REDIRECT_URI",
    "http://localhost:5000/auth/microsoft/callback",
)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI",
    "http://localhost:5000/auth/google/callback",
)

LOCAL_USERS = {
    "admin": {
        "password_hash": hashlib.sha256("Admin@2026".encode()).hexdigest(),
        "name": "Administrador",
        "role": "admin",
        "email": "admin@sparksoc.local",
        "avatar": "AD",
    }
}

SCORE_BLOQUEIO = int(os.environ.get("SCORE_BLOQUEIO", 80))
SCORE_ALERTA = int(os.environ.get("SCORE_ALERTA", 40))
INTERVALO_COLETA = int(os.environ.get("INTERVALO_COLETA", 30))

DB_PATH = os.environ.get("DB_PATH", str(DATA_DIR / "events.db"))

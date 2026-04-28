"""
SPARK SOC — Proxy de IA
========================
Expõe Anthropic Claude (primário) e Ollama (fallback local)
sem vazar a API key para o frontend.
"""
import json
import re
import requests

SYSTEM_PROMPT = """Você é um analista sênior de SOC (NG-SOC / SOCaaS) especializado em Fortinet, Wazuh e resposta a incidentes.
Gere conteúdo para um ticket de incidente em português brasileiro.
Responda SOMENTE com um objeto JSON válido, sem markdown, sem blocos de código, sem texto antes ou depois.
Retorne exatamente as seguintes chaves:
- title: título conciso e técnico (max 80 chars) incluindo [P1/P2/P3/P4]
- description: descrição técnica do incidente com evidências e contexto (3-4 frases)
- playbook: passos de resposta numerados (5-6 passos específicos para SOC)
- analysis: análise técnica com recomendação de ação imediata (2-3 frases)
Use linguagem técnica de SOC. Sem emojis."""


def _parse_json(raw: str) -> dict:
    """Extrai JSON da resposta mesmo que venha dentro de markdown code blocks."""
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            return json.loads(m.group())
        return {}


# ── Anthropic Claude ───────────────────────────────────────────────────────

def autofill_anthropic(api_key: str, model: str, context: str) -> tuple[dict, int]:
    """
    Chama a API Anthropic e retorna (parsed_dict, http_status).
    Em caso de erro retorna (error_dict, status_code).
    """
    if not api_key:
        return {
            "error":  "ANTHROPIC_API_KEY não configurada",
            "hint":   "Defina a variável de ambiente ANTHROPIC_API_KEY",
            "source": "config_error",
        }, 503

    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":    model,
                "max_tokens": 1000,
                "system":   SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": f"Gere ticket para: {context}"}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        raw     = resp.json()["content"][0]["text"]
        parsed  = _parse_json(raw)
        parsed["source"] = "anthropic"
        return parsed, 200

    except requests.exceptions.Timeout:
        return {"error": "Timeout na API Anthropic", "source": "timeout"}, 504
    except requests.exceptions.HTTPError as exc:
        code = exc.response.status_code if exc.response else 0
        msg  = exc.response.text[:200]   if exc.response else str(exc)
        return {"error": f"Anthropic HTTP {code}: {msg}", "source": "anthropic_error"}, 502
    except Exception as exc:
        return {"error": str(exc), "source": "unknown"}, 500


# ── Ollama (local) ─────────────────────────────────────────────────────────

def autofill_ollama(ollama_base: str, ollama_model: str, context: str) -> tuple[dict, int]:
    """Chama o Ollama local. Fallback quando Anthropic não está disponível."""
    prompt = f"{SYSTEM_PROMPT}\n\nGere ticket para: {context}"
    try:
        resp = requests.post(
            f"{ollama_base}/api/generate",
            json={
                "model":   ollama_model,
                "prompt":  prompt,
                "stream":  False,
                "options": {"temperature": 0.3, "num_predict": 1000},
            },
            timeout=60,
        )
        resp.raise_for_status()
        raw    = resp.json().get("response", "")
        parsed = _parse_json(raw)
        parsed["source"] = f"ollama/{ollama_model}"
        return parsed, 200

    except requests.exceptions.ConnectionError:
        return {
            "error":  f"Ollama não disponível em {ollama_base}",
            "hint":   "Instale via https://ollama.ai e execute: ollama run llama3",
            "source": "ollama_offline",
        }, 503
    except Exception as exc:
        return {"error": str(exc), "source": "ollama_error"}, 500


# ── Status ─────────────────────────────────────────────────────────────────

def check_status(api_key: str, model: str, ollama_base: str, ollama_model: str) -> dict:
    """Verifica disponibilidade de cada provedor de IA."""
    result: dict = {}

    # Anthropic
    if api_key:
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":         api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json",
                },
                json={"model": model, "max_tokens": 5, "messages": [{"role": "user", "content": "ping"}]},
                timeout=10,
            )
            result["anthropic"] = "online" if r.status_code in (200, 400) else f"error_{r.status_code}"
        except Exception as exc:
            result["anthropic"] = f"offline ({type(exc).__name__})"
    else:
        result["anthropic"] = "no_key"

    # Ollama
    try:
        r = requests.get(f"{ollama_base}/api/tags", timeout=5)
        models = [m["name"] for m in r.json().get("models", [])]
        result["ollama"]          = "online"
        result["ollama_models"]   = models
        result["ollama_selected"] = ollama_model
    except Exception:
        result["ollama"]      = "offline"
        result["ollama_hint"] = "https://ollama.ai"

    return result
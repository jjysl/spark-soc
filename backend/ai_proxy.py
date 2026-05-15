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
INCIDENT_BRIEFING_SYSTEM_PROMPT = """You are a senior MDR incident commander.
Generate concise executive and operational incident briefing JSON only.
Return exactly these keys:
- executive_summary: one short paragraph.
- severity_rationale: one short paragraph.
- response_taken: one short paragraph.
- containment_status: one short paragraph.
- recommended_next_steps: array of 3 to 5 short action strings.
Use only the evidence provided. Do not invent facts. No markdown."""


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


def _incident_field(payload: dict, key: str, default: str = "") -> str:
    value = payload.get(key, default)
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)[:500]
    return str(value)[:500]


def _fallback_incident_briefing(payload: dict, reason: str = "") -> dict:
    evidence = payload.get("evidence") or {}
    fortigate = evidence.get("fortigate") or evidence
    title = _incident_field(payload, "title", "Security incident requires analyst review")
    severity = _incident_field(payload, "severity", "Requires analyst review")
    source_ip = _incident_field(payload, "source_ip", evidence.get("ip") or "--")
    target = _incident_field(payload, "target", "monitored asset")
    mitre = _incident_field(payload, "mitre", "Requires analyst review")
    confidence = _incident_field(payload, "containment_confidence", "0%")
    object_name = fortigate.get("object_name") or evidence.get("object_name") or "--"
    group_name = fortigate.get("group_name") or evidence.get("group_name") or "SPARK_BLOCKLIST"
    policy_name = fortigate.get("policy_name") or evidence.get("policy_name") or "SPARK_AUTO_BLOCK"
    evidence_id = evidence.get("evidence_id") or "--"
    suffix = f" Fallback reason: {reason}" if reason else ""
    return {
        "executive_summary": (
            f"{title} is prioritized as {severity}. Source {source_ip} targeted {target}; "
            f"MITRE context: {mitre}.{suffix}"
        ),
        "severity_rationale": (
            f"Severity is based on available Wazuh evidence, incident priority and analyst review context. "
            f"Current severity: {severity}."
        ),
        "response_taken": (
            f"FortiGate response evidence references object {object_name}, group {group_name}, "
            f"policy {policy_name}, and evidence ID {evidence_id}."
        ),
        "containment_status": (
            f"Containment confidence is {confidence}. Traffic-path validation and correlated alert review "
            "remain analyst-controlled checks."
        ),
        "recommended_next_steps": [
            "Validate traffic-path enforcement for the affected segment.",
            "Review correlated Wazuh alerts for the same source and target.",
            "Attach the Evidence Pack to the incident workspace.",
            "Confirm business impact and assign a case owner.",
        ],
    }


def _normalize_briefing(value: dict, fallback: dict) -> dict:
    if not isinstance(value, dict):
        return fallback
    steps = value.get("recommended_next_steps")
    if not isinstance(steps, list):
        steps = fallback["recommended_next_steps"]
    return {
        "executive_summary": str(value.get("executive_summary") or fallback["executive_summary"])[:1200],
        "severity_rationale": str(value.get("severity_rationale") or fallback["severity_rationale"])[:1200],
        "response_taken": str(value.get("response_taken") or fallback["response_taken"])[:1200],
        "containment_status": str(value.get("containment_status") or fallback["containment_status"])[:1200],
        "recommended_next_steps": [str(item)[:240] for item in steps[:5]],
    }


def _briefing_prompt(payload: dict) -> str:
    evidence = payload.get("evidence") or {}
    compact = {
        "incident_id": payload.get("incident_id", ""),
        "title": payload.get("title", ""),
        "severity": payload.get("severity", ""),
        "source_ip": payload.get("source_ip", ""),
        "target": payload.get("target", ""),
        "mitre": payload.get("mitre", ""),
        "wazuh_evidence": payload.get("wazuh_evidence") or evidence.get("wazuh") or {},
        "fortigate": {
            "object": evidence.get("object_name") or evidence.get("fortigate_object") or "",
            "group": evidence.get("group_name") or evidence.get("fortigate_group") or "",
            "policy": evidence.get("policy_name") or evidence.get("fortigate_policy") or "",
            "evidence_id": evidence.get("evidence_id") or "",
        },
        "containment_confidence": payload.get("containment_confidence", ""),
        "recommended_next_steps": payload.get("recommended_next_steps", []),
    }
    return json.dumps(compact, ensure_ascii=False)


def generate_ai_incident_briefing(
    incident_payload: dict,
    provider: str = "none",
    groq_api_key: str = "",
    groq_model: str = "llama-3.1-8b-instant",
) -> dict:
    """Generate an incident briefing through Groq, with deterministic fallback."""
    provider = (provider or "none").lower()
    model = groq_model or "llama-3.1-8b-instant"
    fallback = _fallback_incident_briefing(incident_payload)

    if provider != "groq":
        return {
            "provider": provider,
            "model": model,
            "source": "fallback",
            "briefing": fallback,
            "fallback_reason": "AI provider is not set to groq.",
        }
    if not groq_api_key:
        return {
            "provider": "groq",
            "model": model,
            "source": "fallback",
            "briefing": _fallback_incident_briefing(incident_payload, "Groq API key is not configured."),
            "fallback_reason": "GROQ_API_KEY is not configured.",
        }

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {groq_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "temperature": 0.2,
                "max_tokens": 700,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": INCIDENT_BRIEFING_SYSTEM_PROMPT},
                    {"role": "user", "content": _briefing_prompt(incident_payload)},
                ],
            },
            timeout=18,
        )
        if response.status_code in (408, 409, 429, 500, 502, 503, 504):
            return {
                "provider": "groq",
                "model": model,
                "source": "fallback",
                "briefing": _fallback_incident_briefing(incident_payload, f"Groq HTTP {response.status_code}."),
                "fallback_reason": f"groq_http_{response.status_code}",
            }
        response.raise_for_status()
        raw = response.json()["choices"][0]["message"]["content"]
        parsed = _parse_json(raw)
        return {
            "provider": "groq",
            "model": model,
            "source": "ai-live",
            "briefing": _normalize_briefing(parsed, fallback),
        }
    except requests.exceptions.Timeout:
        reason = "groq_timeout"
    except Exception as exc:
        reason = f"groq_error:{type(exc).__name__}"

    return {
        "provider": "groq",
        "model": model,
        "source": "fallback",
        "briefing": _fallback_incident_briefing(incident_payload, reason),
        "fallback_reason": reason,
    }


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

def check_provider_config(
    provider: str,
    gemini_key: str = "",
    groq_key: str = "",
    deepseek_key: str = "",
    model: str = "",
) -> dict:
    """Return provider readiness without exposing secrets or requiring network access."""
    selected = (provider or "none").lower()
    keys = {
        "gemini": bool(gemini_key),
        "groq": bool(groq_key),
        "deepseek": bool(deepseek_key),
        "none": False,
    }
    configured = keys.get(selected, False)
    selected_model = model or ("llama-3.1-8b-instant" if selected == "groq" else "provider-default")
    return {
        "provider": selected if selected in keys else "none",
        "configured": configured,
        "model": selected_model,
        "mode": "provider" if configured else "deterministic_fallback",
        "fallback_available": True,
        "message": "AI connector configured" if configured else "Deterministic briefing fallback active",
    }


def check_status(
    api_key: str,
    model: str,
    ollama_base: str,
    ollama_model: str,
    provider: str = "none",
    gemini_key: str = "",
    groq_key: str = "",
    deepseek_key: str = "",
    provider_model: str = "",
) -> dict:
    """Verifica disponibilidade de cada provedor de IA."""
    selected_provider = check_provider_config(
        provider, gemini_key, groq_key, deepseek_key, provider_model
    )
    result: dict = {
        "provider": selected_provider["provider"],
        "model": selected_provider["model"],
        "configured": selected_provider["configured"],
        "fallback_available": True,
        "selected_provider": selected_provider,
    }

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

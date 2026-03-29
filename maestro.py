# maestro.py — O Maestro do SPARK SOC
import requests
import time
import json
from datetime import datetime, timezone
from config import *
from database import inicializar_banco, salvar_evento

# Cache: evita consultar o mesmo IP várias vezes seguidas
_cache_ips = {}

# Cache do token Wazuh
_wazuh_token = None
_token_time = 0


# ──────────────────────────────────────────────────────────
# CAMADA 1: COLETA (FortiGate / Mock)
# ──────────────────────────────────────────────────────────
def coletar_sessoes_fortigate():
    url = f"{FORTIGATE_BASE_URL}/api/v2/monitor/system/resource/usage"
    params = {"access_token": FORTIGATE_API_KEY, "interval": "1-min"}
    try:
        response = requests.get(url, params=params, timeout=10, verify=False)
        response.raise_for_status()
        results = response.json().get("results", {})

        cpu = results.get("cpu", [{}])[0].get("current", 0)
        mem = results.get("mem", [{}])[0].get("current", 0)
        sessions = results.get("session", [{}])[0].get("current", 0)

        print(f"[FortiGate] CPU: {cpu}% | Mem: {mem}% | Sessões: {sessions}")

        # Gera eventos sintéticos baseados nos dados reais
        eventos = [{
            "srcip": "fortigate-monitor",
            "dstip":  "internal",
            "proto":  "system",
            "dstport": 0,
            "bytes":   0,
            "cpu":     cpu,
            "mem":     mem,
            "sessions": sessions
        }]
        return eventos

    except Exception as e:
        print(f"[FortiGate] ERRO: {e}")
        return []
    
    
# ──────────────────────────────────────────────────────────
# CAMADA 2: ENRIQUECIMENTO (AbuseIPDB)
# ──────────────────────────────────────────────────────────
def consultar_abuseipdb(ip: str) -> dict:
    if ip.startswith(("192.168.", "10.", "172.16.", "127.")):
        return {"abuseConfidenceScore": 0, "isPrivate": True}
    if ip in _cache_ips:
        return _cache_ips[ip]
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {})
        _cache_ips[ip] = data
        print(f"  [AbuseIPDB] {ip} score={data.get('abuseConfidenceScore', 0)}")
        return data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            print("  [AbuseIPDB] Rate limit. Aguardando 60s...")
            time.sleep(60)
        return {"abuseConfidenceScore": 0}


# ──────────────────────────────────────────────────────────
# CAMADA 3: CORRELAÇÃO E DECISÃO
# ──────────────────────────────────────────────────────────
def classificar_e_agir(sessao: dict, abuse: dict) -> dict:
    score   = abuse.get("abuseConfidenceScore", 0)
    reports = abuse.get("totalReports", 0)
    is_priv = abuse.get("isPrivate", False)
    if is_priv:
        classif, acao = "INTERNAL", "MONITOR"
    elif score >= SCORE_BLOQUEIO:
        classif, acao = "MALICIOUS", "BLOCK"
    elif score >= SCORE_ALERTA:
        classif, acao = "SUSPICIOUS", "ALERT"
    else:
        classif, acao = "CLEAN", "ALLOW"
    if acao == 'BLOQUEAR':
        print(f"  BLOQUEIO: {sessao['srcip']} (score: {score})")
    return {
        **sessao,
        "abuse_score": score,
        "total_reports": reports,
        "classificacao": classif,
        "acao": acao
    }


# ──────────────────────────────────────────────────────────
# CAMADA 4: INTEGRAÇÃO WAZUH SIEM
# ──────────────────────────────────────────────────────────
def obter_token_wazuh():
    global _wazuh_token, _token_time
    # Reutiliza o token se ainda for válido (55 minutos)
    if _wazuh_token and (time.time() - _token_time) < 3300:
        return _wazuh_token
    try:
        r = requests.get(
            "https://localhost:55000/security/user/authenticate?raw=true",
            auth=("wazuh", "Spark.SOC+2026"),
            verify=False,
            timeout=10
        )
        _wazuh_token = r.text.strip()
        _token_time = time.time()
        print("[Wazuh] Token obtido com sucesso")
        return _wazuh_token
    except Exception as e:
        print(f"[Wazuh] Erro ao obter token: {e}")
        return None


import socket

def enviar_para_wazuh(evento: dict):
    if evento.get("classificacao") not in ["MALICIOUS", "SUSPICIOUS"]:
        return
    try:
        msg = (
            f"SPARK_SOC | "
            f"classificacao={evento.get('classificacao')} | "
            f"ip_origem={evento.get('srcip')} | "
            f"ip_destino={evento.get('dstip')} | "
            f"abuse_score={evento.get('abuse_score')} | "
            f"acao={evento.get('acao')} | "
            f"porta={evento.get('dstport')}"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), ("localhost", 514))
        sock.close()
        print(f"[Wazuh] Syslog enviado: {evento['srcip']} ({evento['classificacao']})")
    except Exception as e:
        print(f"[Wazuh] Erro syslog: {e}")

# ──────────────────────────────────────────────────────────
# LOOP PRINCIPAL
# ──────────────────────────────────────────────────────────
def main():
    print("=" * 50)
    print("   SPARK SOC — Maestro iniciado")
    print(f"   Coleta a cada {INTERVALO_COLETA}s")
    print("=" * 50)
    inicializar_banco()
    rodada = 0
    while True:
        rodada += 1
        print(f"\n[Rodada {rodada}] {datetime.now():%H:%M:%S}")
        print("-" * 40)
        for sessao in coletar_sessoes_fortigate():
            ip = sessao.get("srcip", "")
            if not ip:
                continue
            abuse  = consultar_abuseipdb(ip)
            evento = classificar_e_agir(sessao, abuse)
            salvar_evento(evento)
            enviar_para_wazuh(evento)  # envia para o SIEM
        print(f"[Aguardando {INTERVALO_COLETA}s...]")
        time.sleep(INTERVALO_COLETA)


if __name__ == '__main__':
    main()
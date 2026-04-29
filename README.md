# SPARK SOC

NG-SOC as a Service para o FIAP/Fortinet Challenge.

## Estrutura

```text
backend/      Flask blueprints e clientes Wazuh/FortiGate/Shuffle/IA
frontend/     HTML estático, JS legado e ilhas React
scripts/      automações locais de tunnel/start/stop
data/         runtime local do SQLite (ignorado no Git)
```

`config.py` é local e fica fora do Git por conter credenciais do lab. Para uma
nova máquina, copie `config.example.py` para `config.py` e preencha os tokens.

## Rodar com Wazuh Indexer via SSH tunnel

O Wazuh Indexer fica protegido dentro da VM em `localhost:9200`. No Windows/host,
o SPARK acessa ele por um tunnel local em `https://localhost:19200`.

1. Ligue a VM Wazuh.
2. Confirme que o port forwarding SSH do VirtualBox existe:
   `localhost:2222 -> VM:22`.
3. Suba o tunnel:

```powershell
.\scripts\start-indexer-tunnel.ps1
```

4. Teste:

```powershell
$cred = Get-Credential -UserName admin
Invoke-WebRequest -Uri https://localhost:19200 -Credential $cred -SkipCertificateCheck
```

5. Rode o Flask:

```powershell
python backend/app.py
```

Ou suba tunnel + Flask de uma vez:

```powershell
.\scripts\start-spark.ps1
```

Para encerrar o tunnel:

```powershell
.\scripts\stop-indexer-tunnel.ps1
```

## Executive Overview live

A primeira aba consome `/spark/executive-overview`, que agrega:

- Wazuh Indexer: volume de alertas, severidade, timeline e workqueue.
- Wazuh Manager API: agentes monitorados e status.
- FortiGate: CPU, memória e sessões via Monitor API.
- Shuffle: conectividade básica da API e saúde do SOAR.

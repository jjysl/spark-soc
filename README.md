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

## Rodar local com Wazuh Indexer via SSH tunnel

O Wazuh Indexer fica protegido dentro da VM em `localhost:9200`. No Windows/host,
quando o backend roda localmente, o SPARK acessa ele por um tunnel em
`https://localhost:19200`.

1. Ligue a VM Wazuh/Shuffle no VMware.
2. Confirme que o host alcança a VM em `192.168.50.20` e que SSH responde na porta `22`.
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

Defaults do lab VMware quando o backend roda dentro da VM Wazuh/Shuffle:

```powershell
$env:WAZUH_BASE="https://192.168.50.20:55000"
$env:SHUFFLE_BASE_URL="http://192.168.50.20:3001"
$env:SHUFFLE_BACKEND_URL="http://192.168.50.20:5001"
$env:INDEXER_BASE="https://localhost:9200"
$env:FORTIGATE_BASE_URL="https://192.168.50.40"
```

Para encerrar o tunnel:

```powershell
.\scripts\stop-indexer-tunnel.ps1
```

## Deploy no VMware Lab

O Windows/VS Code é a fonte oficial do código. Não edite arquivos manualmente
em `/opt/spark-soc` na VM Wazuh, porque isso deixa o ambiente fora do controle
de versão.

Arquitetura do lab:

```text
Windows host / navegador: 192.168.50.1
Wazuh + Shuffle VM:      192.168.50.20
Agent/client VM:         192.168.50.30
FortiGate SOC IP:        192.168.50.40
Dashboard:               http://192.168.50.20:5000
Shuffle frontend:        http://192.168.50.20:3001
Shuffle backend/API:     http://192.168.50.20:5001
Wazuh API:               https://192.168.50.20:55000
Wazuh Indexer na VM:     https://localhost:9200
```

Fluxo recomendado:

1. Desenvolva e commite no Windows.
2. Rode o deploy pelo PowerShell a partir da raiz do projeto:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-vmware.ps1
```

O script cria um `spark-soc.tar.gz` temporário, envia para
`wazuh@192.168.50.20:/tmp/spark-soc.tar.gz`, reinstala `/opt/spark-soc` e
reinicia o serviço `spark-soc`.

O deploy preserva na VM:

- `/opt/spark-soc/vendor`
- `/opt/spark-soc/.env`
- `/opt/spark-soc/config.py`

Esses arquivos não são substituídos pelo pacote do Windows. Se a VM ainda não
tiver `config.py`, o script cria um a partir de `config.example.py`.

A FortiGate API key deve ser configurada apenas no `.env` da VM em
`/opt/spark-soc/.env`. Não coloque o token real no Git, README, `.env.example`
ou `config.example.py`.

Se o `sudo` pedir senha, digite a senha do usuário `wazuh`. Se o serviço falhar,
verifique na VM:

```bash
sudo systemctl status spark-soc --no-pager
sudo journalctl -u spark-soc -n 100 --no-pager
```

## Executive Overview live

A primeira aba consome `/spark/executive-overview`, que agrega:

- Wazuh Indexer: volume de alertas, severidade, timeline e workqueue.
- Wazuh Manager API: agentes monitorados e status.
- FortiGate: CPU, memória e sessões via Monitor API.
- Shuffle: conectividade básica da API e saúde do SOAR.

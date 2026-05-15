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

Para contenção via FortiGate, o SPARK usa por padrão:

```text
FORTIGATE_BLOCKLIST_GROUP=SPARK_BLOCKLIST
FORTIGATE_BLOCKLIST_POLICY=SPARK_AUTO_BLOCK
FORTIGATE_BLOCK_SRCINTF=any
FORTIGATE_BLOCK_DSTINTF=any
```

Teste manual de bloqueio:

```bash
curl -X POST http://192.168.50.20:5000/spark/fortigate/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.124","reason":"Manual SOC containment test","source":"manual","severity":"high"}'
```

Listar bloqueios:

```bash
curl http://192.168.50.20:5000/spark/fortigate/blocklist
```

Teste manual de desbloqueio:

```bash
curl -X POST http://192.168.50.20:5000/spark/fortigate/unblock-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.124","reason":"Test cleanup"}'
```

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

## Frontend Architecture

O frontend agora usa um shell React unico em `frontend/src`, servido diretamente pelo Flask sem etapa de build. Por compatibilidade com o ambiente atual, os arquivos carregados pelo navegador sao `.js` UMD/IIFE em vez de JSX compilado.

```text
frontend/src/api/          API client centralizado e modulos por dominio
frontend/src/hooks/        hooks reutilizaveis para live data, acoes e toast
frontend/src/components/   componentes comuns, incidentes, integracoes e compliance
frontend/src/components/layout/ AppShell, Header, SidebarOrTabs e PageContainer
frontend/src/pages/        paginas React ativas do dashboard
frontend/src/styles/       tokens e estilos de componentes novos
```

Camada de API:

- `SparkApi.client`: wrapper unico de `fetch` com JSON, credenciais e erro padrao.
- `SparkApi.fortigate`: `getStatus`, `blockIp`, `unblockIp`, `getBlocklist`.
- `SparkApi.incidents`: response telemetry, case creation e case actions.
- `SparkApi.integrations`: executive overview, threat detection, network endpoint e status auxiliares.
- `SparkApi.compliance`: compliance/risk telemetry.

Hooks e componentes:

- `useLiveData(fetcher, options)`: polling, loading inicial, erro e refresh manual.
- `useAsyncAction(action)`: estado `idle/loading/success/error` para comandos.
- `useToast()`: feedback global de sucesso/erro.
- `ActionButton`, `StatusBadge`, `MetricCard`, `ToastProvider`, `LoadingState`, `EmptyState`, `ErrorState`, modal e drawer.
- `BlockIpModal`, `EvidencePanel`, `ContainmentStatus`, `IntegrationHealthCard`.
- `ComplianceEvidenceTable`.

## Frontend Migration Plan

Migrado nesta etapa:

- `frontend/dashboard.html` virou shell minimo com `#root` e scripts do app React.
- `frontend/src/App.js` monta o dashboard inteiro em um unico root React.
- `AppShell`, `Header`, `SidebarOrTabs` e `PageContainer` substituem topbar, tabbar, relogio e navegacao antigos.
- Paginas ativas foram movidas para `frontend/src/pages`.
- API calls das paginas ativas passam por `frontend/src/api`.
- Incident Response usa `/spark/fortigate/block-ip`, `/spark/fortigate/unblock-ip` e `/spark/fortigate/blocklist`.
- Compliance/Risk usa tabela de Evidence Coverage e disclaimer de auditoria.

Legado mantido apenas como codigo nao ativo:

- `frontend/react/*` permanece no repositorio como referencia temporaria, mas nao e carregado por `dashboard.html`.

Removido nesta etapa:

- `frontend/js/exec.js`.
- CSS inline gigante de `frontend/dashboard.html`; os estilos foram movidos para `frontend/src/styles/dashboard.css`.
- Scripts ativos de `frontend/react/*` no shell do dashboard.

Ordem recomendada para eliminar o legado restante:

1. Comparar `frontend/react/*` com `frontend/src/pages` e mover qualquer detalhe visual ainda util.
2. Remover fisicamente `frontend/react/*` quando a demo validar paridade suficiente.
3. Reduzir classes CSS herdadas de `dashboard.css` que nao forem usadas pelo novo shell.
4. Introduzir build tool apenas se o projeto decidir usar JSX real, TypeScript ou bundling.

## LEGACY_FRONTEND_DEBT

O dashboard ativo nao depende mais de `frontend/js/exec.js`, `frontend/react/*` ou do layout antigo embutido em `dashboard.html`. A divida restante e manter os arquivos `frontend/react/*` como referencia temporaria e limpar classes CSS herdadas que foram migradas para `frontend/src/styles/dashboard.css`. Qualquer feature nova deve nascer em `frontend/src`.

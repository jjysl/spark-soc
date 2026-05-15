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

O frontend ainda roda sem bundler para preservar compatibilidade com o Flask estatico, mas a base de produto agora fica em `frontend/src`.

```text
frontend/src/api/          API client centralizado e modulos por dominio
frontend/src/hooks/        hooks reutilizaveis para live data, acoes e toast
frontend/src/components/   componentes comuns, incidentes, integracoes e compliance
frontend/src/styles/       tokens e estilos de componentes novos
frontend/react/            paginas React atuais montadas pelo shell legado
```

Camada de API:

- `SparkApi.client`: wrapper unico de `fetch` com JSON, credenciais e erro padrao.
- `SparkApi.fortigate`: `getStatus`, `blockIp`, `unblockIp`, `getBlocklist`.
- `SparkApi.incidents`: response telemetry, case creation e case actions.
- `SparkApi.integrations`: executive overview, network endpoint e status auxiliares.
- `SparkApi.compliance`: compliance/risk telemetry.

Hooks e componentes:

- `useLiveData(fetcher, options)`: polling, loading inicial, erro e refresh manual.
- `useAsyncAction(action)`: estado `idle/loading/success/error` para comandos.
- `useToast()`: feedback global de sucesso/erro.
- `ActionButton`, `StatusBadge`, `MetricCard`, `ToastProvider`, estados, modal e drawer.
- `BlockIpModal`, `EvidencePanel`, `ContainmentStatus`, `IntegrationHealthCard`.
- `ComplianceEvidenceTable`.

## Frontend Migration Plan

Regra de produto: a migracao React nao pode empobrecer o dashboard. O shell legado permanece ativo ate haver paridade visual por pagina.

Inventario visual que deve ser preservado antes de qualquer nova remocao:

- Header/topbar: marca SPARK SOC, status live, relogio UTC, usuario, role e logout.
- Tabs: navegacao horizontal, estado ativo, spacing compacto e responsividade.
- Cards/KPIs: bordas, sombra, badges de severidade, estados criticos e grid responsivo.
- Graficos e visualizacoes: qualquer grafico/timeline/barra existente deve ter equivalente React antes da troca.
- Tabelas: cabecalho uppercase, hover, mono para IP/timestamps, scroll horizontal e densidade operacional.
- Incident Response: candidate table, case queue, botoes de acao, Block IP, toast e painel de evidencia.
- Executive Overview: KPIs, workqueue, health de integracoes, hierarquia visual e cores de status.
- Network/Endpoint: cards de agentes/FortiGate, tabelas e sinais de conectividade.
- Compliance/Risk: tabela de evidencia e disclaimer, mantendo acabamento visual sem cards falsos de certificacao.

Migrado nesta etapa segura:

- API calls novas centralizadas em `frontend/src/api`.
- Hooks e componentes base em `frontend/src`.
- Incident Response usa `SparkApi.incidents` e `SparkApi.fortigate.blockIp`.
- Feedback de Block IP usa toast e painel de evidencia com `evidence_id`, object, group e policy.
- Compliance ganhou tabela inicial de Evidence Coverage e disclaimer de auditoria.

Ainda legado por compatibilidade:

- `frontend/dashboard.html` continua como app shell, topbar, tabbar e fallback HTML.
- `frontend/js/exec.js` ainda controla autenticacao visual, relogio e troca de tabs.
- Paginas em `frontend/react/*` ainda sao scripts globais carregados por `<script>`.
- Executive, Threat, Network e Tickets ainda possuem `fetch` e componentes locais duplicados, a migrar gradualmente.

Arquivos candidatos a remocao na proxima fase:

- `frontend/js/exec.js`, depois que `AppShell`, `Header` e `SidebarOrTabs` assumirem autenticacao, relogio e navegacao.
- CSS inline de `frontend/dashboard.html`, depois de mover tudo para `frontend/src/styles`.
- Componentes duplicados dentro de `frontend/react/*`, depois de trocar para `frontend/src/components`.

Ordem correta para eliminar o legado:

1. Migrar Incident Response mantendo paridade visual e print comparativo.
2. Migrar Executive Overview mantendo graficos/cards/cores/status.
3. Migrar Network/Endpoint mantendo integracao visual e tabelas.
4. Migrar Compliance/Risk para modelo de evidencia sem perder acabamento.
5. So depois mover topbar/tabbar para React.
6. So depois remover `frontend/js/exec.js`.
7. So depois transformar `dashboard.html` em shell minimo.

## LEGACY_FRONTEND_DEBT

O legado foi preservado para nao quebrar a demo enquanto a arquitetura React e introduzida. Ele nao deve virar permanente, mas tambem nao deve ser removido antes de paridade visual. Qualquer feature nova deve nascer em `frontend/src` e ser conectada ao shell atual com cuidado. A proxima fase deve migrar uma pagina por vez e comparar visualmente antes de remover navegacao imperativa, CSS inline ou scripts globais.

## Visual Parity Migration Status

As paginas ativas do dashboard agora carregam de `frontend/src/pages`, mantendo os mesmos roots, classes CSS, graficos, cards, tabelas e botoes do visual original:

- Executive Overview: KPIs, posture score SVG, Chart.js alert volume, workqueue expansivel, filtros e service request.
- Threat Detection: cards de alertas, graficos Chart.js, filtros, facetas, MITRE e tabela de alertas Wazuh.
- Network / Endpoint: cards FortiGate/Wazuh, topologia SVG, agentes, correlacoes, blocklist e tabelas operacionais.
- Incident Response: candidates, case queue, timeline, action log, Block IP, Unblock IP, FortiGate blocklist e evidence panel.
- Compliance / Risk: tabela Evidence Coverage, disclaimer de auditoria, achados Wazuh e sem PCI DSS/porcentagens de certificacao como cards principais.
- Cases & Response: listagem rica de casos, filtros, formulario, FortiGate block action, escalonamento, Jira e logs de resposta.

O shell `frontend/dashboard.html` e `frontend/js/exec.js` ainda sao ativos por decisao de paridade visual. Eles so devem ser removidos quando um AppShell React reproduzir o mesmo header, tabs, spacing, estados globais e responsividade.

## Product UI Direction

O dashboard comunica o fluxo operacional `Detect -> Decide -> Respond -> Document`. A camada visual adicionada nesta fase preserva os graficos e tabelas existentes, mas reforca o posicionamento de produto MDR:

- Product strip no shell com narrativa NG-SOC/MDR e etapas Detect, Analyze, Respond, Contain, Document.
- Incident Response com SPARK Trace, Block IP modal, Evidence Pack e Containment Confidence.
- Block/Unblock continuam usando os endpoints FortiGate reais e atualizam blocklist/action log sem reload completo.
- AppShell React profissional existe em `frontend/src/components/layout` como alvo da proxima fase, mas ainda nao substitui o shell ativo para evitar perda visual.

`dashboard.html` e `frontend/js/exec.js` continuam ativos porque ainda carregam o header, tabs, relogio e responsividade com paridade visual total. A remocao deve acontecer apenas depois que o AppShell React reproduzir ou melhorar esses elementos.

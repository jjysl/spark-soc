param(
    [string]$SshUser = "wazuh",
    [string]$SshHost = "127.0.0.1",
    [int]$SshPort = 2222,
    [string]$KeyPath = "$env:USERPROFILE\.ssh\sparksoc_wazuh_ed25519"
)

$ErrorActionPreference = "Stop"

$ssh = Get-Command ssh -ErrorAction SilentlyContinue
if (-not $ssh) {
    throw "OpenSSH client nao encontrado. Instale o recurso 'OpenSSH Client' do Windows."
}

$sshKeygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
if (-not $sshKeygen) {
    throw "ssh-keygen nao encontrado. Instale o recurso 'OpenSSH Client' do Windows."
}

$sshDir = Split-Path -Parent $KeyPath
if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir | Out-Null
}

if (-not (Test-Path $KeyPath)) {
    Write-Host "[SPARK] Gerando chave SSH em $KeyPath" -ForegroundColor Cyan
    ssh-keygen -q -t ed25519 -f $KeyPath -N '""' -C "sparksoc-wazuh-tunnel"
} else {
    Write-Host "[SPARK] Chave ja existe: $KeyPath" -ForegroundColor Yellow
}

if (-not (Test-Path "$KeyPath.pub")) {
    Write-Host "[SPARK] Arquivo .pub nao encontrado; recriando a partir da chave privada." -ForegroundColor Yellow
    ssh-keygen -y -f $KeyPath | Set-Content -Encoding ascii "$KeyPath.pub"
}

$publicKey = (Get-Content "$KeyPath.pub" -Raw).Trim()
$remoteCommand = "mkdir -p ~/.ssh && chmod 700 ~/.ssh && grep -qxF '$publicKey' ~/.ssh/authorized_keys 2>/dev/null || echo '$publicKey' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

Write-Host "[SPARK] Instalando chave publica na VM Wazuh via SSH localhost:$SshPort" -ForegroundColor Cyan
Write-Host "[SPARK] Digite a senha do usuario '$SshUser' da VM quando o ssh pedir." -ForegroundColor Yellow
ssh -o StrictHostKeyChecking=accept-new -p $SshPort "$SshUser@$SshHost" $remoteCommand

Write-Host "[SPARK] Testando login por chave..." -ForegroundColor Cyan
ssh -i $KeyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p $SshPort "$SshUser@$SshHost" "echo ok"

Write-Host "[SPARK] Chave SSH configurada. Agora o tunnel sobe sem senha." -ForegroundColor Green

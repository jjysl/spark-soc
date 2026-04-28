param(
    [string]$SshUser = "wazuh",
    [string]$SshHost = "127.0.0.1",
    [int]$SshPort = 2222
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

& "$PSScriptRoot\start-indexer-tunnel.ps1" -SshUser $SshUser -SshHost $SshHost -SshPort $SshPort

Write-Host "[SPARK] Iniciando Flask em http://localhost:5000" -ForegroundColor Cyan
Set-Location $root
python backend/app.py

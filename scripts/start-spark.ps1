param(
    [string]$SshUser = "wazuh",
    [string]$SshHost = "192.168.50.20",
    [int]$SshPort = 22
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

& "$PSScriptRoot\start-indexer-tunnel.ps1" -SshUser $SshUser -SshHost $SshHost -SshPort $SshPort

Write-Host "[SPARK] Iniciando Flask em http://localhost:5000" -ForegroundColor Cyan
Set-Location $root
$env:SPARK_PROFILE = if ($env:SPARK_PROFILE) { $env:SPARK_PROFILE } else { "vmware-lab" }
$env:WAZUH_MANAGER_IP = if ($env:WAZUH_MANAGER_IP) { $env:WAZUH_MANAGER_IP } else { $SshHost }
$env:WAZUH_BASE = if ($env:WAZUH_BASE) { $env:WAZUH_BASE } else { "https://${SshHost}:55000" }
$env:SHUFFLE_BASE_URL = if ($env:SHUFFLE_BASE_URL) { $env:SHUFFLE_BASE_URL } else { "http://${SshHost}:3001" }
$env:SHUFFLE_BACKEND_URL = if ($env:SHUFFLE_BACKEND_URL) { $env:SHUFFLE_BACKEND_URL } else { "http://${SshHost}:5001" }
$env:INDEXER_BASE = if ($env:INDEXER_BASE) { $env:INDEXER_BASE } else { "https://localhost:19200" }
python backend/app.py

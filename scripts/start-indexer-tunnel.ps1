param(
    [string]$SshUser = "wazuh",
    [string]$SshHost = "127.0.0.1",
    [int]$SshPort = 2222,
    [int]$LocalIndexerPort = 19200,
    [int]$RemoteIndexerPort = 9200,
    [string]$KeyPath = "$env:USERPROFILE\.ssh\sparksoc_wazuh_ed25519"
)

$ErrorActionPreference = "Stop"

function Test-PortListening {
    param([int]$Port)
    return [bool](Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Test-OpenSsh {
    $ssh = Get-Command ssh -ErrorAction SilentlyContinue
    if (-not $ssh) {
        throw "OpenSSH client nao encontrado. Instale o recurso 'OpenSSH Client' do Windows."
    }
}

Test-OpenSsh

if (Test-PortListening -Port $LocalIndexerPort) {
    Write-Host "[SPARK] Porta local $LocalIndexerPort ja esta ouvindo. Vou reutilizar o tunel/servico existente." -ForegroundColor Yellow
} else {
    $identityArgs = @()
    if (Test-Path $KeyPath) {
        $identityArgs = @("-i", $KeyPath)
    }

    $batchArgs = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "StrictHostKeyChecking=accept-new"
    ) + $identityArgs + @(
        "-p", "$SshPort",
        "$SshUser@$SshHost",
        "exit"
    )
    $batch = Start-Process -FilePath "ssh" -ArgumentList $batchArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\sparksoc-ssh-test.out" -RedirectStandardError "$env:TEMP\sparksoc-ssh-test.err"
    $hasKeyAuth = $batch.ExitCode -eq 0

    $args = @(
        "-N",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-L", "127.0.0.1:${LocalIndexerPort}:127.0.0.1:${RemoteIndexerPort}",
        $identityArgs,
        "-p", "$SshPort",
        "$SshUser@$SshHost"
    ) | ForEach-Object { $_ }

    Write-Host "[SPARK] Abrindo tunel Wazuh Indexer: https://localhost:$LocalIndexerPort -> VM localhost:$RemoteIndexerPort" -ForegroundColor Cyan
    if ($hasKeyAuth) {
        Write-Host "[SPARK] Chave SSH detectada. O tunel vai rodar em segundo plano." -ForegroundColor DarkGray
        $windowStyle = "Hidden"
    } else {
        throw "Chave SSH nao detectada. Rode primeiro: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-wazuh-ssh-key.ps1"
    }

    $process = Start-Process -FilePath "ssh" -ArgumentList $args -WindowStyle $windowStyle -PassThru
    Start-Sleep -Seconds 3

    if (-not (Test-PortListening -Port $LocalIndexerPort)) {
        throw "O tunel nao abriu a porta local $LocalIndexerPort. Verifique se a VM esta ligada e se o SSH em localhost:$SshPort funciona."
    }

    Write-Host "[SPARK] Tunel iniciado. PID: $($process.Id)" -ForegroundColor Green
}

Write-Host "[SPARK] Teste rapido:" -ForegroundColor Cyan
Write-Host "curl.exe -k -u admin:Spark.SOC+2026 https://localhost:$LocalIndexerPort" -ForegroundColor DarkGray

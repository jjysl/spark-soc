param(
    [int]$LocalIndexerPort = 19200
)

$connections = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $LocalIndexerPort -State Listen -ErrorAction SilentlyContinue
if (-not $connections) {
    Write-Host "[SPARK] Nenhum tunel ouvindo em localhost:$LocalIndexerPort." -ForegroundColor Yellow
    exit 0
}

$pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
foreach ($pidValue in $pids) {
    $process = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -eq "ssh") {
        Stop-Process -Id $pidValue -Force
        Write-Host "[SPARK] Tunel encerrado. PID: $pidValue" -ForegroundColor Green
    } else {
        Write-Host "[SPARK] Porta $LocalIndexerPort pertence a '$($process.ProcessName)' PID $pidValue; nao encerrei." -ForegroundColor Yellow
    }
}

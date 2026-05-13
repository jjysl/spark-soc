param(
    [string]$SshUser = "wazuh",
    [string]$SshHost = "192.168.50.20",
    [string]$RemoteRoot = "/opt/spark-soc",
    [string]$ServiceName = "spark-soc",
    [string]$ArchivePath = "$env:TEMP\spark-soc.tar.gz"
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path (Join-Path $scriptRoot "..")
$projectName = Split-Path -Leaf $projectRoot
$projectParent = Split-Path -Parent $projectRoot

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

Require-Command tar
Require-Command scp
Require-Command ssh

Set-Location $projectRoot
$sshOptions = @("-o", "StrictHostKeyChecking=accept-new")

if (Test-Path $ArchivePath) {
    Remove-Item -Force -LiteralPath $ArchivePath
}

$excludeArgs = @(
    "--exclude=$projectName/.git",
    "--exclude=$projectName/.venv",
    "--exclude=$projectName/vendor",
    "--exclude=$projectName/node_modules",
    "--exclude=$projectName/wheelhouse",
    "--exclude=$projectName/__pycache__",
    "--exclude=*/__pycache__",
    "--exclude=$projectName/*.pyc",
    "--exclude=*.pyc",
    "--exclude=$projectName/spark-soc.tar.gz",
    "--exclude=$projectName/spark-deps.tar.gz",
    "--exclude=$projectName/.env",
    "--exclude=$projectName/config.py"
)

Write-Host "[SPARK] Creating archive: $ArchivePath" -ForegroundColor Cyan
& tar @excludeArgs -czf $ArchivePath -C $projectParent $projectName

Write-Host "[SPARK] Uploading archive to ${SshUser}@${SshHost}:/tmp/spark-soc.tar.gz" -ForegroundColor Cyan
& scp @sshOptions $ArchivePath "${SshUser}@${SshHost}:/tmp/spark-soc.tar.gz"

$remoteScript = @'
set -e
service_name="spark-soc"
remote_root="/opt/spark-soc"
release_dir="/opt/SPARKSoc"
archive="/tmp/spark-soc.tar.gz"
backup_dir="/tmp/spark-soc-preserve-$$"

sudo mkdir -p "$backup_dir"

if sudo test -d "$remote_root/vendor"; then
  sudo mv "$remote_root/vendor" "$backup_dir/vendor"
fi

if sudo test -f "$remote_root/.env"; then
  sudo cp "$remote_root/.env" "$backup_dir/.env"
fi

if sudo test -f "$remote_root/config.py"; then
  sudo cp "$remote_root/config.py" "$backup_dir/config.py"
fi

sudo systemctl stop "$service_name" 2>/dev/null || true
sudo rm -rf "$remote_root" "$release_dir"
sudo tar -xzf "$archive" -C /opt
sudo mv "$release_dir" "$remote_root"

if sudo test -d "$backup_dir/vendor"; then
  sudo rm -rf "$remote_root/vendor"
  sudo mv "$backup_dir/vendor" "$remote_root/vendor"
fi

if sudo test -f "$backup_dir/.env"; then
  sudo cp "$backup_dir/.env" "$remote_root/.env"
fi

if sudo test -f "$backup_dir/config.py"; then
  sudo cp "$backup_dir/config.py" "$remote_root/config.py"
elif sudo test -f "$remote_root/config.example.py"; then
  sudo cp "$remote_root/config.example.py" "$remote_root/config.py"
fi

sudo rm -rf "$backup_dir"
sudo systemctl start "$service_name"
sudo systemctl status "$service_name" --no-pager
'@

$remoteScript = $remoteScript.Replace('service_name="spark-soc"', "service_name=`"$ServiceName`"")
$remoteScript = $remoteScript.Replace('remote_root="/opt/spark-soc"', "remote_root=`"$RemoteRoot`"")

Write-Host "[SPARK] Deploying on ${SshHost} and restarting $ServiceName" -ForegroundColor Cyan
$remoteScript | ssh @sshOptions "${SshUser}@${SshHost}" "bash -s"

Write-Host "[SPARK] Testing dashboard from Windows host: http://${SshHost}:5000" -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "http://${SshHost}:5000" -UseBasicParsing -TimeoutSec 10
    Write-Host "[SPARK] Dashboard HTTP status: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[SPARK] Dashboard test failed from Windows: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "[SPARK] Open http://${SshHost}:5000 in the browser and check: sudo systemctl status $ServiceName --no-pager" -ForegroundColor Yellow
}

$root = Split-Path -Parent $PSScriptRoot

Start-Process -FilePath powershell.exe `
    -ArgumentList "-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSScriptRoot\setup-wazuh-ssh-key.ps1`"" `
    -WorkingDirectory $root `
    -WindowStyle Normal

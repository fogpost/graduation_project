param(
  [switch]$WithCapture
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot

Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $repoRoot 'scripts\start_backend.ps1')
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $repoRoot 'scripts\start_frontend.ps1')

if ($WithCapture) {
  Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $repoRoot 'scripts\start_go_capture.ps1')
}

Write-Host 'Backend and frontend launch commands have been started in new PowerShell windows.'
if ($WithCapture) {
  Write-Host 'Go live capture process has also been started.'
}

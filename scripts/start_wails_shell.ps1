$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $repoRoot 'Traffic_analyzer\wails_shell\frontend')
npm install
Set-Location (Join-Path $repoRoot 'Traffic_analyzer\wails_shell')

go mod tidy
wails dev

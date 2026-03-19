$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $repoRoot 'Traffic_analyzer\traffic-ui')

npm install
npm run dev

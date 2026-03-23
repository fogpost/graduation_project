$ErrorActionPreference = 'Stop'
param(
  [string[]]$ArgsForGo = @()
)

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $repoRoot 'Traffic_analyzer\go_capture')

go mod tidy
go run . @ArgsForGo

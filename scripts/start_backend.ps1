$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path '.venv\Scripts\python.exe')) {
  Write-Host 'Virtual environment not found. Creating .venv...'
  python -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
& .\.venv\Scripts\python.exe -m uvicorn Traffic_analyzer.main:app --reload --host 127.0.0.1 --port 8000

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonRoot = Join-Path $projectRoot 'code\python'
$composeRoot = Join-Path $projectRoot 'code'
$workspaceVenv = Join-Path (Split-Path -Parent $projectRoot) '.venv\Scripts\python.exe'
$projectVenv = Join-Path $projectRoot '.venv\Scripts\python.exe'
$envExample = Join-Path $pythonRoot '.env.example'
$envFile = Join-Path $pythonRoot '.env'

function Find-ProjectPython {
    foreach ($candidate in @($projectVenv, $workspaceVenv)) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    throw @"
Python 3.12 virtual environment was not found.
Run these commands from the project root:
  py -3.12 -m venv .venv
  .\.venv\Scripts\python.exe -m pip install -r code\python\requirements-dev.txt
"@
}

$pythonExe = Find-ProjectPython

if (-not (Test-Path -LiteralPath $envFile)) {
    Copy-Item -LiteralPath $envExample -Destination $envFile
    Write-Host 'Created code\python\.env from .env.example.' -ForegroundColor Yellow
    Write-Host 'Offline mode is enabled by default; no API key is required for health checks and security analysis.'
}

$env:PYTHONUTF8 = '1'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker command was not found. Install and start Docker Desktop first.'
}

try {
    docker info *> $null
} catch {
    throw 'Docker Desktop is not running. Start Docker Desktop, wait until it is ready, then run this script again.'
}

Write-Host 'Starting Neo4j...' -ForegroundColor Cyan
Push-Location $composeRoot
try {
    docker compose up -d neo4j
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to start the Neo4j container.'
    }

    $ready = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $health = docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' sentinelkb-neo4j 2>$null
        if ($health -eq 'healthy') {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) {
        throw 'Neo4j did not become healthy within 60 seconds. Run: docker compose logs neo4j'
    }
} finally {
    Pop-Location
}

Write-Host 'SentinelKB development server' -ForegroundColor Cyan
Write-Host "Python: $pythonExe"
Write-Host 'Console:  http://localhost:8080'
Write-Host 'API docs: http://localhost:8080/docs'
Write-Host 'Health:   http://localhost:8080/api/health'
Write-Host 'Neo4j:    http://localhost:7474 (neo4j / password)'
Write-Host 'Press Ctrl+C to stop.'

Set-Location $pythonRoot
& $pythonExe -m uvicorn api.main:app --host 127.0.0.1 --port 8080

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$composeRoot = Join-Path $projectRoot 'code'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker command was not found.'
}

Write-Host 'Stopping SentinelKB Neo4j container...' -ForegroundColor Cyan
Push-Location $composeRoot
try {
    docker compose stop neo4j
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to stop the Neo4j container.'
    }
} finally {
    Pop-Location
}

Write-Host 'Neo4j stopped. Project data remains in the Docker volume.' -ForegroundColor Green
Write-Host 'If the API terminal is still open, press Ctrl+C in that terminal.'

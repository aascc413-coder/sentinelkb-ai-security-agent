$ErrorActionPreference = 'Stop'

$baseUrl = 'http://localhost:8080'

function Assert-Condition {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw "FAILED: $Message"
    }
    Write-Host "PASS: $Message" -ForegroundColor Green
}

Write-Host 'SentinelKB end-to-end smoke test' -ForegroundColor Cyan

$health = Invoke-RestMethod -Uri "$baseUrl/api/health" -TimeoutSec 10
Assert-Condition ($health.status -eq 'ok') 'API health status is ok'
Assert-Condition ($health.components.vector_store.status -eq 'ready') 'Vector store is ready'
Assert-Condition ($health.components.knowledge_graph.status -eq 'ready') 'Neo4j knowledge graph is ready'
Assert-Condition ($health.components.workflows.status -eq 'ready') 'LangGraph workflows are ready'

$questionJson = @{
    question = 'Mimikatz PowerShell SMB incident response'
} | ConvertTo-Json
$question = Invoke-RestMethod `
    -Uri "$baseUrl/api/qa/ask" `
    -Method Post `
    -ContentType 'application/json; charset=utf-8' `
    -Body ([Text.Encoding]::UTF8.GetBytes($questionJson)) `
    -TimeoutSec 90
Assert-Condition (-not [string]::IsNullOrWhiteSpace($question.answer)) 'Knowledge QA returned an answer'
Assert-Condition ($question.sources.Count -gt 0) 'Knowledge QA returned traceable sources'

$analysisJson = @{
    text = 'PowerShell EncodedCommand contacted http://evil-example.top/a, followed by Mimikatz credential dumping and SMB lateral movement from 203.0.113.10.'
    source = 'smoke-test'
} | ConvertTo-Json
$analysis = Invoke-RestMethod `
    -Uri "$baseUrl/api/security/analyze" `
    -Method Post `
    -ContentType 'application/json; charset=utf-8' `
    -Body ([Text.Encoding]::UTF8.GetBytes($analysisJson)) `
    -TimeoutSec 90
Assert-Condition ($analysis.indicators.Count -ge 1) 'Security analysis extracted IOCs'
Assert-Condition ($analysis.techniques.Count -ge 3) 'Security analysis mapped ATT&CK techniques'

$stats = Invoke-RestMethod -Uri "$baseUrl/api/admin/stats" -TimeoutSec 10
Assert-Condition ($stats.vector_store.total_vectors -gt 0) 'Retrieval index contains data'
Assert-Condition ($stats.knowledge_graph.total_entities -gt 0) 'Knowledge graph contains entities'
Assert-Condition ($stats.knowledge_graph.total_relations -gt 0) 'Knowledge graph contains relationships'

Write-Host ''
Write-Host 'All end-to-end checks passed.' -ForegroundColor Cyan
Write-Host "Mode: $($health.mode) | Vectors: $($stats.vector_store.total_vectors) | Entities: $($stats.knowledge_graph.total_entities) | Relations: $($stats.knowledge_graph.total_relations)"

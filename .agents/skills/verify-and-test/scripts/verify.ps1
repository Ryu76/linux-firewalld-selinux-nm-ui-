$ErrorActionPreference = "Stop"
Write-Host "[1/2] Running pytest suite..." -ForegroundColor Cyan
python -m pytest -v

Write-Host "[2/2] Checking agent/ for Python 3.9 incompatible union syntax..." -ForegroundColor Cyan
$matches = Select-String -Path "agent\*.py" -Pattern "\|\s*None|\bUnion\b" -SimpleMatch:$false | Where-Object { $_.Line -match "\|\s*None" }
if ($matches) {
    Write-Host "WARNING: Found Python 3.10+ union syntax (| None) in agent/:" -ForegroundColor Yellow
    $matches | ForEach-Object { Write-Host "  $($_.Filename):$($_.LineNumber): $($_.Line.Trim())" }
    exit 1
}
Write-Host "All checks passed!" -ForegroundColor Green

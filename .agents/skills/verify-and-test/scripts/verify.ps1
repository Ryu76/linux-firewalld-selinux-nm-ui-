$ErrorActionPreference = "Stop"

Write-Host "[1/2] Checking Python version in uv environment..." -ForegroundColor Cyan
uv run python --version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/2] Running pytest suite..." -ForegroundColor Cyan
uv run pytest -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "All checks passed!" -ForegroundColor Green

$ErrorActionPreference = "Stop"

param(
    [string]$PythonVersion = "3.14",
    [string]$Platform = "manylinux2014_x86_64"
)

$WheelsDir = Join-Path $PSScriptRoot "wheels"
$ExportedReq = Join-Path $PSScriptRoot "requirements-agent.lock.txt"
New-Item -ItemType Directory -Force -Path $WheelsDir | Out-Null

Write-Host "[1/3] Exporting locked agent dependencies from uv.lock..." -ForegroundColor Cyan
uv export --extra agent --no-dev --frozen --no-hashes -o $ExportedReq

Write-Host "[2/3] Downloading Linux ($Platform, Python $PythonVersion) wheels..." -ForegroundColor Cyan
uv run --with pip python -m pip download `
    -r $ExportedReq `
    --dest $WheelsDir `
    --platform $Platform `
    --python-version $PythonVersion `
    --only-binary=:all:

Write-Host "[3/3] Wheel bundle ready at: $WheelsDir" -ForegroundColor Green
Get-ChildItem $WheelsDir | Select-Object Name, Length

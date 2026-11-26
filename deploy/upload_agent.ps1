param(
    [Parameter(Mandatory = $true)]
    [string]$ServerIp,
    [string]$User = "root",
    [int]$SshPort = 22,
    [string]$RemoteDir = "/opt/linux-access-control-hub",
    [switch]$Offline
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $ProjectRoot

try {
    if ($Offline) {
        Write-Host "[1/2] Building offline Linux wheel bundle..." -ForegroundColor Cyan
        & (Join-Path $PSScriptRoot "build_bundle.ps1")
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        Write-Host "[1/2] Online deploy mode..." -ForegroundColor Cyan
    }

    $Target = "${User}@${ServerIp}"
    Write-Host "[2/2] Streaming bundle & executing deploy_agent.sh on ${Target} (single password prompt)..." -ForegroundColor Cyan

    # Use cmd.exe native byte pipe because Windows PowerShell 5.1 corrupts binary stdout in pipelines
    $RemoteCmd = "mkdir -p $RemoteDir && tar -xzf - -C $RemoteDir && sed -i 's/\r$//' $RemoteDir/deploy/deploy_agent.sh && bash $RemoteDir/deploy/deploy_agent.sh"
    $CmdLine = "tar.exe --exclude=__pycache__ --exclude=*.pyc --exclude=agent/logs -czf - pyproject.toml uv.lock .python-version agent deploy | ssh.exe -p $SshPort $Target `"$RemoteCmd`""
    cmd.exe /c $CmdLine
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "Deploy completed successfully!" -ForegroundColor Green
} finally {
    Pop-Location
}

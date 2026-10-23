
$ErrorActionPreference = "Stop"

$Project = "C:\Users\admin\CyberShield\CyberShield-Ransomware-Analysis"
$Image = "cybershield/analysis-sandbox:latest"

Set-Location $Project

Write-Host "`n[1/3] Checking Docker..." -ForegroundColor Cyan
docker info | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker is not running. Start Docker Desktop and try again."
}

Write-Host "`n[2/3] Building CyberShield sandbox image..." -ForegroundColor Cyan
docker build -t $Image -f docker/sandbox/Dockerfile docker/sandbox
if ($LASTEXITCODE -ne 0) {
    throw "Docker image build failed."
}

Write-Host "`n[3/3] Starting CyberShield..." -ForegroundColor Cyan
& ".\start_projectbot.ps1"

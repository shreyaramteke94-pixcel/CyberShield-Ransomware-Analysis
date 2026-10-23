$ProjectRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       CYBERSHIELD PROJECT STARTUP      " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------
# Start Backend
# -----------------------------------------

Write-Host "Starting Backend..." -ForegroundColor Yellow

Start-Process powershell.exe -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$ProjectRoot'; .\venv\Scripts\Activate.ps1; Set-Location backend; python -m uvicorn app.main:app --reload"
)

# -----------------------------------------
# Start Frontend
# -----------------------------------------

Write-Host "Starting Frontend..." -ForegroundColor Yellow

Start-Process cmd.exe -ArgumentList @(
    "/k",
    "cd /d `"$ProjectRoot\frontend`" && npm run dev -- --host localhost --port 3001"
)

# -----------------------------------------
# Wait for Frontend
# -----------------------------------------

Write-Host ""
Write-Host "Waiting for Frontend on http://localhost:3001 ..." -ForegroundColor Yellow

$FrontendReady = $false

for ($i = 1; $i -le 30; $i++) {

    Start-Sleep -Seconds 1

    try {
        $response = Invoke-WebRequest `
            -Uri "http://localhost:3001" `
            -UseBasicParsing `
            -TimeoutSec 2 `
            -ErrorAction Stop

        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
            $FrontendReady = $true
            break
        }
    }
    catch {
        # Frontend is not ready yet
    }

    Write-Host "Waiting... ($i/30)"
}

# -----------------------------------------
# Open Chrome
# -----------------------------------------

if ($FrontendReady) {

    Write-Host ""
    Write-Host "Frontend is ready!" -ForegroundColor Green
    Write-Host "Opening CyberShield..." -ForegroundColor Green

    Start-Process "chrome.exe" "http://localhost:3001"

    Write-Host ""
    Write-Host "CyberShield is running." -ForegroundColor Green
    Write-Host "Frontend : http://localhost:3001" -ForegroundColor Cyan
    Write-Host "Backend  : http://127.0.0.1:8000" -ForegroundColor Cyan
    Write-Host "Swagger  : http://127.0.0.1:8000/docs" -ForegroundColor Cyan
}
else {

    Write-Host ""
    Write-Host "ERROR: Frontend did not start on port 3001." -ForegroundColor Red
    Write-Host ""
    Write-Host "Look at the FRONTEND CMD window." -ForegroundColor Yellow
    Write-Host "It will show the actual npm/Vite error." -ForegroundColor Yellow
}
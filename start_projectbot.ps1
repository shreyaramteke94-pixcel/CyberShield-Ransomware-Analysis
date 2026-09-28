$ProjectRoot = "C:\Users\admin\CyberShield\CyberShield-Ransomware-Analysis"

Write-Host "Starting CyberShield..." -ForegroundColor Cyan

# Start Backend
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$ProjectRoot'; .\venv\Scripts\Activate.ps1; Set-Location backend; python -m uvicorn app.main:app --reload"
)

# Start Frontend
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$ProjectRoot\frontend'; npm run dev"
)

Write-Host "Waiting for frontend server..." -ForegroundColor Yellow

# Wait for frontend on port 3001
$FrontendReady = $false

for ($i = 1; $i -le 30; $i++) {
    Start-Sleep -Seconds 1

    $connection = Test-NetConnection `
        -ComputerName "localhost" `
        -Port 3001 `
        -WarningAction SilentlyContinue

    if ($connection.TcpTestSucceeded) {
        $FrontendReady = $true
        break
    }

    Write-Host "Waiting... ($i/30)"
}

if ($FrontendReady) {
    Write-Host "Frontend is running on port 3001." -ForegroundColor Green

    Start-Process "chrome.exe" "http://localhost:3001"

    Write-Host "CyberShield opened in Chrome." -ForegroundColor Green
}
else {
    Write-Host "ERROR: Frontend did not start on port 3001." -ForegroundColor Red
    Write-Host "Check the frontend PowerShell window for the npm error." -ForegroundColor Yellow
}
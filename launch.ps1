# GhostLink Launcher - PowerShell Script
# Runs both the FastAPI backend and React frontend

# Check if we're in the right directory
$projectRoot = $PSScriptRoot
if (-not (Test-Path "$projectRoot\web-radar")) {
    Write-Host "Error: web-radar folder not found in $projectRoot" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "$projectRoot\ghostlink\api\server.py")) {
    Write-Host "Error: ghostlink\api\server.py not found in $projectRoot" -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "         GhostLink Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to run backend
function Start-Backend {
    Write-Host "[1/2] Starting FastAPI backend..." -ForegroundColor Yellow
    $backendJob = Start-Job -ScriptBlock {
        param($root)
        Set-Location $root
        python -m uvicorn ghostlink.api.server:app --reload --host 127.0.0.1 --port 5966
    } -ArgumentList $projectRoot
    return $backendJob
}

# Function to run frontend
function Start-Frontend {
    Write-Host "[2/2] Starting React frontend (Vite dev server)..." -ForegroundColor Yellow
    $frontendJob = Start-Job -ScriptBlock {
        param($root)
        Set-Location "$root\web-radar"
        npm run dev
    } -ArgumentList $projectRoot
    return $frontendJob
}

# Start both services
try {
    $backend = Start-Backend
    Start-Sleep -Seconds 2  # Give backend a moment to start
    $frontend = Start-Frontend
    
    Write-Host ""
    Write-Host "✅ Services started successfully!" -ForegroundColor Green
    Write-Host "   - Backend API: http://127.0.0.1:5966" -ForegroundColor Gray
    Write-Host "   - Frontend UI: http://localhost:5173" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Press Ctrl+C to stop all services..." -ForegroundColor Cyan
    Write-Host ""

    # Wait for user input to stop
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host ""
    Write-Host "🛑 Stopping services..." -ForegroundColor Yellow
    if ($backend) { Stop-Job $backend; Remove-Job $backend -Force }
    if ($frontend) { Stop-Job $frontend; Remove-Job $frontend -Force }
    Write-Host "✅ All services stopped!" -ForegroundColor Green
}

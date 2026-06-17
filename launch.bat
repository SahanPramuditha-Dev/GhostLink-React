@echo off
REM GhostLink Launcher - Batch Script
REM Runs both the FastAPI backend and React frontend

title GhostLink Launcher

echo ========================================
echo          GhostLink Launcher
echo ========================================
echo.

REM Check if we're in the right directory
if not exist "web-radar" (
    echo Error: web-radar folder not found!
    pause
    exit /b 1
)
if not exist "ghostlink\api\server.py" (
    echo Error: ghostlink\api\server.py not found!
    pause
    exit /b 1
)

REM Create a temporary directory for log files
if not exist "logs" mkdir logs

echo [1/2] Starting FastAPI backend...
start "GhostLink Backend" cmd /k "python -m uvicorn ghostlink.api.server:app --reload --host 127.0.0.1 --port 5966"

echo [2/2] Starting React frontend...
cd web-radar
start "GhostLink Frontend" cmd /k "npm run dev"
cd ..

echo.
echo ========================================
echo ✅ Services started successfully!
echo    - Backend API: http://127.0.0.1:5966
echo    - Frontend UI: http://localhost:5173
echo ========================================
echo.
echo Press any key to stop all services...
pause > nul

echo.
echo 🛑 Stopping services...
taskkill /FI "WINDOWTITLE eq GhostLink Backend*" /T /F > nul 2>&1
taskkill /FI "WINDOWTITLE eq GhostLink Frontend*" /T /F > nul 2>&1
echo ✅ All services stopped!
pause

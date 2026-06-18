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
start "GhostLink Backend" cmd /k "
REM Ensure virtualenv exists, create if missing
if not exist .venv (python -m venv .venv) 
echo Activating venv and installing Python deps (if needed)...
.venv\Scripts\python -m pip install --upgrade pip setuptools wheel
if exist requirements.txt (.venv\Scripts\pip install -r requirements.txt) else (echo requirements.txt not found)
echo Starting uvicorn backend on 127.0.0.1:5966...
.venv\Scripts\python -m uvicorn ghostlink.api.server:app --reload --host 127.0.0.1 --port 5966"

echo [2/2] Starting React frontend...
cd web-radar
REM Install node deps if missing
if not exist node_modules (echo Installing frontend dependencies... & npm install)
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

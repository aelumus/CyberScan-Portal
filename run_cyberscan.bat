@echo off
echo ==============================================
echo      CyberScan Portal - Local Startup
echo ==============================================
echo.
echo If you had any frozen terminals, please close them before continuing.
echo.
echo [1/3] Starting Backend (Port 8000)...
start "CyberScan Backend" cmd /k "cd backend && python main.py"

echo [2/3] Starting Worker (Background Tasks)...
start "CyberScan Worker" cmd /k "cd backend && python worker.py"

echo [3/3] Starting Frontend (Port 3000)...
start "CyberScan Frontend" cmd /k "cd portal && npm run dev"

echo.
echo Servers are starting in separate windows!
echo Please wait about 10 seconds for them to load, then open:
echo    http://localhost:3000/
echo.
pause

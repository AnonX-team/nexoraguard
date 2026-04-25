@echo off
title NexoraGuard Server
cd /d "%~dp0backend"
echo.
echo  ============================================
echo   NexoraGuard - AI Security Platform
echo  ============================================
echo.
echo  Starting server on http://localhost:8000
echo  Dashboard: Open dashboard/index.html
echo.
echo  Press Ctrl+C to stop the server
echo.
python -m uvicorn main:app --host 127.0.0.1 --port 9090 --reload
pause

@echo off
title AI Security Suite
cd /d "%~dp0"

echo ============================================
echo   Starting AI Security Suite...
echo ============================================
echo.

echo [1/3] Starting backend (FastAPI, port 8000)
start "AI Security - Backend" cmd /k "cd /d %~dp0backend && uvicorn main:app --reload --port 8000"

echo [2/3] Starting frontend (Vite, port 5173)
start "AI Security - Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo [3/3] Waiting for servers to start...
timeout /t 6 /nobreak >nul

start "" "http://localhost:5173"

echo.
echo Done. If the page does not load, wait a few seconds and refresh.
echo To stop the servers, close the two new console windows (Backend/Frontend).
echo This window can be closed - the servers keep running.
echo.
pause

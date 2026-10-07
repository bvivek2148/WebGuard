@echo off
title WebGuard AI - Full Stack Launcher
echo ======================================================================
echo           🛡️ WebGuard AI - Cyber Defense Platform Launcher 🛡️
echo ======================================================================
echo.
echo 1. Starting Upstream Target Web App (Port 8080)...
start "WebGuard - Target App (8080)" cmd /k "cd /d %~dp0backend && IF EXIST venv\Scripts\python.exe (venv\Scripts\python.exe target_app.py) ELSE (python target_app.py)"

echo 2. Starting FastAPI WAF Reverse Proxy & ML Engine (Port 8000)...
start "WebGuard - FastAPI WAF Proxy (8000)" cmd /k "cd /d %~dp0backend && IF EXIST venv\Scripts\python.exe (venv\Scripts\python.exe main.py) ELSE (python main.py)"

echo 3. Starting React SOC Dashboard Frontend (Port 5173)...
start "WebGuard - React SOC Frontend (5173)" cmd /k "cd /d %~dp0 && npm run dev"

echo.
echo ======================================================================
echo  All services launched in separate windows!
echo  - SOC Frontend Dashboard : http://localhost:5173
echo  - WAF Proxy & Telemetry  : http://localhost:8000
echo  - Interactive API Docs   : http://localhost:8000/docs
echo  - Target Application     : http://localhost:8080
echo ======================================================================
echo.
pause

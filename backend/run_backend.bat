@echo off
title WebGuard AI - FastAPI Backend & WAF Reverse Proxy (Port 8000)
echo ================================================================
echo   WebGuard AI: Starting Python FastAPI Backend & Reverse Proxy
echo   Port: 8000 | WebSocket: ws://127.0.0.1:8000/ws/events
echo ================================================================
cd /d "%~dp0"

IF EXIST "venv\Scripts\python.exe" (
    set "PYTHON_EXE=venv\Scripts\python.exe"
) ELSE (
    set "PYTHON_EXE=python"
)

echo Using Python: %PYTHON_EXE%
"%PYTHON_EXE%" main.py
pause

@echo off
title WebGuard - Target Upstream Application (Port 8080)
echo ================================================================
echo   Starting Target Web Application (Protected by WebGuard)
echo   Port: 8080 | URL: http://127.0.0.1:8080
echo ================================================================
cd /d "%~dp0"

IF EXIST "venv\Scripts\python.exe" (
    set "PYTHON_EXE=venv\Scripts\python.exe"
) ELSE (
    set "PYTHON_EXE=python"
)

echo Using Python: %PYTHON_EXE%
"%PYTHON_EXE%" target_app.py
pause

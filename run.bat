@echo off
title StegoCrypt Pro - Launcher
echo ===================================================
echo             StegoCrypt Pro Launcher
echo   Secure Secret Vault Steganography & Detection
echo ===================================================
echo.

cd /d "%~dp0"

echo [1/2] Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    pause
    exit /b 1
)

echo [2/2] Launching StegoCrypt Pro Dashboard...
python -m streamlit run app.py --server.port 8501 --server.headless false

if errorlevel 1 (
    echo.
    echo [ERROR] Application failed to start.
    pause
    exit /b 1
)

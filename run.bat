@echo off
REM ─────────────────────────────────────────────────────────
REM  StegoCrypt — Run Script (Windows)
REM ─────────────────────────────────────────────────────────

echo.
echo  ███████╗████████╗███████╗ ██████╗  ██████╗
echo  ██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗
echo  ███████╗   ██║   █████╗  ██║  ███╗██║   ██║
echo  ╚════██║   ██║   ██╔══╝  ██║   ██║██║   ██║
echo  ███████║   ██║   ███████╗╚██████╔╝╚██████╔╝
echo  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝
echo         Secure Image Steganography with AES
echo.

REM Check if virtual environment exists
IF EXIST "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
) ELSE (
    echo [INFO] No virtual environment found. Using system Python.
    echo [TIP]  To create one: python -m venv venv
    echo.
)

REM Check Python version
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

REM Install / check dependencies
echo [INFO] Checking dependencies...
pip install -r requirements.txt -q

echo.
echo [INFO] Starting StegoCrypt...
echo [INFO] Open your browser at: http://localhost:8501
echo [INFO] Press Ctrl+C to stop the server.
echo.

streamlit run app.py --server.port 8501 --server.headless false

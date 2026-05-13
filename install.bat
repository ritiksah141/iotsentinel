@echo off
REM IoTSentinel — one-command install for Windows
REM
REM Usage:  Double-click install.bat  (or run from Command Prompt)
REM What it does:
REM   1. Checks Python 3.9+
REM   2. Creates a virtual environment (venv\)
REM   3. Installs Python dependencies
REM   4. Initialises the database (admin/admin — change in the wizard)
REM   5. Opens your browser to http://localhost:8050/setup
REM   6. Starts the dashboard

setlocal EnableDelayedExpansion
title IoTSentinel Installer

echo.
echo  =============================================
echo    IoTSentinel Installer
echo  =============================================
echo.

REM ---------------------------------------------------------------------------
REM 1. Check Python 3.9+
REM ---------------------------------------------------------------------------
echo Checking Python version...

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found.
    echo   Download it from https://www.python.org/downloads/
    echo   Make sure to tick "Add Python to PATH" during installation.
    pause
    exit /b 1
)

REM Verify 3.9+
python -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.9 or higher is required.
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo   Found: %%v
    echo   Download Python 3.11+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [OK] Found %%v
echo.

REM ---------------------------------------------------------------------------
REM 2. Create virtual environment
REM ---------------------------------------------------------------------------
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created
) else (
    echo [OK] Virtual environment already exists
)
echo.

REM ---------------------------------------------------------------------------
REM 3. Install dependencies
REM ---------------------------------------------------------------------------
echo Installing dependencies (this may take a few minutes)...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] Dependency installation failed.
    echo   Try running:  venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)
echo [OK] Dependencies installed
echo.

REM ---------------------------------------------------------------------------
REM 4. Initialise database
REM ---------------------------------------------------------------------------
echo Initialising database...
python config\init_database.py < nul
if errorlevel 1 (
    echo [ERROR] Database initialisation failed.
    pause
    exit /b 1
)
echo [OK] Database ready
echo.

REM ---------------------------------------------------------------------------
REM 5. Open browser after a short delay
REM ---------------------------------------------------------------------------
REM Start a background process that waits 5 seconds then opens the browser
start "" /b cmd /c "timeout /t 5 /nobreak >nul & start http://localhost:8050/setup"

REM ---------------------------------------------------------------------------
REM 6. Start dashboard
REM ---------------------------------------------------------------------------
echo  =============================================
echo   Setup complete!
echo  =============================================
echo.
echo   Your browser will open to:
echo   http://localhost:8050/setup
echo.
echo   Press Ctrl+C to stop the server.
echo.

python dashboard\app.py

pause

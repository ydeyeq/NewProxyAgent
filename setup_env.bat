@echo off
title Proxy Agent Environment Setup
echo 🚀 Starting Proxy Agent setup...

:: Check for Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Python not found! Please install Python 3.9 or higher from https://www.python.org/downloads/
    pause
    exit /b
)

:: Check Python version
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
for /f "tokens=1,2 delims=." %%a in ("%PYVER%") do (
    set MAJOR=%%a
    set MINOR=%%b
)
if %MAJOR% LSS 3 (
    echo ❌ Python 3.9 or higher required! You have %PYVER%.
    pause
    exit /b
)
if %MAJOR%==3 if %MINOR% LSS 9 (
    echo ❌ Python 3.9 or higher required! You have %PYVER%.
    pause
    exit /b
)

:: Create venv if missing
if not exist venv (
    echo 🧱 Creating virtual environment...
    python -m venv venv
) else (
    echo 🔹 Virtual environment already exists.
)

:: Activate venv
call venv\Scripts\activate
if %errorlevel% neq 0 (
    echo ❌ Failed to activate virtual environment.
    pause
    exit /b
)

:: Upgrade pip
echo ⬆️  Upgrading pip...
python -m pip install --upgrade pip

:: Run smart setup script
if exist setup_env.py (
    echo ⚙️ Running smart setup...
    python setup_env.py
) else (
    echo ❌ setup_env.py not found! Falling back to requirements.txt...
    if exist requirements.txt (
        pip install -r requirements.txt
    ) else (
        echo requirements.txt not found!
        pause
        exit /b
    )
)

echo ✅ Setup complete!
echo To run:
echo venv\Scripts\activate && python web_agent.py
pause

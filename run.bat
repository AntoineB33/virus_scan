@echo off
setlocal

echo Checking for uv...
uv --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] uv not found. Installing standalone uv...
    :: Uses PowerShell to install uv directly, bypassing pip entirely
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    
    :: The installer updates the system PATH, but this current CMD session won't see it.
    :: We temporarily append the standard uv install locations to the current session's PATH.
    set "PATH=%USERPROFILE%\.local\bin;%USERPROFILE%\.cargo\bin;%PATH%"
)

:: Verify uv is now accessible
uv --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install uv. Please install it manually from https://docs.astral.sh/uv/
    pause
    exit /b 1
)

echo [INFO] Setting up the environment...
:: Creates the .venv (uv will automatically fetch a managed Python version if the user lacks one)
uv venv >nul 2>&1

echo [INFO] Installing dependencies...
uv pip install -r requirements.txt

echo [INFO] Starting the program...
uv run scan.py
pause
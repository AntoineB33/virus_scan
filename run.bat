@echo off
setlocal

:: Set the program path
set "PROGRAM_PATH=scan.py"

:: Switch to the directory where this batch file is located
cd /d "%~dp0"

echo [INFO] Checking for uv...
uv --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] uv not found. Installing standalone uv...
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    
    :: Temporarily append standard uv install locations to the current session's PATH
    set "PATH=%USERPROFILE%\.local\bin;%USERPROFILE%\.cargo\bin;%PATH%"
)

:: Verify uv is now accessible
uv --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install uv. Please install it manually from https://docs.astral.sh/uv/
    pause
    exit /b 1
)

:: OPTIMIZATION: Only create venv and install dependencies if they don't already exist
if not exist ".venv\" (
    echo [INFO] First run detected. Setting up the environment...
    uv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create the virtual environment.
        pause
        exit /b 1
    )

    echo [INFO] Installing dependencies...
    if exist "requirements.txt" (
        uv pip install -r requirements.txt
        if %errorlevel% neq 0 (
            echo [ERROR] Failed to install dependencies. Check your requirements.txt or network connection.
            pause
            exit /b 1
        )
    ) else (
        echo [WARNING] requirements.txt not found. Skipping dependency installation.
    )
)

echo [INFO] Starting the program...
if not exist "%PROGRAM_PATH%" (
    echo [ERROR] %PROGRAM_PATH% not found in the current directory.
    pause
    exit /b 1
)

:: uv run automatically detects and uses the .venv folder in the current directory
uv run "%PROGRAM_PATH%"
if %errorlevel% neq 0 (
    echo [ERROR] %PROGRAM_PATH% exited with an error.
)

pause
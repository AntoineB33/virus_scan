@echo off
REM Set the Python executable path (adjust if necessary)
set PYTHON_EXECUTABLE=python

REM List of Python script paths (absolute or relative)
REM Add the full paths to your Python files below
setlocal enabledelayedexpansion
set SCRIPT_LIST="C:\Users\abarb\Documents\health\news_underground\games\downloaded\virus_scan\programs\scan.py" "C:\Users\abarb\Documents\health\vue\clock\clock.py"

REM Loop through each script in the list
for %%S in (%SCRIPT_LIST%) do (
    REM Extract the script directory
    set "SCRIPT_DIR=%%~dpS"
    REM Extract the script file name
    set "SCRIPT_NAME=%%~nxS"

    REM Run the Python script in a new CMD window, concurrently
    start "Running %%S" cmd /K "cd /D %%~dpS && %PYTHON_EXECUTABLE% %%~nxS"
)

REM Optional: Add a message indicating all scripts have been started
echo All Python scripts have been started in separate windows.

@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title NetScope - Windows Launcher
color 0B

set "PYTHON_CMD="
where py >nul 2>nul
if not errorlevel 1 (
    py -3 --version >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=py -3"
)
if not defined PYTHON_CMD (
    where python >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=python"
)
if not defined PYTHON_CMD (
    echo ERROR: Python 3 was not found.
    echo Install 64-bit Python 3.10+ from https://www.python.org/downloads/windows/
    echo and enable "Add python.exe to PATH".
    goto :fail
)

echo [1/4] Checking Python...
%PYTHON_CMD% -c "import sys; print('Python', sys.version.split()[0]); raise SystemExit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 (
    echo ERROR: NetScope requires Python 3.10 or newer.
    goto :fail
)

if not exist ".venv\Scripts\python.exe" (
    echo [2/4] Creating virtual environment...
    %PYTHON_CMD% -m venv .venv
    if errorlevel 1 goto :fail
) else (
    echo [2/4] Using existing virtual environment...
)

echo [3/4] Installing Python packages (first run needs internet)...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :fail

echo [4/4] Optional C helper...
where gcc >nul 2>nul
if not errorlevel 1 (
    ".venv\Scripts\python.exe" netscope.py --build-c
    if errorlevel 1 echo WARNING: C helper build skipped. NetScope runs without it.
) else (
    echo GCC not found - skipping optional C helper.
)

where nmap >nul 2>nul
if errorlevel 1 (
    echo.
    echo NOTE: Nmap is not on PATH. NetScope opens, but scans need Nmap: https://nmap.org/download.html
)

echo.
echo Starting NetScope...
".venv\Scripts\python.exe" netscope.py
if errorlevel 1 goto :fail
exit /b 0

:fail
echo.
echo NetScope could not start. See the message above and README.md.
pause
exit /b 1

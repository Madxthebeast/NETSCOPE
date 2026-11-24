@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" netscope.py --check
) else (
    py -3 netscope.py --check
)
pause

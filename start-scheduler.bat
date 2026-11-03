@echo off
rem Start the resident scheduler without a console window.
rem Safe to run twice: the second one finds the port taken and exits by itself.
setlocal
cd /d "%~dp0"

set "PY=%~dp0.venv\Scripts\pythonw.exe"
if not exist "%PY%" (
    echo [ERROR] venv not found: %PY%
    echo Run run.bat once to create it.
    exit /b 2
)
if not exist "%~dp0scheduler.py" (
    echo [ERROR] scheduler.py not found.
    exit /b 2
)

start "" "%PY%" "%~dp0scheduler.py"
exit /b 0

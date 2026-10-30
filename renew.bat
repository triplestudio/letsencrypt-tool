@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem Entry point for Task Scheduler. Arguments are passed through to renew.py:
rem   renew.bat --dry-run
rem   renew.bat --days 20 --force
rem Without arguments: renew when <=15 days left, then deploy to ALB.

set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" (
    echo [ERROR] venv not found. Run run.bat once to install dependencies.
    exit /b 2
)

if not exist "data\logs" mkdir "data\logs"

rem Force UTF-8 so Chinese log lines survive redirection
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

"%PY%" "%~dp0renew.py" %*
set "CODE=%ERRORLEVEL%"

>>"data\logs\renew.log" echo [%date% %time%] exit=%CODE%
exit /b %CODE%

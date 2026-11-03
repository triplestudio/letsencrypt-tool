@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem Show the auto-renew status in plain language, then wait so the
rem window stays open. Safe to run any time - it only reads.

set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" (
    echo [ERROR] venv not found. Run run.bat once to install dependencies.
    pause
    exit /b 2
)

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

"%PY%" "%~dp0scheduler.py" --report %*

if errorlevel 2 (
    echo.
    echo [WARN] 状态读取失败，看看 data\logs\scheduler.log 最后几行。
)

echo.
pause
exit /b 0

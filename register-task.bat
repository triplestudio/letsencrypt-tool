@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem Register the auto-renew scheduled task.
rem Double-click: runs as current user (only when logged on).
rem Run as administrator with /system: runs as SYSTEM (works when logged off).

set "EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%EXE%" (
    echo [ERROR] PowerShell not found.
    pause
    exit /b 2
)

if not exist "%~dp0renew.bat" (
    echo [ERROR] renew.bat not found.
    pause
    exit /b 2
)

set "EXTRA="
if /i "%~1"=="/system" set "EXTRA=-RunAsSystem"

"%EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0register-task.ps1" %EXTRA%
set "CODE=%ERRORLEVEL%"

echo.
pause
exit /b %CODE%

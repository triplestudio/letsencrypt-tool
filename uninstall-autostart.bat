@echo off
rem Stop the scheduler (by its pid file) and remove it from the Startup folder.
setlocal
cd /d "%~dp0"

set "DST=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\cert-renew-scheduler.bat"

if exist "%DST%" (
    del /f /q "%DST%"
    echo Removed startup entry.
) else (
    echo No startup entry found.
)

"%~dp0.venv\Scripts\python.exe" "%~dp0scheduler.py" --stop

echo.
pause
exit /b 0

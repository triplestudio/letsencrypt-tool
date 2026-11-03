@echo off
rem Add the scheduler to the current user's Startup folder, then start it now.
rem Uses a generated .bat with absolute paths, because the copy lives elsewhere.
setlocal
cd /d "%~dp0"

set "PY=%~dp0.venv\Scripts\pythonw.exe"
set "SC=%~dp0scheduler.py"
set "DST=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\cert-renew-scheduler.bat"

if not exist "%PY%" (
    echo [ERROR] venv not found: %PY%
    exit /b 2
)

echo Creating startup entry...
echo   %DST%
(
    echo @echo off
    echo start "" "%PY%" "%SC%"
) > "%DST%"

if not exist "%DST%" (
    echo [ERROR] failed to write the startup entry.
    exit /b 3
)

echo Starting scheduler now...
start "" "%PY%" "%SC%"

echo.
echo Done. The scheduler will start automatically after you log in.
echo   Status  : open the tool page, top card shows it
echo   Stop    : stop-scheduler.bat
echo   Remove  : uninstall-autostart.bat
echo.
pause
exit /b 0

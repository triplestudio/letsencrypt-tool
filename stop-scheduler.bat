@echo off
rem Stop the resident scheduler.
"%~dp0.venv\Scripts\python.exe" "%~dp0scheduler.py" --stop
echo.
pause
exit /b 0

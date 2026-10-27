@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "VENV=%~dp0.venv"
set "PY=%VENV%\Scripts\python.exe"

rem 虚拟环境可能因移动目录/更换用户而失效（pyvenv.cfg 指向不存在的 Python），
rem 仅判断文件是否存在不够，必须实际跑一次导入来验证。
set "NEED_VENV=0"
if not exist "%PY%" set "NEED_VENV=1"
if exist "%PY%" (
    "%PY%" -c "import cryptography, certifi" >nul 2>&1
    if errorlevel 1 set "NEED_VENV=1"
)

if "%NEED_VENV%"=="1" (
    echo [1/2] 正在创建 Python 运行环境...
    python -m venv --clear "%VENV%"
    if errorlevel 1 (
        echo.
        echo 创建失败：请先安装 Python 3.9 或更高版本，并确保 python 命令可用。
        echo 下载地址：https://www.python.org/downloads/
        pause
        exit /b 1
    )
    echo [2/2] 正在安装依赖（cryptography、certifi）...
    "%PY%" -m pip install -q --disable-pip-version-check -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo.
        echo 依赖安装失败：请检查网络后重试，或手动执行：
        echo    "%PY%" -m pip install -r requirements.txt
        pause
        exit /b 1
    )
)

"%PY%" app.py %*
if errorlevel 1 pause

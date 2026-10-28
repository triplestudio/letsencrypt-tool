@echo off
chcp 65001 >nul
setlocal

rem ---------------------------------------------------------------------------
rem 把本机已签发的证书上传并绑定到阿里云 ALB
rem
rem 凭证放在 data\alb.env（该目录已被 .gitignore 排除，不会进仓库），格式：
rem   ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI...
rem   ALIBABA_CLOUD_ACCESS_KEY_SECRET=...
rem
rem 建议先用 --dry-run 试跑：
rem   run-alb-deploy.bat --listener-id lsn-xxxx --region cn-hangzhou --domain example.com --dry-run
rem ---------------------------------------------------------------------------

cd /d "%~dp0.."

set "PY=%~dp0..\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

if "%~1"=="" (
  echo 用法: run-alb-deploy.bat --listener-id lsn-xxxx --region cn-hangzhou --domain example.com
  echo 提示: 加 --dry-run 可先试跑，不调用写接口。
  exit /b 1
)

if exist "data\alb.env" (
  "%PY%" "deploy\alb_deploy.py" --env-file "data\alb.env" %*
) else (
  "%PY%" "deploy\alb_deploy.py" %*
)

set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  if not exist "data" mkdir "data"
  echo [%date% %time%] alb_deploy 失败，退出码 %RC% >> "data\alb-deploy.log"
)
exit /b %RC%

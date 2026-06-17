@echo off
setlocal
cd /d "%~dp0..\frontend"
call npm install
if errorlevel 1 exit /b 1
call npm run build
if errorlevel 1 exit /b 1
echo Frontend built to backend\app\static

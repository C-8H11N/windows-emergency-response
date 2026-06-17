@echo off
setlocal
cd /d "%~dp0.."

echo ========================================
echo   Windows 应急响应工具 - EXE 构建
echo ========================================
echo.

if not exist backend\app\static\index.html (
  echo [INFO] 前端未构建，先构建前端...
  call scripts\build_frontend.bat
  if errorlevel 1 exit /b 1
)

echo [INFO] 检查 Python 依赖...
python -m pip install -r requirements.txt -q
if errorlevel 1 exit /b 1

echo [INFO] 使用 PyInstaller 构建 EXE (使用 win_er.spec)...
pyinstaller --clean win_er.spec
if errorlevel 1 exit /b 1

echo.
echo ========================================
echo   ✓ 构建完成!
echo   输出文件: dist\win_er_tool.exe
echo ========================================


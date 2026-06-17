# Windows 应急响应工具 - PowerShell 构建脚本
# 使用方法: .\scripts\build.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Windows 应急响应工具 - EXE 构建" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $ProjectRoot

# 检查前端是否已构建
if (-not (Test-Path "backend\app\static\index.html")) {
  Write-Host "[INFO] 前端未构建，先构建前端..." -ForegroundColor Yellow
  & "$ScriptDir\build_frontend.bat"
  if ($LASTEXITCODE -ne 0) { exit 1 }
}

Write-Host "[INFO] 检查 Python 依赖..." -ForegroundColor Yellow
python -m pip install -r requirements.txt -q
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[INFO] 使用 PyInstaller 构建 EXE..." -ForegroundColor Yellow
pyinstaller --clean win_er.spec
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  ✓ 构建完成!" -ForegroundColor Green
Write-Host "  输出文件: dist\win_er_tool.exe" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

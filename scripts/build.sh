#!/bin/bash
# Linux/macOS 跨平台构建脚本（仅用于开发测试）

set -e

cd "$(dirname "$0")/.."

echo "========================================"
echo "  Windows ER Tool - Build Script"
echo "========================================"
echo ""

# 检查是否在 WSL/Linux 环境
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "win32" ]]; then
    echo "[WARN] 非 Windows 环境，EXE 可能无法正常运行"
    echo "       建议使用 Windows + Python 原生构建"
    echo ""
fi

echo "[INFO] Building frontend..."
cd frontend
npm ci
npm run build
cd ..

echo "[INFO] Building EXE with PyInstaller..."
pip install -r requirements.txt
pyinstaller --clean win_er.spec

echo ""
echo "========================================"
echo "  ✓ Build complete!"
echo "  Output: dist/win_er_tool.exe"
echo "========================================"

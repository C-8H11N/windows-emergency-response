# 资源文件

## 🖼️ 程序图标

### icon.svg
矢量图标源文件。可以用以下方式转换为 `.ico`：

1. **在线转换**：访问 https://convertio.co/zh/svg-ico/ 上传转换
2. **ImageMagick**：
   ```bash
   magick convert -background none icon.svg -define icon:auto-resize=256,128,64,48,32,16 icon.ico
   ```
3. **GIMP**：手动导出为多尺寸 ICO

### 图标尺寸建议
- 256×256 (大图标)
- 128×128
- 64×64
- 48×48
- 32×32
- 16×16 (小图标)

---

## 📋 版本信息

### version_info.txt
PyInstaller 版本资源文件。使用方式：

```bash
pyinstaller --version-file assets/version_info.txt ...
```

包含：
- 文件版本：0.1.0.0
- 产品版本：0.1.0
- 文件描述：Windows 应急响应助手
- 版权信息

---

## 🎨 其他资源

后续可添加：
- 安装程序横幅
- 启动画面图片
- 各主题预览图

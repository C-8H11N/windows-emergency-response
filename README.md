# Windows 应急响应助手

<div align="center">

  ![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
  ![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
  ![Vue](https://img.shields.io/badge/Vue.js-3-4FC08D?style=for-the-badge&logo=vuedotjs&logoColor=white)
  ![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
  ![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

  <p>面向安全运维人员（尤其是初级工程师）的 Windows 应急响应图形化工具</p>
  <p>双击 EXE 后本地启动 FastAPI 服务并打开浏览器，提供一键扫描、攻击分类引导、风险卡片、网络/进程图表和 HTML 报告导出</p>

</div>

---

## ⚠️ 免责声明

**本工具仅用于授权的安全评估和应急响应。使用前请确保遵守当地法律法规。作者不对因使用本工具造成的任何损失负责。**

> 安全边界：工具默认只做本地采集与启发式分析，不保存历史数据库，不自动删除文件/修改注册表/终止进程，不读取或导出 SAM/LSASS/凭据。威胁情报默认关闭，真实 API 查询必须显式开启。

## ✨ 功能特性

| 模块 | 功能说明 | 技术实现 |
|------|----------|----------|
| 🎯 **攻击分类引导** | Web 入侵、主机入侵、网络攻击、路由/交换机攻击 | 自动勾选对应模块 |
| 📜 **Windows 日志** | Security/System/Application 关键事件分析 | `wevtutil` |
| 👤 **可疑账户** | 本地账户、管理员组、异常 Profile、SAM 权限、WDigest/UAC 风险 | `net user` + 注册表 |
| 📂 **文件痕迹** | Temp、回收站、Recent、hosts 异常绑定、近 7 天可疑文件 | 文件遍历 + 扩展名匹配 |
| 🌐 **网络行为** | 连接可视化、公网 IP 标记、PID 关联 | `netstat -ano` |
| 🔍 **进程分析** | 用户目录进程、伪装系统进程、可疑命令行、多级降级 | WMIC + tasklist + PowerShell |
| 🧩 **补丁核查** | 系统版本、KB 安装日期、补丁滞后风险 | `systeminfo` + `wmic qfe` |
| 🛡️ **网络攻击诊断** | SYN 半连接、CC 连接数、ARP 异常、防火墙状态 | 网络堆栈统计 |
| 🔌 **持久化检测** | Run/RunOnce、启动文件夹、服务、计划任务 | 注册表 + schtasks |
| 📊 **综合报告** | 主机信息、风险评级、证据链、处置建议 | Jinja2 HTML 模板 |

## 🎨 界面主题

支持 **4 种主题** 一键切换：

- 🌙 **深色** - 默认护眼模式
- ☀️ **浅色** - 适合明亮环境
- 🟪 **赛博** - 科技感紫色调
- 🎑 **柔和** - 低对比度舒适模式

## 源码运行

### 后端

```bat
cd /d "D:\win er"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

打开 API 文档：<http://127.0.0.1:8000/docs>

### 前端

```bat
cd /d "D:\win er\frontend"
npm install
npm run dev
```

打开：<http://127.0.0.1:5173>

## 构建前端

```bat
scripts\build_frontend.bat
```

Vite 会输出到 `backend\app\static`，随后 FastAPI 可直接托管前端。

## 打包单 EXE

```bat
scripts\build_exe.bat
```

产物：`dist\win_er_tool.exe`。双击后自动打开：<http://127.0.0.1:8000>

## 管理员权限

建议右键“以管理员身份运行”，否则 Security 日志、部分注册表、服务/计划任务等结果可能不完整。工具会在界面中显示当前权限并对受限模块降级提示。

## 威胁情报配置

默认关闭：不联网、不外发数据。

测试模式：前端设置页选择“测试模式”，使用本地模拟结果，不联网。

真实 API 模式（MVP 中不做批量外发，仅显示显式查询占位）：

```bat
set WIN_ER_ENABLE_EXTERNAL_INTEL=1
set WIN_ER_VT_API_KEY=你的_API_KEY
```

然后在设置页点击“真实 API（显式授权）”。请注意真实模式可能向第三方发送你选择查询的 IP/域名/哈希，默认不会上传报告、日志、用户名或文件。

## 非 Windows 开发

非 Windows 环境下后端可启动，扫描模块会返回 unsupported。设置 `WIN_ER_MOCK=1` 可生成部分示例数据用于前端调试。

```bat
set WIN_ER_MOCK=1
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

## 🖼️ 界面特性

| 功能 | 说明 | 预览 |
|------|------|------|
| 📊 **仪表盘** | 主机信息、风险统计、发现项分布图表 | 风险卡片 + ECharts 饼图/柱状图 |
| 🚀 **一键扫描** | 模块勾选、进度条、实时结果展示 | 雷达动画 + 扫描进度 + 模块状态 |
| 🔥 **发现项详情** | 按严重程度分类、证据展示、一键处置 | 可折叠卡片 + 处置按钮 + 证据代码块 |
| 📋 **HTML 报告** | 完整导出、打印友好、包含所有证据 | 单文件 HTML + 风险汇总表 |

💡 **主题切换**：支持 4 种内置主题
- 🌙 深色主题（默认）
- ☀️ 浅色主题
- 🟪 赛博朋克
- 🎑 柔和护眼

> 欢迎提交你的界面截图到 PR！

## ❓ 常见问题

- **端口占用**：设置 `WIN_ER_PORT=8001` 后重新启动。
- **日志读取失败**：请以管理员运行，或检查事件日志服务状态。
- **WMIC 不可用**：较新系统可能弱化 WMIC，已内置 tasklist + PowerShell 多级降级。
- **扫描慢**：文件扫描和服务/计划任务查询设置了数量与超时限制，结果以证据优先，可能存在误报，需要人工复核。
- **SmartScreen 拦截**：开源工具默认无代码签名，请右键 → 属性 → 解除锁定。

## 🤝 贡献指南

欢迎任何形式的贡献！

1. **Fork** 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 **Pull Request**

### 开发环境

```bash
# 后端
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 前端
cd frontend
npm install
npm run dev
```

## 📝 更新日志

见 [CHANGELOG.md](CHANGELOG.md)

## 🗺️ Roadmap

- [ ] YARA 规则扫描
- [ ] 扫描配置保存/加载
- [ ] JSON/CSV/Markdown 多格式导出
- [ ] 多语言 i18n 支持
- [ ] 远程 Agent 批量扫描
- [ ] 基线对比功能
- [ ] 内存痕迹分析

---

## 💰 支持本项目

如果这个工具对你有帮助，欢迎通过以下方式支持：

| 方式 | 说明 |
|------|------|
| ⭐️ **Star 本仓库** | 免费的支持，让更多人看到 |
| 🐛 **提交 Issue/PR** | 报告 Bug 或贡献代码 |
| ❤️ **赞助支持** | 见仓库 Sponsor 按钮 |

你的支持是我持续改进的动力！💪

---

<div align="center">

**如果觉得有用，请给个 ⭐️ Star 支持一下！**

Made with ❤️ for the security community

</div>

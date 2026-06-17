# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-16

### Added
- 🎉 Initial public release
- 🎯 攻击分类引导模块（Web 入侵、主机入侵、网络攻击、路由/交换机攻击）
- 📜 Windows 事件日志分析模块（Security/System/Application）
- 👤 可疑账户与管理员组检测
- 📂 文件痕迹扫描（Temp/回收站/Recent/hosts）
- 🌐 网络连接可视化与公网 IP 标记
- 🔍 进程深度分析与可疑命令行检测
- 🧩 系统补丁与漏洞风险评估
- 🛡️ 网络攻击诊断（SYN/CC/ARP/防火墙）
- 🔌 启动项与持久化检测
- 📊 HTML 综合报告导出
- 🎨 4 种主题切换（深色/浅色/赛博/柔和）
- 📁 可疑文件一键定位功能
- ⚙️ 威胁情报支持（测试模式 + VirusTotal API 接口）

### Fixed
- 修复 WinError 2 "系统找不到指定的文件" 进程枚举失败问题
- 修复饼图标签文字重叠问题
- 修复浅色主题下权限提示文字看不清问题
- 修复 PyInstaller 打包导入错误

### Security
- 默认纯本地分析，不联网、不上传数据
- 威胁情报默认关闭，需显式授权开启
- 关键系统进程保护，防止误终止
- 不读取 SAM/LSASS 等敏感凭据数据

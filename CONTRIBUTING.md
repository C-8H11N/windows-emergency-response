# 贡献指南

感谢你对 Windows 应急响应助手的关注！欢迎任何形式的贡献。

## 📋 目录

- [代码贡献](#代码贡献)
- [Bug 报告](#bug-报告)
- [功能建议](#功能建议)
- [开发指南](#开发指南)
- [代码规范](#代码规范)

---

## 🐛 Bug 报告

提交 Issue 前请检查：

1. 是否已在 [Issues](https://github.com/yourusername/win-er/issues) 中搜索过相同问题
2. 是否使用最新版本代码
3. 提供以下信息：
   - Windows 版本（Win10/11，内部版本号）
   - 是否以管理员运行
   - 错误信息或截图
   - 复现步骤

Bug Issue 模板：
```
**环境信息**
- Windows 版本：
- 工具版本：
- 是否管理员：

**问题描述**

**复现步骤**
1. 
2. 
3. 

**预期行为**

**截图/日志**
```

---

## 💡 功能建议

欢迎提交新功能建议！请说明：

1. 功能适用场景
2. 技术实现思路（可选）
3. 是否愿意提交 PR 实现

---

## 👨‍💻 代码贡献

### 开发流程

1. **Fork** 本仓库
2. 克隆到本地：
   ```bash
   git clone https://github.com/yourusername/win-er.git
   cd win-er
   ```
3. 创建特性分支：
   ```bash
   git checkout -b feature/your-feature-name
   # 或 bug 修复: git checkout -b fix/issue-number
   ```
4. 编码并测试
5. 提交 Commit：
   ```bash
   git add .
   git commit -m "feat: add some feature"
   # 或 fix: fix some bug
   # 或 docs: update documentation
   ```
6. 推送到你的 Fork
   ```bash
   git push origin feature/your-feature-name
   ```
7. 开启 **Pull Request**

### PR 要求

- 代码通过语法检查（Python: `pyflakes`，TS: `npm run typecheck`）
- 更新相关文档（README, CHANGELOG 等）
- 一个 PR 只做一件事，拆分大功能为多个小 PR
- PR 标题清晰，关联相关 Issue

### Commit 规范

遵循 [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: 新增功能
fix: 修复 Bug
docs: 文档更新
style: 代码格式、UI 样式
refactor: 重构
perf: 性能优化
test: 测试相关
build: 构建脚本、依赖、版本号
chore: 其他杂项
```

---

## 🔧 开发指南

### 环境搭建

**后端：**
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn backend.app.main:app --reload
```

**前端：**
```bash
cd frontend
npm install
npm run dev
```

### 添加新扫描模块

参考 `backend/app/modules/` 下的现有模块：

1. 创建 `your_module.py`
2. 实现 `run()` 函数返回 `ModuleResult`
3. 在 `scanner.py` 中注册模块
4. 在前端 `App.vue` 的 `moduleChoices` 中添加选项

### 测试

```bash
# 后端单元测试（待完善）
python -m pytest tests/

# 前端类型检查
cd frontend
npx vue-tsc --noEmit
```

### 构建验证

```bash
# 构建前端
npm run build --prefix frontend

# 构建 EXE
pyinstaller --clean --onefile --name win_er_tool ^
  --add-data "backend\app\static;backend\app\static" ^
  --add-data "backend\app\templates;backend\app\templates" ^
  backend/launcher.py
```

---

## 📝 代码规范

### Python

- 遵循 [PEP 8](https://peps.python.org/pep-0008/)
- 使用类型注解
- 函数和类添加 docstring

### TypeScript/Vue

- 使用 Composition API
- Props 添加类型注解
- 响应式变量命名清晰

### 安全

- 不硬编码密钥或凭证
- 不自动执行破坏性操作（删除文件、终止进程）
- 不向外发送敏感数据（默认本地分析）
- 新增网络请求需在 README 中说明

---

## ❓ 问题

有任何问题可以：
- 开启 [Discussion](https://github.com/yourusername/win-er/discussions)
- 提交 Issue
- 直接在 PR 中评论

再次感谢你的贡献！ 🙏

"""基础测试"""
import sys
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_imports():
    """测试关键模块可导入"""
    from backend.app.config import APP_NAME, APP_VERSION
    assert APP_NAME == "Windows 应急响应助手"
    assert APP_VERSION


def test_threat_intel_default():
    """测试威胁情报默认关闭"""
    from backend.app.config import threat_intel_config
    cfg = threat_intel_config()
    assert cfg.enabled is False
    assert cfg.mode == "off"


def test_subprocess_wrapper():
    """测试命令执行包装器"""
    from backend.app.utils.subprocesses import run_command, CommandResult
    result = run_command(["echo", "test"], timeout=5)
    assert isinstance(result, CommandResult)
    assert result.returncode == 0


if __name__ == "__main__":
    test_imports()
    test_threat_intel_default()
    test_subprocess_wrapper()
    print("All tests passed! ✓")

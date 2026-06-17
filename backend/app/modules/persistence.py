from __future__ import annotations

import os
import re
import time
from pathlib import Path

from backend.app.models import Finding, ModuleResult, Severity
from backend.app.utils.platform import is_user_writable_path, is_windows, mock_enabled
from backend.app.utils.subprocesses import run_command

MODULE = "persistence"
DISPLAY = "启动项与持久化后门检查"
RUN_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
]
SCRIPT_MARKERS = ["powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32"]


def _entry_risk(line: str) -> bool:
    low = line.lower()
    return is_user_writable_path(low) or any(m in low for m in SCRIPT_MARKERS) or "-enc" in low or "downloadstring" in low


def run() -> ModuleResult:
    start = time.perf_counter(); result = ModuleResult(module=MODULE, display_name=DISPLAY, status="done")
    if not is_windows():
        if mock_enabled():
            result.findings.append(Finding(id=f"{MODULE}-run", module=MODULE, title="启动项指向 AppData（示例）", severity=Severity.high, summary="可疑持久化。", evidence=[r"HKCU Run demo C:\Users\demo\AppData\Roaming\demo.exe"], recommendation="核查文件和创建时间，必要时隔离。")); return result
        result.status = "unsupported"; result.summary = "非 Windows 环境不支持启动项检查。"; return result
    suspicious = []
    all_entries = []
    for key in RUN_KEYS:
        q = run_command(["reg", "query", key], timeout=10)
        if q.ok:
            for line in q.stdout.splitlines():
                if "REG_" in line:
                    entry = f"{key}: {line.strip()}"
                    all_entries.append(entry)
                    if _entry_risk(entry):
                        suspicious.append(entry)
    if suspicious:
        result.findings.append(Finding(id=f"{MODULE}-run", module=MODULE, title="发现可疑注册表启动项", severity=Severity.high, summary="Run/RunOnce 中存在用户可写路径或脚本解释器。", evidence=suspicious[:80], recommendation="确认启动项来源、签名与业务必要性；处置前先导出证据。", tags=["persistence", "registry"], confidence=0.8))
    startup_hits = []
    folders = [Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp"]
    users = Path(r"C:\Users")
    if users.exists():
        for user in users.iterdir():
            folders.append(user / r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
    for folder in folders:
        if folder.exists():
            for p in folder.iterdir():
                startup_hits.append(str(p))
    if startup_hits:
        result.findings.append(Finding(id=f"{MODULE}-folder", module=MODULE, title="启动文件夹存在项目", severity=Severity.medium, summary="启动文件夹内容需要核查。", evidence=startup_hits[:80], recommendation="确认每个快捷方式/脚本/可执行文件是否为业务需要。", tags=["persistence", "startup-folder"], confidence=0.65))
    svc = run_command(["wmic", "service", "get", "Name,DisplayName,State,StartMode,PathName", "/format:csv"], timeout=30, max_output=4_000_000)
    svc_susp = []
    if svc.ok:
        for line in svc.stdout.splitlines():
            low = line.lower()
            if ",auto," in low or ",automatic," in low or "auto" in low:
                if _entry_risk(line):
                    svc_susp.append(line[:800])
    if svc_susp:
        result.findings.append(Finding(id=f"{MODULE}-service", module=MODULE, title="自动启动服务路径可疑", severity=Severity.high, summary="自动服务指向用户可写路径或脚本解释器。", evidence=svc_susp[:80], recommendation="核查服务创建事件 7045、服务二进制签名和父进程来源。", tags=["persistence", "service"], confidence=0.8))
    tasks = run_command(["schtasks", "/query", "/fo", "csv", "/v"], timeout=35, max_output=4_000_000)
    task_susp = []
    if tasks.ok:
        for line in tasks.stdout.splitlines():
            if _entry_risk(line):
                task_susp.append(line[:800])
    if task_susp:
        result.findings.append(Finding(id=f"{MODULE}-task", module=MODULE, title="计划任务存在可疑动作", severity=Severity.high, summary="计划任务包含用户目录/脚本/编码执行特征。", evidence=task_susp[:80], recommendation="核查任务作者、触发器、创建时间和动作命令。", tags=["persistence", "scheduled-task"], confidence=0.8))
    result.data["run_entries"] = all_entries[:500]
    result.summary = f"持久化检查完成，发现 {len(result.findings)} 类线索。"; result.duration_ms = int((time.perf_counter()-start)*1000)
    return result

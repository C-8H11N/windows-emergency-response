from __future__ import annotations

import csv
import re
import time
from io import StringIO

from backend.app.models import Finding, ModuleResult, Severity
from backend.app.utils.platform import is_user_writable_path, is_windows, mock_enabled
from backend.app.utils.subprocesses import run_command

MODULE = "processes"
DISPLAY = "可疑进程深度分析"
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe", "smss.exe"}
CMD_PATTERNS = ["-encodedcommand", " frombase64string", "downloadstring", " iex", "certutil", "bitsadmin", "mshta http", "regsvr32", "rundll32 javascript"]


def _parse_wmic(text: str) -> list[dict[str, str]]:
    clean = "\n".join(line for line in text.splitlines() if line.strip())
    rows = []
    for row in csv.DictReader(StringIO(clean)):
        rows.append({k.strip(): (v or "").strip() for k, v in row.items() if k})
    return rows


def _fallback_tasklist_v() -> list[dict[str, str]]:
    out = run_command(["tasklist", "/v", "/fo", "csv"], timeout=30, max_output=4_000_000)
    if not out.ok:
        return []
    rows = []
    for row in csv.DictReader(StringIO(out.stdout)):
        pid = row.get("PID") or row.get("PID ") or ""
        name = row.get("Image Name") or row.get("映像名称") or ""
        cmd = row.get("Command Line") or row.get("命令行") or ""
        rows.append({"ProcessId": pid, "Name": name, "CommandLine": cmd, "ExecutablePath": ""})
    return rows


def _fallback_tasklist_simple() -> list[dict[str, str]]:
    out = run_command(["tasklist", "/fo", "csv"], timeout=30, max_output=4_000_000)
    if not out.ok:
        return []
    rows = []
    for row in csv.DictReader(StringIO(out.stdout)):
        pid = row.get("PID") or row.get("PID ") or ""
        name = row.get("Image Name") or row.get("映像名称") or ""
        rows.append({"ProcessId": pid, "Name": name, "CommandLine": "", "ExecutablePath": ""})
    return rows


def _fallback_powershell() -> list[dict[str, str]]:
    ps_cmd = "Get-Process | Select-Object Id,Name,Path,CommandLine | ConvertTo-Csv -NoTypeInformation"
    out = run_command(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=30, max_output=4_000_000)
    if not out.ok:
        return []
    rows = []
    for row in csv.DictReader(StringIO(out.stdout)):
        pid = row.get("Id") or row.get("ID") or ""
        name = row.get("Name") or ""
        path = row.get("Path") or ""
        cmd = row.get("CommandLine") or ""
        rows.append({"ProcessId": pid, "Name": name, "CommandLine": cmd, "ExecutablePath": path})
    return rows


def run() -> ModuleResult:
    start = time.perf_counter(); result = ModuleResult(module=MODULE, display_name=DISPLAY, status="done")
    if not is_windows():
        if mock_enabled():
            result.findings.append(Finding(id=f"{MODULE}-appdata", module=MODULE, title="AppData 下运行可执行文件（示例）", severity=Severity.high, summary="用户目录下进程具备持久化/木马风险。", evidence=[r"demo.exe PID 1234 C:\Users\demo\AppData\Roaming\demo.exe"], recommendation="核查签名、哈希、启动项与网络连接。")); return result
        result.status = "unsupported"; result.summary = "非 Windows 环境不支持 Windows 进程分析。"; return result
    out = run_command(["wmic", "process", "get", "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine", "/format:csv"], timeout=30, max_output=4_000_000)
    if out.ok:
        rows = _parse_wmic(out.stdout)
    else:
        rows = _fallback_tasklist_v()
        if rows:
            result.errors.append("WMIC 不可用，降级使用 tasklist /v；部分路径和父进程信息可能缺失。")
        else:
            rows = _fallback_tasklist_simple()
            if rows:
                result.errors.append("WMIC 和 tasklist /v 不可用，降级使用 tasklist；命令行和路径信息缺失。")
            else:
                rows = _fallback_powershell()
                if rows:
                    result.errors.append("WMIC 和 tasklist 不可用，降级使用 PowerShell Get-Process。")
                else:
                    result.status = "error"; result.errors.append("进程枚举失败：WMIC、tasklist 和 PowerShell 均不可用"); return result
    suspicious_paths, masquerade, suspicious_cmd = [], [], []
    for row in rows:
        name = (row.get("Name") or "").lower()
        path = row.get("ExecutablePath") or ""
        cmd = (row.get("CommandLine") or "").lower()
        pid = row.get("ProcessId") or ""
        if path and is_user_writable_path(path):
            suspicious_paths.append(f"{name} PID {pid} Path={path}")
        if name in SYSTEM_NAMES and path and "\\windows\\system32\\" not in path.lower() and "\\windows\\syswow64\\" not in path.lower():
            masquerade.append(f"{name} PID {pid} Path={path}")
        if any(p in cmd for p in CMD_PATTERNS):
            suspicious_cmd.append(f"{name} PID {pid} CMD={(row.get('CommandLine') or '')[:500]}")
    if suspicious_paths:
        result.findings.append(Finding(id=f"{MODULE}-writable", module=MODULE, title="用户可写目录中存在运行进程", severity=Severity.high, summary=f"发现 {len(suspicious_paths)} 个用户可写路径进程。", evidence=suspicious_paths[:80], recommendation="优先核查父进程、启动项、签名和网络连接；必要时隔离样本。", tags=["process", "path"], confidence=0.8))
    if masquerade:
        result.findings.append(Finding(id=f"{MODULE}-masquerade", module=MODULE, title="疑似系统进程名称伪装", severity=Severity.critical, summary="系统关键进程名出现在非系统目录。", evidence=masquerade[:40], recommendation="立即保全证据并隔离分析，确认是否为伪装木马。", tags=["process", "masquerade"], confidence=0.9))
    if suspicious_cmd:
        result.findings.append(Finding(id=f"{MODULE}-cmd", module=MODULE, title="发现可疑命令行特征", severity=Severity.high, summary="进程命令行包含下载、编码执行或 LOLBin 特征。", evidence=suspicious_cmd[:60], recommendation="核查命令来源、父进程、执行时间和落地文件。", tags=["process", "commandline"], confidence=0.85))
    result.data["processes"] = rows[:1500]
    result.summary = f"分析进程 {len(rows)} 个，发现 {len(result.findings)} 类线索。"; result.duration_ms = int((time.perf_counter()-start)*1000)
    return result

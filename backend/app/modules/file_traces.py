from __future__ import annotations

import os
import time
from datetime import datetime, timedelta
from pathlib import Path

from backend.app.models import Finding, ModuleResult, Severity
from backend.app.utils.platform import is_windows, mock_enabled

MODULE = "file_traces"
DISPLAY = "文件痕迹与 hosts 分析"
SUSP_EXT = {".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd", ".js", ".hta", ".scr", ".lnk"}


def _finding(id_: str, title: str, sev: Severity, evidence: list[str], rec: str) -> Finding:
    return Finding(id=f"{MODULE}-{id_}", module=MODULE, title=title, severity=sev, summary=title, evidence=evidence[:50], recommendation=rec, tags=["file"], confidence=0.65)


def _scan_dir(root: Path, since: float, limit: int = 600) -> list[str]:
    hits: list[str] = []
    if not root.exists():
        return hits
    for base, dirs, files in os.walk(root):
        dirs[:] = dirs[:20]
        for name in files:
            if len(hits) >= limit:
                return hits
            p = Path(base) / name
            if p.suffix.lower() not in SUSP_EXT:
                continue
            try:
                if p.stat().st_mtime >= since:
                    hits.append(f"{p} | 修改时间 {datetime.fromtimestamp(p.stat().st_mtime):%Y-%m-%d %H:%M:%S}")
            except OSError:
                continue
    return hits


def run() -> ModuleResult:
    start = time.perf_counter(); result = ModuleResult(module=MODULE, display_name=DISPLAY, status="done")
    if not is_windows():
        if mock_enabled():
            result.findings.append(_finding("temp", "临时目录发现近期脚本文件（示例）", Severity.medium, [r"C:\Users\demo\AppData\Local\Temp\a.ps1"], "确认来源并保全样本。")); return result
        result.status = "unsupported"; result.summary = "非 Windows 环境不支持默认 Windows 路径扫描。"; return result
    since = (datetime.now() - timedelta(days=7)).timestamp()
    roots = [Path(r"C:\Windows\Temp"), Path(r"C:\$Recycle.Bin")]
    users = Path(r"C:\Users")
    if users.exists():
        for user in users.iterdir():
            roots.extend([user / "AppData" / "Local" / "Temp", user / "Recent"])
    hits: list[str] = []
    for root in roots:
        hits.extend(_scan_dir(root, since, limit=150))
        if len(hits) >= 600:
            break
    if hits:
        result.findings.append(_finding("recent", "用户可写目录发现近 7 天可执行/脚本类文件", Severity.medium, hits, "核查文件来源、签名、哈希和父进程；必要时隔离分析。"))
    hosts = Path(r"C:\Windows\System32\drivers\etc\hosts")
    if hosts.exists():
        suspicious = []
        try:
            for line in hosts.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) >= 2 and not parts[0].startswith("127.") and parts[0] != "::1":
                    suspicious.append(stripped)
        except OSError as exc:
            result.errors.append(f"hosts 读取失败: {exc}")
        if suspicious:
            result.findings.append(_finding("hosts", "hosts 文件存在非 localhost 绑定", Severity.high, suspicious, "确认是否为业务配置；异常绑定可能用于钓鱼、劫持或阻断安全更新。"))
    result.data["scanned_roots"] = [str(p) for p in roots]
    result.summary = f"文件痕迹扫描完成，近期可疑文件 {len(hits)} 个。"; result.duration_ms = int((time.perf_counter()-start)*1000)
    return result

from __future__ import annotations

import re
import time
from datetime import datetime

from backend.app.models import Finding, ModuleResult, Severity
from backend.app.utils.platform import is_windows, mock_enabled
from backend.app.utils.subprocesses import run_command

MODULE = "patches"
DISPLAY = "系统漏洞与补丁核查"
DATE_RE = re.compile(r"(\d{1,2})/(\d{1,2})/(\d{4})|(\d{4})-(\d{1,2})-(\d{1,2})")


def _dates(text: str) -> list[datetime]:
    dates = []
    for m in DATE_RE.finditer(text):
        try:
            if m.group(1):
                dates.append(datetime(int(m.group(3)), int(m.group(1)), int(m.group(2))))
            else:
                dates.append(datetime(int(m.group(4)), int(m.group(5)), int(m.group(6))))
        except ValueError:
            pass
    return dates


def run() -> ModuleResult:
    start = time.perf_counter(); result = ModuleResult(module=MODULE, display_name=DISPLAY, status="done")
    if not is_windows():
        if mock_enabled():
            result.findings.append(Finding(id=f"{MODULE}-old", module=MODULE, title="超过 90 天未发现补丁（示例）", severity=Severity.medium, summary="补丁滞后。", evidence=["LastHotFix=2024-01-01"], recommendation="尽快评估并安装近三个月安全更新。")); return result
        result.status = "unsupported"; result.summary = "非 Windows 环境不支持 systeminfo/HotFix 核查。"; return result
    sysinfo = run_command(["systeminfo"], timeout=35, max_output=2_000_000)
    qfe = run_command(["wmic", "qfe", "get", "HotFixID,InstalledOn,Description", "/format:csv"], timeout=25)
    text = (sysinfo.stdout if sysinfo.ok else "") + "\n" + (qfe.stdout if qfe.ok else "")
    if not text.strip():
        result.status = "error"; result.errors.append(sysinfo.stderr or qfe.stderr or "补丁命令执行失败"); return result
    dates = _dates(text)
    result.data["systeminfo_tail"] = sysinfo.stdout[-8000:]
    result.data["hotfixes"] = qfe.stdout[-12000:]
    if dates:
        latest = max(dates)
        days = (datetime.now() - latest).days
        sev = Severity.info
        if days > 180: sev = Severity.high
        elif days > 90: sev = Severity.medium
        elif days > 45: sev = Severity.low
        if sev != Severity.info:
            result.findings.append(Finding(id=f"{MODULE}-stale", module=MODULE, title=f"最近补丁距今 {days} 天", severity=sev, summary="系统安全更新可能滞后。", evidence=[f"最近解析到的补丁日期: {latest:%Y-%m-%d}", f"距今: {days} 天"], recommendation="结合 WSUS/Windows Update 策略安装近三个月安全更新，并优先处理高危漏洞公告。", tags=["patch"], confidence=0.75))
    else:
        result.findings.append(Finding(id=f"{MODULE}-parse", module=MODULE, title="未能解析补丁安装日期", severity=Severity.info, summary="无法判断补丁新旧。", evidence=["systeminfo/wmic qfe 输出未匹配日期"], recommendation="请人工检查 Windows Update 或企业补丁平台。", tags=["patch"], confidence=0.4))
    result.summary = f"补丁核查完成，发现 {len(result.findings)} 项线索。"; result.duration_ms = int((time.perf_counter()-start)*1000)
    return result

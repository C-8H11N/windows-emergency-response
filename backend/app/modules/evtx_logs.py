from __future__ import annotations

import re
import time
from collections import Counter

from backend.app.models import Finding, ModuleResult, Severity
from backend.app.utils.platform import is_windows, mock_enabled
from backend.app.utils.subprocesses import run_command

MODULE = "evtx_logs"
DISPLAY = "Windows 日志快速分析"
EVENT_RE = re.compile(r"Event\s+ID:\s*(\d+)|事件\s*ID:\s*(\d+)", re.I)
KEY_EVENTS = {"4625", "4688", "1102", "4720", "4728", "4732", "7045", "6008", "4672", "4648"}


def _finding(event_id: str, count: int, log: str) -> Finding:
    severity = Severity.info
    title = f"事件 {event_id} 出现 {count} 次"
    rec = "请结合时间线、账号、源 IP 与业务变更确认。"
    if event_id == "4625" and count >= 10:
        severity, title = Severity.high, "发现大量登录失败事件，疑似爆破"
    elif event_id == "1102":
        severity, title = Severity.high, "安全审计日志被清除"
    elif event_id in {"4720", "4728", "4732"}:
        severity, title = Severity.high, "发现账户或特权组变更事件"
    elif event_id == "7045":
        severity, title = Severity.medium, "发现新服务安装事件"
    elif event_id == "6008":
        severity, title = Severity.medium, "发现异常关机事件"
    elif event_id in {"4648", "4672"}:
        severity = Severity.low
    return Finding(
        id=f"{MODULE}-{log}-{event_id}", module=MODULE, title=title, severity=severity,
        summary=f"{log} 日志中匹配事件 ID {event_id} 共 {count} 次。",
        evidence=[f"日志: {log}", f"事件 ID: {event_id}", f"最近记录匹配次数: {count}"],
        recommendation=rec, tags=["eventlog", event_id], confidence=0.75,
    )


def run() -> ModuleResult:
    start = time.perf_counter()
    result = ModuleResult(module=MODULE, display_name=DISPLAY, status="done")
    if not is_windows():
        if mock_enabled():
            result.findings = [_finding("4625", 16, "Security"), _finding("7045", 1, "System")]
            result.summary = "Mock 模式：生成示例日志风险。"
            return result
        result.status = "unsupported"; result.summary = "非 Windows 环境不支持读取 EVTX。"; return result
    rows: list[dict[str, str]] = []
    for log, count in [("Security", "1000"), ("System", "300"), ("Application", "300")]:
        cmd = ["wevtutil", "qe", log, "/rd:true", f"/c:{count}", "/f:text"]
        out = run_command(cmd, timeout=30)
        if not out.ok:
            result.errors.append(f"{log}: {out.stderr or out.stdout or '读取失败'}")
            continue
        ids = []
        for match in EVENT_RE.finditer(out.stdout):
            event_id = match.group(1) or match.group(2)
            ids.append(event_id)
            if len(rows) < 1000 and event_id in KEY_EVENTS:
                rows.append({"log": log, "event_id": event_id})
        for event_id, num in Counter(ids).items():
            if event_id in KEY_EVENTS:
                result.findings.append(_finding(event_id, num, log))
    result.data["recent_events"] = rows[:1000]
    result.summary = f"发现 {len(result.findings)} 类关键日志线索。"
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    if result.errors:
        result.findings.append(Finding(
            id=f"{MODULE}-permission", module=MODULE, title="部分事件日志读取受限", severity=Severity.info,
            summary="部分日志读取失败，结果可能不完整。", evidence=result.errors[:5],
            recommendation="建议右键以管理员身份运行后复查 Security/System 日志。", requires_admin=True,
            tags=["eventlog", "permission"], confidence=0.7,
        ))
    return result

from __future__ import annotations

import time

from backend.app.models import Finding, ModuleResult, Severity
from backend.app.utils.platform import is_admin, is_windows, mock_enabled
from backend.app.utils.subprocesses import run_command

MODULE = "accounts_registry"
DISPLAY = "可疑账户与注册表排查"


def _f(id_: str, title: str, sev: Severity, evidence: list[str], rec: str, admin: bool = False) -> Finding:
    return Finding(id=f"{MODULE}-{id_}", module=MODULE, title=title, severity=sev, summary=title, evidence=evidence, recommendation=rec, requires_admin=admin, tags=["account", "registry"], confidence=0.7)


def run() -> ModuleResult:
    start = time.perf_counter(); result = ModuleResult(module=MODULE, display_name=DISPLAY, status="done")
    if not is_windows():
        if mock_enabled():
            result.findings.append(_f("guest", "Guest 账户处于启用状态（示例）", Severity.medium, ["Mock account: Guest Enabled"], "建议禁用 Guest 并核查本地管理员组。"))
            return result
        result.status = "unsupported"; result.summary = "非 Windows 环境不支持本地账户排查。"; return result
    users = run_command(["net", "user"], timeout=15)
    admins = run_command(["net", "localgroup", "administrators"], timeout=15)
    result.data["net_user"] = users.stdout[-12000:]
    result.data["administrators"] = admins.stdout[-12000:]
    if not users.ok: result.errors.append(users.stderr or "net user 执行失败")
    if admins.ok:
        lines = [l.strip() for l in admins.stdout.splitlines() if l.strip() and "---" not in l and "命令成功" not in l and "command completed" not in l.lower()]
        result.data["admin_members"] = lines[-20:]
        if len(lines) > 6:
            result.findings.append(_f("admins", "管理员组成员较多，请核查是否存在异常账号", Severity.medium, lines[-20:], "确认每个管理员组成员的业务必要性，移除未知账号。"))
    sam = run_command(["reg", "query", r"HKLM\SAM\SAM"], timeout=10)
    if sam.ok:
        result.findings.append(_f("sam-readable", "当前权限可访问 SAM 注册表区域", Severity.medium, ["reg query HKLM\\SAM\\SAM 成功"], "不要导出 SAM；建议确认工具以最小权限运行并保护凭据安全。", True))
    else:
        result.data["sam_status"] = "SAM 受系统保护，未读取敏感内容。"
    profile = run_command(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", "/s"], timeout=20)
    if profile.ok:
        suspicious = [l.strip() for l in profile.stdout.splitlines() if "ProfileImagePath" in l and ("\\Temp" in l or "\\Public" in l)]
        if suspicious:
            result.findings.append(_f("profile", "发现 ProfileList 指向异常目录", Severity.high, suspicious[:20], "核查对应 SID 与本地账号，确认是否为隐藏/后门账户。", True))
    else:
        result.errors.append("ProfileList 查询失败，建议管理员运行。")
    for key, name in [(r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "WDigest"), (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "UAC/远程 UAC")]:
        q = run_command(["reg", "query", key], timeout=10)
        if q.ok and ("UseLogonCredential    REG_DWORD    0x1" in q.stdout or "LocalAccountTokenFilterPolicy    REG_DWORD    0x1" in q.stdout):
            result.findings.append(_f(name.lower(), f"{name} 存在高风险配置", Severity.high, [q.stdout[-1000:]], "建议按基线关闭该配置，并核查是否为攻击者修改。", True))
    if not is_admin():
        result.findings.append(_f("admin", "当前不是管理员权限，账户/注册表结果可能不完整", Severity.info, ["IsUserAnAdmin=False"], "建议右键以管理员身份运行后复查。", True))
    result.summary = f"账户与注册表检查完成，发现 {len(result.findings)} 项线索。"; result.duration_ms = int((time.perf_counter()-start)*1000)
    return result

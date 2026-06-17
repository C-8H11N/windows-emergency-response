from __future__ import annotations

import re
import time
from collections import Counter

from backend.app.models import Finding, ModuleResult, Severity
from backend.app.utils.platform import is_windows, mock_enabled
from backend.app.utils.subprocesses import run_command

MODULE = "network_diagnostics"
DISPLAY = "网络攻击专项检测"


def run() -> ModuleResult:
    start = time.perf_counter(); result = ModuleResult(module=MODULE, display_name=DISPLAY, status="done")
    if not is_windows():
        if mock_enabled():
            result.findings.append(Finding(id=f"{MODULE}-syn", module=MODULE, title="疑似 SYN Flood（示例）", severity=Severity.high, summary="SYN_RECEIVED 超过阈值。", evidence=["SYN_RECEIVED=120"], recommendation="结合边界设备流量和防火墙日志确认。")); return result
        result.status = "unsupported"; result.summary = "非 Windows 环境不支持网络专项检测。"; return result
    net = run_command(["netstat", "-n", "-p", "tcp"], timeout=20)
    if net.ok:
        syn_received = net.stdout.upper().count("SYN_RECEIVED")
        syn_sent = net.stdout.upper().count("SYN_SENT")
        established_sources: Counter[str] = Counter()
        for line in net.stdout.splitlines():
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 4 and parts[0] == "TCP" and parts[3].upper() == "ESTABLISHED":
                host = parts[2].rsplit(":", 1)[0]
                established_sources[host] += 1
        if syn_received > 100 or syn_sent > 100:
            result.findings.append(Finding(id=f"{MODULE}-syn", module=MODULE, title="疑似 SYN Flood 痕迹", severity=Severity.high, summary="半连接状态数量超过阈值。", evidence=[f"SYN_RECEIVED={syn_received}", f"SYN_SENT={syn_sent}"], recommendation="结合防火墙/负载均衡流量确认，必要时启用 SYN 防护和限速。", tags=["network-attack"], confidence=0.75))
        hot = [f"{ip}: {num} ESTABLISHED" for ip, num in established_sources.items() if num > 80]
        if hot:
            result.findings.append(Finding(id=f"{MODULE}-cc", module=MODULE, title="疑似 CC/异常同源连接", severity=Severity.medium, summary="同一远程 IP 建立大量连接。", evidence=hot[:20], recommendation="检查 Web/IIS 日志、User-Agent、URL 分布并在边界处限速。", tags=["network-attack", "cc"], confidence=0.65))
    else:
        result.errors.append(net.stderr or "netstat 检测失败")
    arp = run_command(["arp", "-a"], timeout=15)
    if arp.ok:
        mac_to_ips: dict[str, list[str]] = {}
        ip_to_macs: dict[str, set[str]] = {}
        for line in arp.stdout.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{11,17})", line)
            if m:
                ip_to_macs.setdefault(m.group(1), set()).add(m.group(2).lower())
                mac_to_ips.setdefault(m.group(2).lower(), []).append(m.group(1))
        dup_ip = [f"{ip} -> {sorted(macs)}" for ip, macs in ip_to_macs.items() if len(macs) > 1]
        if dup_ip:
            result.findings.append(Finding(id=f"{MODULE}-arp", module=MODULE, title="疑似 ARP 异常", severity=Severity.medium, summary="同一 IP 出现多个 MAC。", evidence=dup_ip, recommendation="多轮采样并结合交换机 CAM 表确认是否存在 ARP 欺骗。", tags=["arp"], confidence=0.65))
        result.data["arp"] = arp.stdout[-12000:]
    firewall = run_command(["netsh", "advfirewall", "show", "allprofiles"], timeout=15)
    if firewall.ok and re.search(r"State\s+OFF|状态\s+关闭", firewall.stdout, re.I):
        result.findings.append(Finding(id=f"{MODULE}-fw", module=MODULE, title="发现防火墙配置关闭", severity=Severity.medium, summary="至少一个 Windows 防火墙配置文件可能关闭。", evidence=[firewall.stdout[-2000:]], recommendation="确认是否符合安全基线，建议开启并限制远程管理端口来源。", tags=["firewall"], confidence=0.7))
    ipconfig = run_command(["ipconfig", "/all"], timeout=15)
    if ipconfig.ok:
        result.data["ipconfig"] = ipconfig.stdout[-12000:]
        if "DNS Servers" in ipconfig.stdout or "DNS 服务器" in ipconfig.stdout:
            result.findings.append(Finding(id=f"{MODULE}-dns-info", module=MODULE, title="已采集 DNS/网关配置用于人工复核", severity=Severity.info, summary="DNS 放大/劫持需结合流量和服务进程确认。", evidence=["ipconfig /all 已采集，报告中可查看。"], recommendation="核对 DNS 是否为企业授权地址；DNS 服务异常高流量需结合性能计数器进一步确认。", tags=["dns"], confidence=0.4))
    result.summary = "正常" if not [f for f in result.findings if f.severity != Severity.info] else "疑似攻击/配置风险，详见发现项。"
    result.duration_ms = int((time.perf_counter()-start)*1000)
    return result

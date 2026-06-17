from __future__ import annotations

import csv
import ipaddress
import re
import time
from collections import Counter, defaultdict
from io import StringIO

from backend.app.models import Finding, ModuleResult, Severity
from backend.app.modules.threat_intel import lookup_ip
from backend.app.utils.platform import is_windows, mock_enabled
from backend.app.utils.subprocesses import run_command

MODULE = "network"
DISPLAY = "网络连接与 PID 关联"
RISK_PORTS = {3389: "RDP", 445: "SMB", 135: "RPC", 139: "NetBIOS", 5900: "VNC", 6379: "Redis", 3306: "MySQL", 1433: "MSSQL"}


def _public_ip(value: str) -> bool:
    try:
        host = value.rsplit(":", 1)[0].strip("[]") if ":" in value else value
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def _remote_ip(value: str) -> str | None:
    try:
        host = value.rsplit(":", 1)[0].strip("[]")
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


def _port(value: str) -> int | None:
    try:
        return int(value.rsplit(":", 1)[1])
    except Exception:
        return None


def _tasklist() -> dict[str, str]:
    out = run_command(["tasklist", "/fo", "csv", "/v"], timeout=20)
    mapping: dict[str, str] = {}
    if out.ok:
        for row in csv.DictReader(StringIO(out.stdout)):
            pid = row.get("PID") or row.get("PID ")
            name = row.get("Image Name") or row.get("映像名称") or row.get("映像名称 ")
            if pid and name:
                mapping[pid] = name
    return mapping


def run() -> ModuleResult:
    start = time.perf_counter(); result = ModuleResult(module=MODULE, display_name=DISPLAY, status="done")
    if not is_windows():
        if mock_enabled():
            result.findings.append(Finding(id=f"{MODULE}-public", module=MODULE, title="发现公网连接（示例）", severity=Severity.low, summary="进程与公网 IP 建立连接。", evidence=["TCP 10.0.0.2:50000 8.8.8.8:443 ESTABLISHED 1234"], recommendation="确认目标 IP 和进程业务用途。")); return result
        result.status = "unsupported"; result.summary = "非 Windows 环境不支持 netstat/tasklist 解析。"; return result
    net = run_command(["netstat", "-ano"], timeout=25)
    if not net.ok:
        result.status = "error"; result.errors.append(net.stderr or "netstat 执行失败"); return result
    pid_names = _tasklist()
    connections = []
    public_hits = []
    risky_listeners = []
    pid_counter: Counter[str] = Counter()
    remote_counter: Counter[str] = Counter()
    for line in net.stdout.splitlines():
        parts = re.split(r"\s+", line.strip())
        if len(parts) < 4 or parts[0] not in {"TCP", "UDP"}:
            continue
        proto = parts[0]
        if proto == "TCP" and len(parts) >= 5:
            local, remote, state, pid = parts[1], parts[2], parts[3], parts[4]
        elif proto == "UDP" and len(parts) >= 4:
            local, remote, state, pid = parts[1], parts[2], "", parts[3]
        else:
            continue
        pid_counter[pid] += 1
        rip = _remote_ip(remote)
        if rip: remote_counter[rip] += 1
        item = {"protocol": proto, "local": local, "remote": remote, "state": state, "pid": pid, "process": pid_names.get(pid, "未知"), "public": _public_ip(remote)}
        connections.append(item)
        if item["public"] and state in {"ESTABLISHED", "SYN_SENT"}:
            public_hits.append(f"{proto} {local} -> {remote} {state} PID {pid} {item['process']} TI={lookup_ip(rip or remote)['verdict']}")
        lp = _port(local)
        if state == "LISTENING" and lp in RISK_PORTS:
            risky_listeners.append(f"{RISK_PORTS[lp]} {local} PID {pid} {item['process']}")
    if public_hits:
        result.findings.append(Finding(id=f"{MODULE}-public", module=MODULE, title="发现公网远程连接", severity=Severity.low, summary=f"发现 {len(public_hits)} 条公网连接。", evidence=public_hits[:80], recommendation="确认连接目的、进程路径与业务必要性；可对单个指标启用威胁情报查询。", tags=["network", "public-ip"], confidence=0.55))
    if risky_listeners:
        result.findings.append(Finding(id=f"{MODULE}-listen", module=MODULE, title="发现高风险端口监听", severity=Severity.medium, summary="主机存在常见远程管理/数据库端口监听。", evidence=risky_listeners[:50], recommendation="确认是否需要对外监听；建议限制防火墙来源并核查对应进程。", tags=["network", "listening"], confidence=0.7))
    busy = [f"PID {pid} {pid_names.get(pid, '未知')} 连接数 {num}" for pid, num in pid_counter.items() if num > 80]
    if busy:
        result.findings.append(Finding(id=f"{MODULE}-busy-pid", module=MODULE, title="单进程连接数量异常", severity=Severity.medium, summary="单个 PID 连接数较高。", evidence=busy, recommendation="检查该进程是否为 Web 服务、代理、扫描器或恶意程序。", tags=["network", "pid"], confidence=0.6))
    result.data["connections"] = connections[:2000]
    result.summary = f"解析连接 {len(connections)} 条，发现 {len(result.findings)} 类线索。"; result.duration_ms = int((time.perf_counter()-start)*1000)
    return result

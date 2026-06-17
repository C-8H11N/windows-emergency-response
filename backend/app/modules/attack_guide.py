from __future__ import annotations

CATEGORIES = [
    {
        "id": "web",
        "title": "Web 入侵",
        "icon": "🌐",
        "description": "WebShell、弱口令、异常上传、IIS/中间件日志异常。",
        "modules": ["evtx_logs", "file_traces", "network", "processes", "persistence"],
        "steps": ["检查 Web 目录最近修改文件", "排查异常脚本解释器进程", "核查外连与监听端口", "确认新增服务/计划任务"],
    },
    {
        "id": "host",
        "title": "主机入侵",
        "icon": "🛡️",
        "description": "账号异常、横向移动、恶意进程、启动项后门。",
        "modules": ["evtx_logs", "accounts_registry", "processes", "persistence", "patches"],
        "steps": ["检查失败登录和新增账号", "核查管理员组", "定位可疑进程树", "检查自启动与服务"],
    },
    {
        "id": "network",
        "title": "网络攻击",
        "icon": "📡",
        "description": "SYN Flood、CC、ARP 欺骗、DNS 异常、异常公网连接。",
        "modules": ["network", "network_diagnostics", "processes"],
        "steps": ["检查连接状态分布", "统计同源 IP 连接", "分析 ARP/DNS/网关", "关联 PID 与进程路径"],
    },
    {
        "id": "network_device",
        "title": "路由/交换机攻击",
        "icon": "🛰️",
        "description": "本机侧发现网关、DNS、ARP、路由异常线索。",
        "modules": ["network_diagnostics", "network", "evtx_logs"],
        "steps": ["核对默认网关与 DNS", "检查 ARP 表异常", "检查防火墙和远程管理暴露", "导出证据交由网络设备侧复核"],
    },
]


def get_guide() -> dict:
    return {
        "categories": CATEGORIES,
        "safe_notice": "工具只做本地证据采集与启发式分析；真实威胁情报查询默认关闭，需显式授权。",
    }

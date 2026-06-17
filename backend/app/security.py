from __future__ import annotations

import os

import psutil

from backend.app.models import KillProcessRequest, KillProcessResponse
from backend.app.utils.platform import is_admin

CRITICAL_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe", "memory compression",
}

ACTION_LOG: list[dict[str, str | int | bool]] = []


def kill_process(req: KillProcessRequest) -> KillProcessResponse:
    if not req.confirm:
        return KillProcessResponse(ok=False, message="需要勾选确认后才能终止进程。")
    if req.pid in {0, 4, os.getpid(), os.getppid()} or req.pid < 0:
        return KillProcessResponse(ok=False, message="拒绝终止系统/当前工具关键 PID。")
    try:
        proc = psutil.Process(req.pid)
        name = proc.name().lower()
        if name in CRITICAL_NAMES:
            return KillProcessResponse(ok=False, message=f"拒绝终止受保护关键进程: {name}")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()
        ACTION_LOG.append({"pid": req.pid, "process": name, "ok": True, "reason": req.reason or "用户确认终止"})
        return KillProcessResponse(ok=True, message=f"已终止进程 {name} ({req.pid})。")
    except psutil.AccessDenied:
        ACTION_LOG.append({"pid": req.pid, "ok": False, "reason": "AccessDenied"})
        return KillProcessResponse(ok=False, message="权限不足，可能需要管理员权限或目标进程受保护。", admin_required=not is_admin())
    except psutil.NoSuchProcess:
        return KillProcessResponse(ok=False, message="进程不存在或已退出。")
    except Exception as exc:  # noqa: BLE001
        ACTION_LOG.append({"pid": req.pid, "ok": False, "reason": str(exc)})
        return KillProcessResponse(ok=False, message=f"终止失败: {exc}")

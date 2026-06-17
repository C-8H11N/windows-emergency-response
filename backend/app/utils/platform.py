from __future__ import annotations

import ctypes
import os
import platform as py_platform
import socket
import sys
from pathlib import Path


def is_windows() -> bool:
    return sys.platform.startswith("win")


def mock_enabled() -> bool:
    return os.getenv("WIN_ER_MOCK", "").lower() in {"1", "true", "yes", "on"}


def is_admin() -> bool:
    if not is_windows():
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def hostname() -> str:
    return socket.gethostname()


def ip_addresses() -> list[str]:
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    return sorted(ips) or ["127.0.0.1"]


def os_version() -> str:
    return f"{py_platform.system()} {py_platform.release()} {py_platform.version()}".strip()


def app_base_path() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "backend" / "app"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[1]


def is_user_writable_path(path: str) -> bool:
    normalized = path.lower().replace("/", "\\")
    markers = ["\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\", "\\public\\"]
    return any(marker in normalized for marker in markers)

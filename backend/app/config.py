from __future__ import annotations

import os
import socket
from pathlib import Path

from backend.app import __version__
from backend.app.models import ThreatIntelConfig
from backend.app.utils.platform import app_base_path

APP_NAME = "Windows 应急响应助手"
APP_VERSION = __version__
HOST = "127.0.0.1"


def _find_free_port(start: int = 8000, max_tries: int = 10) -> int:
    """查找可用端口，从 start 开始尝试"""
    for port in range(start, start + max_tries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, port))
                return port
        except OSError:
            continue
    return start  # 都不可用时返回默认端口


PORT = int(os.getenv("WIN_ER_PORT", _find_free_port(8000)))

BASE_PATH = app_base_path()
STATIC_DIR = BASE_PATH / "static"
TEMPLATES_DIR = BASE_PATH / "templates"


def threat_intel_config() -> ThreatIntelConfig:
    external_allowed = os.getenv("WIN_ER_ENABLE_EXTERNAL_INTEL", "").lower() in {"1", "true", "yes", "on"}
    api_key_configured = bool(os.getenv("WIN_ER_VT_API_KEY"))
    return ThreatIntelConfig(
        enabled=False,
        mode="off",
        api_key_configured=api_key_configured,
        external_allowed=external_allowed,
    )


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]

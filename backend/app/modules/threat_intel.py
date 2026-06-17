from __future__ import annotations

import hashlib
import os
from typing import Literal

from backend.app.models import ThreatIntelConfig

_current = ThreatIntelConfig(
    enabled=False,
    mode="off",
    api_key_configured=bool(os.getenv("WIN_ER_VT_API_KEY")),
    external_allowed=os.getenv("WIN_ER_ENABLE_EXTERNAL_INTEL", "").lower() in {"1", "true", "yes", "on"},
)


def get_config() -> ThreatIntelConfig:
    _current.api_key_configured = bool(os.getenv("WIN_ER_VT_API_KEY"))
    _current.external_allowed = os.getenv("WIN_ER_ENABLE_EXTERNAL_INTEL", "").lower() in {"1", "true", "yes", "on"}
    if _current.mode == "virustotal" and not (_current.api_key_configured and _current.external_allowed):
        _current.mode = "off"
        _current.enabled = False
    return _current


def update_config(mode: Literal["off", "test", "virustotal"], confirm_external: bool = False) -> ThreatIntelConfig:
    cfg = get_config()
    if mode == "off":
        cfg.mode = "off"
        cfg.enabled = False
    elif mode == "test":
        cfg.mode = "test"
        cfg.enabled = True
    elif mode == "virustotal":
        if not confirm_external or not cfg.external_allowed or not cfg.api_key_configured:
            cfg.mode = "off"
            cfg.enabled = False
        else:
            cfg.mode = "virustotal"
            cfg.enabled = True
    return cfg


def lookup_ip(ip: str) -> dict:
    cfg = get_config()
    if cfg.mode == "test" and cfg.enabled:
        score = int(hashlib.sha256(ip.encode()).hexdigest()[:2], 16) % 100
        verdict = "malicious" if score > 92 else "suspicious" if score > 78 else "clean"
        return {"indicator": ip, "mode": "test", "verdict": verdict, "score": score, "source": "demo"}
    if cfg.mode == "virustotal" and cfg.enabled:
        return {"indicator": ip, "mode": "virustotal", "verdict": "not_queried", "score": 0, "source": "需在界面中对单个指标显式查询；MVP 不批量外发。"}
    return {"indicator": ip, "mode": "off", "verdict": "disabled", "score": 0, "source": "local"}

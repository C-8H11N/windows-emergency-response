from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Finding(BaseModel):
    id: str
    module: str
    title: str
    severity: Severity = Severity.info
    summary: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str = "请结合业务环境确认。"
    tags: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    requires_admin: bool = False
    confidence: float = Field(default=0.5, ge=0, le=1)
    data: dict[str, Any] = Field(default_factory=dict)


class ModuleResult(BaseModel):
    module: str
    display_name: str
    status: Literal["pending", "running", "done", "error", "unsupported"] = "pending"
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duration_ms: int | None = None
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class ScanStartRequest(BaseModel):
    modules: list[str] | None = None


class ScanStatus(BaseModel):
    scan_id: str
    status: Literal["idle", "running", "done", "error", "cancelled"] = "idle"
    progress: int = Field(default=0, ge=0, le=100)
    current_module: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    modules: list[ModuleResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class ThreatIntelConfig(BaseModel):
    enabled: bool = False
    mode: Literal["off", "test", "virustotal"] = "off"
    api_key_configured: bool = False
    external_allowed: bool = False


class ThreatIntelUpdate(BaseModel):
    mode: Literal["off", "test", "virustotal"] = "off"
    confirm_external: bool = False


class KillProcessRequest(BaseModel):
    pid: int
    confirm: bool = False
    reason: str | None = None


class KillProcessResponse(BaseModel):
    ok: bool
    message: str
    admin_required: bool = False


class HealthResponse(BaseModel):
    ok: bool = True
    app: str
    version: str
    platform: str
    is_windows: bool
    is_admin: bool
    hostname: str
    ips: list[str]
    os_version: str
    threat_intel: ThreatIntelConfig

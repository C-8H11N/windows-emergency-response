from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime
from typing import Callable

from backend.app.models import Finding, ModuleResult, ScanStatus
from backend.app.modules import accounts_registry, evtx_logs, file_traces, network, network_diagnostics, patches, persistence, processes

ModuleRunner = Callable[[], ModuleResult]

MODULES: dict[str, tuple[str, ModuleRunner]] = {
    "evtx_logs": ("Windows 日志快速分析", evtx_logs.run),
    "accounts_registry": ("可疑账户与注册表排查", accounts_registry.run),
    "file_traces": ("文件痕迹与 hosts 分析", file_traces.run),
    "network": ("网络连接与 PID 关联", network.run),
    "processes": ("可疑进程深度分析", processes.run),
    "patches": ("系统漏洞与补丁核查", patches.run),
    "network_diagnostics": ("网络攻击专项检测", network_diagnostics.run),
    "persistence": ("启动项与持久化后门检查", persistence.run),
}


class ScannerService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self._status = ScanStatus(scan_id="idle")

    def start(self, requested: list[str] | None = None) -> ScanStatus:
        with self._lock:
            if self._status.status == "running":
                return self._status
            module_ids = [m for m in (requested or list(MODULES)) if m in MODULES]
            if not module_ids:
                module_ids = list(MODULES)
            self._cancel.clear()
            self._status = ScanStatus(
                scan_id=str(uuid.uuid4()), status="running", progress=0,
                started_at=datetime.utcnow(), modules=[ModuleResult(module=m, display_name=MODULES[m][0]) for m in module_ids], findings=[])
            self._thread = threading.Thread(target=self._run, args=(module_ids,), daemon=True)
            self._thread.start()
            return self._status

    def cancel(self) -> ScanStatus:
        self._cancel.set()
        with self._lock:
            if self._status.status == "running":
                self._status.status = "cancelled"
                self._status.finished_at = datetime.utcnow()
        return self.status()

    def status(self) -> ScanStatus:
        with self._lock:
            return self._status.model_copy(deep=True)

    def findings(self) -> list[Finding]:
        return self.status().findings

    def _run(self, module_ids: list[str]) -> None:
        total = len(module_ids)
        for index, module_id in enumerate(module_ids):
            if self._cancel.is_set():
                break
            display, runner = MODULES[module_id]
            with self._lock:
                self._status.current_module = module_id
                self._status.modules[index].status = "running"
                self._status.progress = int(index / total * 100)
            started = time.perf_counter()
            try:
                result = runner()
                if result.duration_ms is None:
                    result.duration_ms = int((time.perf_counter() - started) * 1000)
            except Exception as exc:  # noqa: BLE001 - scanner must isolate module failures
                result = ModuleResult(module=module_id, display_name=display, status="error", errors=[str(exc)], duration_ms=int((time.perf_counter() - started) * 1000), summary="模块执行异常")
            with self._lock:
                self._status.modules[index] = result
                self._status.findings = [f for m in self._status.modules for f in m.findings]
                self._status.progress = int((index + 1) / total * 100)
        with self._lock:
            if self._status.status != "cancelled":
                self._status.status = "done"
            self._status.current_module = None
            self._status.progress = 100 if self._status.status == "done" else self._status.progress
            self._status.finished_at = datetime.utcnow()


scanner = ScannerService()

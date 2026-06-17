from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.app import config
from pydantic import BaseModel
from backend.app.models import HealthResponse, KillProcessRequest, KillProcessResponse, ScanStartRequest, ScanStatus, ThreatIntelUpdate
from backend.app.modules.attack_guide import get_guide
from backend.app.modules.threat_intel import get_config, update_config
from backend.app.report import render_report
from backend.app.scanner import scanner
from backend.app.security import kill_process
from backend.app.utils.platform import hostname, ip_addresses, is_admin, is_windows, os_version

app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000", "http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        app=config.APP_NAME,
        version=config.APP_VERSION,
        platform="Windows" if is_windows() else "Other",
        is_windows=is_windows(),
        is_admin=is_admin(),
        hostname=hostname(),
        ips=ip_addresses(),
        os_version=os_version(),
        threat_intel=get_config(),
    )


@app.get("/api/guide")
def guide() -> dict:
    return get_guide()


@app.post("/api/scan/start", response_model=ScanStatus)
def start_scan(req: ScanStartRequest | None = None) -> ScanStatus:
    return scanner.start(req.modules if req else None)


@app.get("/api/scan/status", response_model=ScanStatus)
def scan_status() -> ScanStatus:
    return scanner.status()


@app.get("/api/scan/results", response_model=ScanStatus)
def scan_results() -> ScanStatus:
    return scanner.status()


@app.get("/api/logs/export")
def export_logs_csv() -> Response:
    status = scanner.status()
    rows: list[dict[str, str]] = []
    for module in status.modules:
        if module.module == "evtx_logs":
            rows = module.data.get("recent_events", []) if isinstance(module.data.get("recent_events"), list) else []
            break
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["log", "event_id"])
    writer.writeheader()
    for row in rows:
        writer.writerow({"log": row.get("log", ""), "event_id": row.get("event_id", "")})
    filename = f"win-er-logs-{datetime.now():%Y%m%d-%H%M%S}.csv"
    return Response(buffer.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/scan/cancel", response_model=ScanStatus)
def cancel_scan() -> ScanStatus:
    return scanner.cancel()


@app.get("/api/threat-intel/config")
def threat_intel_config() -> dict:
    return get_config().model_dump()


@app.post("/api/threat-intel/config")
def set_threat_intel(update: ThreatIntelUpdate) -> dict:
    return update_config(update.mode, update.confirm_external).model_dump()


@app.post("/api/processes/kill", response_model=KillProcessResponse)
def kill(req: KillProcessRequest) -> KillProcessResponse:
    return kill_process(req)


class OpenFileRequest(BaseModel):
    path: str


@app.post("/api/files/open-location")
def open_file_location(req: OpenFileRequest) -> dict:
    import os, subprocess
    path = os.path.normpath(req.path)
    if not os.path.exists(path):
        return {"ok": False, "error": f"路径不存在: {path}"}
    try:
        subprocess.Popen(['explorer', '/select,', path], shell=True)
        return {"ok": True, "path": path}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/report/html")
def report_html() -> Response:
    html = render_report(scanner.status())
    filename = f"win-er-report-{datetime.now():%Y%m%d-%H%M%S}.html"
    return HTMLResponse(
        html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


if config.STATIC_DIR.exists() and (config.STATIC_DIR / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=config.STATIC_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> FileResponse:
        return FileResponse(config.STATIC_DIR / "index.html")
else:
    @app.get("/", include_in_schema=False)
    def no_frontend() -> HTMLResponse:
        return HTMLResponse("""
        <html><meta charset='utf-8'><body style='font-family: sans-serif; background:#0f172a; color:#e2e8f0; padding:40px'>
        <h1>Windows 应急响应助手后端已启动</h1>
        <p>前端静态文件尚未构建。开发模式请进入 frontend 运行 <code>npm install && npm run dev</code>。</p>
        <p>API 文档：<a style='color:#38bdf8' href='/docs'>/docs</a></p>
        </body></html>
        """)

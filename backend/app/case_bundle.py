from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from backend.app.models import ScanStatus

SCHEMA_VERSION = "security-case-bundle/1.0"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def build_case_bundle(
    status: ScanStatus,
    *,
    app_name: str,
    app_version: str,
    host: dict[str, Any],
    report_html: str,
) -> bytes:
    artifacts = {
        "findings.json": _json_bytes(status.model_dump(mode="json")),
        "report.html": report_html.encode("utf-8"),
    }
    artifact_meta = {
        name: {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        for name, content in artifacts.items()
    }
    manifest = {
        "schema": SCHEMA_VERSION,
        "case_id": status.scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": {"name": app_name, "version": app_version},
        "host": host,
        "scan": {
            "status": status.status,
            "started_at": status.started_at.isoformat() if status.started_at else None,
            "finished_at": status.finished_at.isoformat() if status.finished_at else None,
            "module_count": len(status.modules),
            "finding_count": len(status.findings),
        },
        "artifacts": artifact_meta,
    }
    artifacts["manifest.json"] = _json_bytes(manifest)
    checksums = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n"
        for name, content in sorted(artifacts.items())
    ).encode("ascii")

    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in artifacts.items():
            archive.writestr(name, content)
        archive.writestr("checksums.sha256", checksums)
    return output.getvalue()

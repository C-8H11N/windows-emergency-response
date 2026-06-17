from __future__ import annotations

from collections import Counter
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.app import config
from backend.app.models import ScanStatus
from backend.app.security import ACTION_LOG
from backend.app.utils.platform import hostname, ip_addresses, is_admin, os_version


def render_report(status: ScanStatus) -> str:
    env = Environment(loader=FileSystemLoader(config.TEMPLATES_DIR), autoescape=select_autoescape())
    template = env.get_template("report.html.j2")
    severity_counts = Counter(f.severity.value for f in status.findings)
    return template.render(
        app_name=config.APP_NAME,
        version=config.APP_VERSION,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        hostname=hostname(),
        ips=ip_addresses(),
        os_version=os_version(),
        is_admin=is_admin(),
        status=status,
        severity_counts=dict(severity_counts),
        action_log=ACTION_LOG,
    )

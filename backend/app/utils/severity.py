from __future__ import annotations

from backend.app.models import Severity


SEVERITY_LABELS = {
    Severity.critical: "严重",
    Severity.high: "高危",
    Severity.medium: "中危",
    Severity.low: "低危",
    Severity.info: "信息",
}


def max_severity(values: list[Severity]) -> Severity:
    order = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]
    return max(values or [Severity.info], key=order.index)

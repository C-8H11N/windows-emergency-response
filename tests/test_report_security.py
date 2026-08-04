from backend.app.models import Finding, ScanStatus, Severity
from backend.app.report import render_report


def test_report_escapes_untrusted_evidence():
    status = ScanStatus(
        scan_id="test",
        status="done",
        findings=[Finding(id="f1", module="evtx_logs", title="unsafe", severity=Severity.high,
                          summary="sample", evidence=["<script>alert(1)</script>"], recommendation="review")],
    )
    html = render_report(status)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

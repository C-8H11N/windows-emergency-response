import hashlib
import json
from io import BytesIO
from zipfile import ZipFile

from backend.app.case_bundle import SCHEMA_VERSION, build_case_bundle
from backend.app.models import ScanStatus


def test_case_bundle_contains_verifiable_artifacts():
    status = ScanStatus(scan_id="case-test", status="done")
    payload = build_case_bundle(
        status,
        app_name="Windows ER",
        app_version="test",
        host={"hostname": "host"},
        report_html="<html>safe</html>",
    )
    with ZipFile(BytesIO(payload)) as archive:
        names = set(archive.namelist())
        assert names == {"manifest.json", "findings.json", "report.html", "checksums.sha256"}
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["schema"] == SCHEMA_VERSION
        assert manifest["case_id"] == "case-test"
        checksums = archive.read("checksums.sha256").decode("ascii")
        for name in ("manifest.json", "findings.json", "report.html"):
            assert f"{hashlib.sha256(archive.read(name)).hexdigest()}  {name}" in checksums

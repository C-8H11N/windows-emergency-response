from fastapi.testclient import TestClient

from backend.app.main import app


def test_mutation_requires_local_session():
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.post("/api/scan/cancel").status_code == 403
        assert client.get("/api/case/export").status_code == 403
        assert client.get("/api/session").status_code == 200
        assert client.post("/api/scan/cancel").status_code == 200
        case_response = client.get("/api/case/export")
        assert case_response.status_code == 200
        assert case_response.headers["content-type"] == "application/zip"


def test_remote_and_cross_site_access_are_rejected():
    with TestClient(app, base_url="http://192.0.2.10:8000") as remote:
        assert remote.get("/api/health").status_code == 403
    with TestClient(app, base_url="http://127.0.0.1:8000") as local:
        assert local.get("/api/session", headers={"Origin": "https://example.com"}).status_code == 403

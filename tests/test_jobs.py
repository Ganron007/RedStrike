import time

from fastapi.testclient import TestClient

from cadre_strike.api import server
from cadre_strike.core.models import OperationResponse


class _OkService:
    def __init__(self, _policy: object) -> None:
        pass

    def __getattr__(self, _name: str):
        def _handler(_request):
            return OperationResponse(success=True)

        return _handler


def _wait(client: TestClient, job_id: str, timeout: float = 2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/jobs/{job_id}")
        if response.status_code == 200 and response.json()["status"] in ("completed", "failed"):
            return response
        time.sleep(0.02)
    return client.get(f"/jobs/{job_id}")


def test_job_lifecycle_and_idempotency(monkeypatch) -> None:
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    app = server.create_app()
    client = TestClient(app)

    payload = {
        "action": "domain_users",
        "request": {"target": "192.168.1.7", "domain": "ignite.local", "username": "raaz"},
    }
    first = client.post("/jobs", json=payload)
    assert first.status_code == 200
    job_id = first.json()["id"]

    final = _wait(client, job_id)
    assert final.json()["status"] == "completed"
    assert final.json()["response"]["success"] is True

    duplicate = client.post("/jobs", json=payload)
    assert duplicate.status_code == 200
    assert duplicate.json()["id"] == job_id


def test_job_rejects_unknown_action(monkeypatch) -> None:
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    app = server.create_app()
    client = TestClient(app)

    payload = {"action": "explode", "request": {"target": "192.168.1.7"}}
    response = client.post("/jobs", json=payload)
    assert response.status_code == 422


def test_job_get_missing_returns_404(monkeypatch) -> None:
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    app = server.create_app()
    client = TestClient(app)

    response = client.get("/jobs/nonexistent")
    assert response.status_code == 404

from fastapi.testclient import TestClient

from redstrike.api import server
from redstrike.core.models import OperationResponse


class _OkService:
    def __init__(self, _policy) -> None:
        pass

    def _ok(self, _request):
        return OperationResponse(success=True)

    domain_users = _ok
    domain_groups = _ok
    domain_computers = _ok
    password_policy = _ok
    shares = _ok
    asrep_roastable = _ok
    kerberoastable = _ok
    delegation = _ok
    admin_count = _ok
    adcs_enum = _ok


def test_api_exposes_read_only_ad_routes(monkeypatch) -> None:
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    app = server.create_app()

    paths = {route.path for route in app.routes}

    assert "/ad/admin-count" in paths
    assert "/ad/adcs" in paths


def test_api_rejects_remote_without_api_key(monkeypatch) -> None:
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    app = server.create_app(api_key="secret")
    client = TestClient(app)

    response = client.post(
        "/ad/users",
        json={"target": "192.168.1.7", "domain": "ignite.local", "username": "raaz"},
    )

    assert response.status_code == 401


def test_api_accepts_valid_api_key(monkeypatch) -> None:
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    app = server.create_app(api_key="secret")
    client = TestClient(app)

    response = client.post(
        "/ad/users",
        headers={"X-API-Key": "secret"},
        json={"target": "192.168.1.7", "domain": "ignite.local", "username": "raaz"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True


def test_api_maps_permission_error_to_403(monkeypatch) -> None:
    class _DenyService(_OkService):
        def domain_users(self, _request):
            raise PermissionError("outside scope")

    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _DenyService)
    app = server.create_app(api_key="secret")
    client = TestClient(app)

    response = client.post(
        "/ad/users",
        headers={"X-API-Key": "secret"},
        json={"target": "192.168.1.200", "domain": "ignite.local", "username": "raaz"},
    )

    assert response.status_code == 403


def test_api_maps_guardrail_violation_to_429(monkeypatch) -> None:
    from redstrike.core.errors import GuardrailViolationError

    class _GuardrailService(_OkService):
        def domain_users(self, _request):
            raise GuardrailViolationError("Target '192.168.1.7' exceeded max concurrent runs (1)")

    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _GuardrailService)
    app = server.create_app(api_key="secret")
    client = TestClient(app)

    response = client.post(
        "/ad/users",
        headers={"X-API-Key": "secret"},
        json={"target": "192.168.1.7", "domain": "ignite.local", "username": "raaz"},
    )

    assert response.status_code == 429


class _TinyLimiter(server.RateLimiter):
    def __init__(self, max_requests: int, window_seconds: float) -> None:
        super().__init__(2, 60.0)


def test_api_rate_limits_non_local_callers(monkeypatch) -> None:
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    monkeypatch.setattr(server, "RateLimiter", _TinyLimiter)
    app = server.create_app()
    client = TestClient(app)

    payload = {"target": "192.168.1.7", "domain": "ignite.local", "username": "raaz"}
    first = client.post("/ad/users", json=payload)
    second = client.post("/ad/users", json=payload)
    third = client.post("/ad/users", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429


def test_api_skips_rate_limit_for_loopback(monkeypatch) -> None:
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    monkeypatch.setattr(server, "_is_loopback_host", lambda host: True)
    app = server.create_app()
    client = TestClient(app)

    payload = {"target": "192.168.1.7", "domain": "ignite.local", "username": "raaz"}
    for _ in range(3):
        response = client.post("/ad/users", json=payload)
        assert response.status_code == 200


def test_rate_limiter_isolates_keys() -> None:
    from redstrike.core.errors import RateLimitExceededError

    limiter = server.RateLimiter(max_requests=1, window_seconds=60.0)
    limiter.check("caller-a|/ad/users")
    limiter.check("caller-b|/ad/users")  # distinct key must not raise

    try:
        limiter.check("caller-a|/ad/users")
    except RateLimitExceededError:
        pass
    else:
        raise AssertionError("expected RateLimitExceededError for repeated key")

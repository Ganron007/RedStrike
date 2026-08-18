from __future__ import annotations

import argparse
import ipaddress
import threading
import time
from collections.abc import Callable

from fastapi import FastAPI, Header, HTTPException, Request

from redstrike import __version__
from redstrike.ad.service import ActiveDirectoryAssessmentService
from redstrike.api.campaign import (
    CampaignApproveRequest,
    CampaignRunRequest,
    CampaignStartRequest,
    CampaignStatusRequest,
    CampaignStreamRequest,
    IntentPreviewRequest,
    campaign_approve,
    campaign_run_phase,
    campaign_start,
    campaign_status,
    campaign_stream,
    intent_preview,
)
from redstrike.api.jobs import ALLOWED_JOB_ACTIONS, Job, JobRequest, JobStore
from redstrike.core.errors import GuardrailViolationError, RateLimitExceededError
from redstrike.core.models import ADRequest, OperationResponse
from redstrike.core.policy import DEFAULT_API_PROFILE, POLICY_PROFILES, load_scope_policy


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class RateLimiter:
    """In-memory sliding-window rate limiter keyed by caller + path.

    Intended for non-local API usage. Loopback callers are exempt in the
    route handler, so local testing is never throttled by default.

    State is per-process only (see B3) and bounded: empty keys are pruned and
    the number of distinct keys is capped by `max_keys` to avoid unbounded
    memory growth.
    """

    def __init__(
        self, max_requests: int, window_seconds: float, max_keys: int = 10000
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max(1, max_keys)
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str) -> None:
        if self.max_requests <= 0 or self.window_seconds <= 0:
            return
        now = time.monotonic()
        with self._lock:
            timestamps = self._hits.get(key, [])
            cutoff = now - self.window_seconds
            timestamps = [stamp for stamp in timestamps if stamp > cutoff]
            if len(timestamps) >= self.max_requests:
                retry_after = max(0.0, self.window_seconds - (now - timestamps[0]))
                raise RateLimitExceededError(
                    f"Rate limit exceeded for '{key}': {self.max_requests} requests per "
                    f"{self.window_seconds:g}s. Retry after {retry_after:.1f}s"
                )
            timestamps.append(now)
            self._hits[key] = timestamps
            if len(self._hits) > self.max_keys:
                # Drop the oldest key to stay within the cap.
                self._hits.pop(next(iter(self._hits)), None)


def create_app(
    scope_path: str | None = None,
    api_key: str | None = None,
    profile: str | None = DEFAULT_API_PROFILE,
) -> FastAPI:
    policy = load_scope_policy(scope_path, profile=profile)
    service = ActiveDirectoryAssessmentService(policy)
    limiter = RateLimiter(policy.rate_limit_requests, policy.rate_limit_window_seconds)
    job_store = JobStore()
    app = FastAPI(
        title="RedStrike",
        version=__version__,
        description="Policy-aware AD assessment service for authorized testing",
    )

    @app.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "version": __version__,
            "allowed_modes": [mode.value for mode in policy.allowed_modes],
            "allowed_targets": policy.allowed_targets,
            "allowed_domains": policy.allowed_domains,
            "policy_profile": profile,
            "guardrails": {
                "max_concurrent_per_target": policy.max_concurrent_per_target,
                "max_concurrent_per_domain": policy.max_concurrent_per_domain,
                "cooldown_seconds_per_target": policy.cooldown_seconds_per_target,
                "cooldown_seconds_per_domain": policy.cooldown_seconds_per_domain,
            },
            "rate_limit": {
                "requests": policy.rate_limit_requests,
                "window_seconds": policy.rate_limit_window_seconds,
            },
        }

    def bind(path: str, handler: Callable[[ADRequest], OperationResponse]) -> None:
        @app.post(path)
        def route(
            request: ADRequest,
            http_request: Request,
            x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        ) -> OperationResponse:
            client_host = http_request.client.host if http_request.client else None
            if api_key and x_api_key != api_key and not _is_loopback_host(client_host):
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            try:
                if not _is_loopback_host(client_host):
                    caller = x_api_key or client_host or "anonymous"
                    limiter.check(f"{caller}|{path}")
                return handler(request)
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            except GuardrailViolationError as exc:
                raise HTTPException(status_code=429, detail=str(exc)) from exc
            except RateLimitExceededError as exc:
                raise HTTPException(status_code=429, detail=str(exc)) from exc
            except FileNotFoundError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            except Exception as exc:
                raise HTTPException(status_code=500, detail="Unhandled service error") from exc

    bind("/ad/users", service.domain_users)
    bind("/ad/groups", service.domain_groups)
    bind("/ad/computers", service.domain_computers)
    bind("/ad/password-policy", service.password_policy)
    bind("/ad/shares", service.shares)
    bind("/ad/asrep-roastable", service.asrep_roastable)
    bind("/ad/kerberoastable", service.kerberoastable)
    bind("/ad/delegation", service.delegation)
    bind("/ad/admin-count", service.admin_count)
    bind("/ad/adcs", service.adcs_enum)

    @app.post("/jobs", response_model=Job)
    def create_job(
        payload: JobRequest,
        http_request: Request,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> Job:
        client_host = http_request.client.host if http_request.client else None
        if api_key and x_api_key != api_key and not _is_loopback_host(client_host):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

        try:
            if not _is_loopback_host(client_host):
                caller = x_api_key or client_host or "anonymous"
                limiter.check(f"{caller}|/jobs")

            action = payload.action
            if action not in ALLOWED_JOB_ACTIONS or not hasattr(service, action):
                raise HTTPException(status_code=422, detail=f"Unknown or disallowed action '{action}'")

            def worker(request: ADRequest) -> OperationResponse:
                return getattr(service, action)(request)

            return job_store.create(action, payload.request, worker)
        except RateLimitExceededError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc

    @app.get("/jobs/{job_id}", response_model=Job)
    def get_job(job_id: str) -> Job:
        job = job_store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return job

    @app.post("/campaign/start")
    def campaign_start_route(payload: CampaignStartRequest) -> dict[str, object]:
        try:
            return campaign_start(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/campaign/approve")
    def campaign_approve_route(payload: CampaignApproveRequest) -> dict[str, object]:
        try:
            return campaign_approve(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/campaign/run_phase")
    def campaign_run_phase_route(payload: CampaignRunRequest) -> dict[str, object]:
        try:
            return campaign_run_phase(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/campaign/status")
    def campaign_status_route(payload: CampaignStatusRequest) -> dict[str, object]:
        try:
            return campaign_status(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/campaign/stream")
    def campaign_stream_route(payload: CampaignStreamRequest) -> dict[str, object]:
        try:
            return campaign_stream(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/builders/preview")
    def builders_preview_route(payload: IntentPreviewRequest) -> dict[str, object]:
        try:
            return intent_preview(payload)
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the RedStrike API")
    parser.add_argument("--scope", default=None, help="Path to scope policy YAML")
    parser.add_argument(
        "--profile",
        default=DEFAULT_API_PROFILE,
        choices=sorted(POLICY_PROFILES.keys()),
        help="Built-in scope profile (overlay your YAML with --scope)",
    )
    parser.add_argument("--api-key", default=None, help="Optional API key for non-local callers")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8890, type=int)
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(create_app(args.scope, args.api_key, args.profile), host=args.host, port=args.port)


if __name__ == "__main__":
    main()

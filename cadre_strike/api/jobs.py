from __future__ import annotations

import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Callable
from uuid import uuid4

from pydantic import BaseModel, Field

from cadre_strike.core.models import ADRequest, OperationResponse


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Job(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    action: str
    target: str
    domain: str | None = None
    status: JobStatus = JobStatus.PENDING
    created_at: datetime = Field(default_factory=_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    response: OperationResponse | None = None
    error: str | None = None
    dedupe_key: str = ""


class JobRequest(BaseModel):
    action: str
    request: ADRequest


ALLOWED_JOB_ACTIONS = {
    "domain_users",
    "domain_groups",
    "domain_computers",
    "password_policy",
    "shares",
    "asrep_roastable",
    "kerberoastable",
    "delegation",
    "admin_count",
    "adcs_enum",
}


class JobStore:
    # In-memory store. Single-process only (see B3): state is not shared across
    # uvicorn workers or reloads. `max_jobs` bounds memory by evicting the oldest
    # finished jobs first.
    def __init__(self, max_jobs: int = 1000) -> None:
        self._max_jobs = max(1, max_jobs)
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}
        self._by_key: dict[str, str] = {}

    def _evict_if_needed(self, protect_id: str) -> None:
        if len(self._jobs) <= self._max_jobs:
            return
        # Evict oldest finished jobs first, then any others, never the protected one.
        ordered_ids = list(self._jobs.keys())
        for job_id in ordered_ids:
            if len(self._jobs) <= self._max_jobs:
                break
            if job_id == protect_id:
                continue
            job = self._jobs.get(job_id)
            if job and job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                self._discard(job_id)
        # If still over limit, evict oldest regardless of status.
        for job_id in ordered_ids:
            if len(self._jobs) <= self._max_jobs:
                break
            if job_id == protect_id:
                continue
            self._discard(job_id)

    def _discard(self, job_id: str) -> None:
        job = self._jobs.pop(job_id, None)
        if job:
            self._by_key.pop(job.dedupe_key, None)

    @staticmethod
    def _dedupe_key(action: str, request: ADRequest) -> str:
        return "|".join(
            [
                action,
                request.target,
                request.domain or "",
                request.mode.value,
                request.username or "",
            ]
        )

    def create(
        self, action: str, request: ADRequest, worker: Callable[[ADRequest], OperationResponse]
    ) -> Job:
        key = self._dedupe_key(action, request)
        with self._lock:
            existing_id = self._by_key.get(key)
            if existing_id and existing_id in self._jobs:
                existing = self._jobs[existing_id]
                if existing.status in (JobStatus.PENDING, JobStatus.RUNNING, JobStatus.COMPLETED):
                    return existing
            job = Job(action=action, target=request.target, domain=request.domain, dedupe_key=key)
            self._jobs[job.id] = job
            self._by_key[key] = job.id
            self._evict_if_needed(job.id)

        thread = threading.Thread(target=self._execute, args=(job, request, worker), daemon=True)
        thread.start()
        return job

    def _execute(
        self, job: Job, request: ADRequest, worker: Callable[[ADRequest], OperationResponse]
    ) -> None:
        job.status = JobStatus.RUNNING
        job.started_at = _now()
        try:
            job.response = worker(request)
            job.status = JobStatus.COMPLETED
        except Exception as exc:  # noqa: BLE001 - capture any worker failure into job state
            job.error = str(exc)
            job.status = JobStatus.FAILED
        job.finished_at = _now()

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

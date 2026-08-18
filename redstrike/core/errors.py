from __future__ import annotations


class GuardrailViolationError(RuntimeError):
    """Raised when execution safety limits are exceeded (concurrency/cooldown)."""


class RateLimitExceededError(RuntimeError):
    """Raised when an API caller exceeds the configured request budget."""

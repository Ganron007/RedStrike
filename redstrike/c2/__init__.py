from __future__ import annotations

from redstrike.c2.base import BaseC2Client
from redstrike.c2.meridian import MeridianClient
from redstrike.c2.sliver import SliverClient
from redstrike.core.models import C2Backend


def get_c2_client(
    backend: C2Backend | str = C2Backend.SLIVER,
    endpoint: str | None = None,
    config_path: str | None = None,
    api_key: str | None = None,
) -> BaseC2Client:
    """Factory helper to obtain a configured C2 client instance."""
    backend_val = C2Backend(backend) if isinstance(backend, str) else backend

    if backend_val == C2Backend.SLIVER:
        return SliverClient(
            endpoint=endpoint or "127.0.0.1:31337",
            config_path=config_path,
        )
    elif backend_val == C2Backend.MERIDIAN:
        return MeridianClient(
            endpoint=endpoint or "http://127.0.0.1:8080",
            api_key=api_key,
        )
    raise ValueError(f"Unsupported C2 backend: {backend_val}")


__all__ = [
    "BaseC2Client",
    "MeridianClient",
    "SliverClient",
    "get_c2_client",
]

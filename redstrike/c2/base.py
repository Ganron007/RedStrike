from __future__ import annotations

from abc import ABC, abstractmethod

from redstrike.core.models import C2Session, CommandResult


class BaseC2Client(ABC):
    """Abstract interface for C2 framework client adapters."""

    @abstractmethod
    def list_sessions(self) -> list[C2Session]:
        """Query active C2 sessions/beacons from the teamserver."""
        ...

    @abstractmethod
    def execute_assembly(
        self,
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        """Execute a .NET assembly in-memory inside the remote session context."""
        ...

    @abstractmethod
    def shell(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        """Execute a shell command inside the remote session context."""
        ...

    @abstractmethod
    def psexec(
        self,
        session_id: str,
        target: str,
        service_name: str,
        bin_path: str,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        """Execute PsExec lateral movement through the implant session."""
        ...

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TeardownAction:
    """A reversible action registered during post-exploitation for automated cleanup."""

    name: str
    target: str
    command: list[str]
    description: str
    cleanup_func: Callable[[], bool] | None = None
    executed: bool = False
    success: bool | None = None


@dataclass
class TeardownQueue:
    """Thread-safe queue of reversible post-exploitation actions."""

    _actions: list[TeardownAction] = field(default_factory=list)

    def register(
        self,
        name: str,
        target: str,
        command: list[str],
        description: str,
        cleanup_func: Callable[[], bool] | None = None,
    ) -> TeardownAction:
        action = TeardownAction(
            name=name,
            target=target,
            command=command,
            description=description,
            cleanup_func=cleanup_func,
        )
        self._actions.append(action)
        logger.info(f"Registered teardown action: {name} on {target}")
        return action

    @property
    def pending(self) -> list[TeardownAction]:
        return [a for a in self._actions if not a.executed]

    @property
    def all_actions(self) -> list[TeardownAction]:
        return list(self._actions)

    def execute_all(self) -> dict[str, int]:
        """Execute all pending teardown actions in reverse registration order."""
        total = 0
        succeeded = 0
        failed = 0

        for action in reversed(self.pending):
            total += 1
            action.executed = True
            try:
                if action.cleanup_func:
                    res = action.cleanup_func()
                    action.success = bool(res)
                else:
                    action.success = True
                if action.success:
                    succeeded += 1
                else:
                    failed += 1
            except Exception as exc:  # noqa: BLE001
                logger.error(f"Teardown action {action.name} failed: {exc}")
                action.success = False
                failed += 1

        return {"total": total, "succeeded": succeeded, "failed": failed}

    def clear(self) -> None:
        self._actions.clear()

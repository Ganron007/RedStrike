from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


def save_queue(path: Path, queue: TeardownQueue) -> None:
    """Persist registered cleanup actions next to the engagement state.

    Only the serializable fields are stored (name/target/command/description/
    executed/success) — ``cleanup_func`` callables live in memory for a single
    process; the command vector is what `redstrike teardown --execute` runs.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "actions": [
            {
                "name": action.name,
                "target": action.target,
                "command": list(action.command),
                "description": action.description,
                "executed": action.executed,
                "success": action.success,
            }
            for action in queue.all_actions
        ]
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_queue(path: Path) -> TeardownQueue:
    path = Path(path)
    queue = TeardownQueue()
    if not path.is_file():
        return queue
    try:
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        logger.warning("teardown queue %s unreadable (%s); starting empty", path, exc)
        return queue
    for item in payload.get("actions") or []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        action = TeardownAction(
            name=str(item["name"]),
            target=str(item.get("target") or ""),
            command=[str(part) for part in (item.get("command") or [])],
            description=str(item.get("description") or ""),
        )
        action.executed = bool(item.get("executed") or False)
        action.success = item.get("success")
        queue._actions.append(action)
    return queue

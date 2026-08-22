"""Fail-closed campaign step verification.

``CommandRunner.success`` is only ``return_code == 0``. That is not enough:
wrappers print ``=== T0xx complete ===`` after WinRM ``Access is denied``,
and negative tests (T028) *expect* ``NT_STATUS_ACCESS_DENIED``.

A live step is verified only when all of these hold:

- it actually executed (not dry-run / stub / skipped / HITL gate)
- ``return_code`` is 0
- no unexpected fail pattern appears in stdout/stderr/error
- a success-marker regex matches the combined output

Default marker is ``{node_id with '-' → '_'}_OK`` (``T013`` → ``T013_OK``,
``H-ASSUME`` → ``H_ASSUME_OK``). Negative tests set ``expected_errors`` so
those strings do not veto a matching marker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_FAIL_PATTERNS: tuple[str, ...] = (
    r"(?i)Access is denied",
    r"MANUAL STEP REQUIRED",
    r"(?i)The command line is too long",
    r"(?i)Cannot index into a null array",
    r"(?i)Unable to extract \S+",
    r"T031_FAIL",
    r"NT_STATUS_ACCESS_DENIED",
    r"(?i)WinRM cannot process the request",
    r"PSSessionStateBroken",
    r"(?i)missing SSH key",
    r"(?i)password required for user",
)


def default_success_marker(node_id: str) -> str:
    return re.escape(node_id.replace("-", "_")) + r"_OK"


@dataclass(frozen=True)
class VerifyOutcome:
    verified: bool
    status: str
    reason: str
    marker: str

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "verified": self.verified,
            "verify_status": self.status,
            "verify_reason": self.reason,
            "success_marker": self.marker,
        }


def _waive_fail_pattern(pattern: str, matched: str, expected_errors: tuple[str, ...]) -> bool:
    for raw in expected_errors:
        token = (raw or "").strip()
        if not token:
            continue
        if token.lower() in pattern.lower() or token.lower() in matched.lower():
            return True
        try:
            if re.search(token, pattern, re.IGNORECASE) or re.search(token, matched, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def verify_step_output(
    *,
    node_id: str,
    return_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
    success_marker: str | None = None,
    extra_fail_patterns: tuple[str, ...] | list[str] = (),
    expected_errors: tuple[str, ...] | list[str] = (),
    dry_run: bool = False,
    skipped: bool = False,
    stub: bool = False,
    awaiting_approval: bool = False,
) -> VerifyOutcome:
    marker = success_marker or default_success_marker(node_id)
    if dry_run:
        return VerifyOutcome(False, "dry_run", "dry-run does not verify attack output", marker)
    if stub:
        return VerifyOutcome(False, "stub", "stub — not executed", marker)
    if awaiting_approval:
        return VerifyOutcome(False, "gate", "HITL gate not approved", marker)
    if skipped:
        return VerifyOutcome(False, "skipped", "step skipped", marker)

    text = "\n".join(part for part in (stdout, stderr, error or "") if part)
    expected = tuple(str(item) for item in expected_errors if item)

    for pattern in (*DEFAULT_FAIL_PATTERNS, *tuple(extra_fail_patterns)):
        match = re.search(pattern, text)
        if not match:
            continue
        if _waive_fail_pattern(pattern, match.group(0), expected):
            continue
        return VerifyOutcome(False, "unverified", f"fail pattern matched: {pattern}", marker)

    if return_code != 0:
        return VerifyOutcome(False, "unverified", f"return_code={return_code}", marker)

    try:
        found = re.search(marker, text)
    except re.error as exc:
        return VerifyOutcome(False, "unverified", f"invalid success_marker: {exc}", marker)
    if not found:
        return VerifyOutcome(False, "unverified", f"missing success marker /{marker}/", marker)
    return VerifyOutcome(True, "verified", f"marker /{marker}/ matched", marker)

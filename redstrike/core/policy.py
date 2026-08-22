from __future__ import annotations

import ipaddress
from pathlib import Path

from pydantic import BaseModel, Field

from redstrike.core.models import EngagementMode

READ_ONLY_ACTIONS = {
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

DEFAULT_API_PROFILE = "gated"
DEFAULT_CAMPAIGN_PROFILE = "gated"

_ALL_MODES = [
    EngagementMode.OBSERVE,
    EngagementMode.ASSESS,
    EngagementMode.VALIDATE,
    EngagementMode.REPORT,
]

_GATED_PROFILE: dict[str, object] = {
    "allowed_modes": [EngagementMode.OBSERVE, EngagementMode.ASSESS],
    "allow_high_risk": False,
    "max_concurrent_per_target": 1,
    "max_concurrent_per_domain": 3,
    "cooldown_seconds_per_target": 1.0,
    "cooldown_seconds_per_domain": 0.0,
}

_AUTONOMOUS_PROFILE: dict[str, object] = {
    "allowed_modes": list(_ALL_MODES),
    "allow_high_risk": True,
    "max_concurrent_per_target": 1,
    "max_concurrent_per_domain": 2,
    "cooldown_seconds_per_target": 1.0,
    "cooldown_seconds_per_domain": 0.5,
}

_LAB_UNGATED_PROFILE: dict[str, object] = {
    "allowed_modes": list(_ALL_MODES),
    "allow_high_risk": True,
    "require_scope": True,
    "ungated": True,
    "max_concurrent_per_target": 1,
    "max_concurrent_per_domain": 4,
    "cooldown_seconds_per_target": 0.0,
    "cooldown_seconds_per_domain": 0.0,
}

# User overlay: copy examples/scope.example.yaml → scope.yaml and pass --scope.
POLICY_PROFILES: dict[str, dict[str, object]] = {
    "gated": dict(_GATED_PROFILE),
    "autonomous": dict(_AUTONOMOUS_PROFILE),
    "standalone": dict(_GATED_PROFILE),  # alias for gated
    "campaign": dict(_AUTONOMOUS_PROFILE),  # alias for autonomous
    "lab-readonly": dict(_GATED_PROFILE),
    "lab-ungated": dict(_LAB_UNGATED_PROFILE),
    "validate-gated": {
        "allowed_modes": [
            EngagementMode.OBSERVE,
            EngagementMode.ASSESS,
            EngagementMode.VALIDATE,
        ],
        "allow_high_risk": True,
        "max_concurrent_per_target": 1,
        "max_concurrent_per_domain": 2,
        "cooldown_seconds_per_target": 2.0,
        "cooldown_seconds_per_domain": 1.0,
    },
    "adcs-deep": {
        "allowed_modes": [EngagementMode.ASSESS, EngagementMode.VALIDATE],
        "allow_high_risk": True,
        "max_concurrent_per_target": 1,
        "max_concurrent_per_domain": 2,
        "cooldown_seconds_per_target": 2.0,
        "cooldown_seconds_per_domain": 0.5,
    },
    "forest-trust-review": {
        "allowed_modes": [EngagementMode.OBSERVE, EngagementMode.ASSESS],
        "allow_high_risk": False,
        "max_concurrent_per_target": 1,
        "max_concurrent_per_domain": 2,
        "cooldown_seconds_per_target": 1.0,
        "cooldown_seconds_per_domain": 0.5,
    },
}

PROFILE_ALIASES = {
    "ungated": "lab-ungated",
}


class ScopePolicy(BaseModel):
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_modes: list[EngagementMode] = Field(
        default_factory=lambda: [EngagementMode.OBSERVE, EngagementMode.ASSESS]
    )
    allow_high_risk: bool = False
    require_scope: bool = False
    ungated: bool = False
    max_concurrent_per_target: int = Field(default=1, ge=1)
    max_concurrent_per_domain: int = Field(default=3, ge=1)
    cooldown_seconds_per_target: float = Field(default=0.0, ge=0.0)
    cooldown_seconds_per_domain: float = Field(default=0.0, ge=0.0)
    rate_limit_requests: int = Field(default=60, ge=1)
    rate_limit_window_seconds: float = Field(default=60.0, ge=1.0)

    def require_scope_ready(self) -> None:
        """Fail closed when ungated/lab mode has no targets or domains."""
        if not self.allowed_targets:
            raise PermissionError(
                "scope required: allowed_targets must list hosts or CIDRs before any run"
            )
        if not self.allowed_domains:
            raise PermissionError(
                "scope required: allowed_domains must list AD DNS names before any run"
            )

    def assert_allowed(self, *, action: str, target: str, domain: str | None, mode: EngagementMode) -> None:
        if self.require_scope:
            self.require_scope_ready()
            if not (target or "").strip():
                raise PermissionError("Target is required by scope policy")
            if not (domain or "").strip():
                raise PermissionError("Domain is required by scope policy")

        if mode not in self.allowed_modes:
            raise PermissionError(f"Mode '{mode.value}' is not allowed by scope policy")

        if mode is EngagementMode.VALIDATE and not self.allow_high_risk:
            raise PermissionError("VALIDATE mode requires high-risk approval (allow_high_risk)")

        if action not in READ_ONLY_ACTIONS and not self.allow_high_risk:
            raise PermissionError(f"Action '{action}' requires high-risk approval")

        if (self.allowed_targets or self.require_scope) and not _target_in_scope(
            target, self.allowed_targets, self.allowed_domains
        ):
            raise PermissionError(f"Target '{target}' is outside allowed scope")

        if domain and (self.allowed_domains or self.require_scope) and not _domain_in_scope(
            domain, self.allowed_domains
        ):
            raise PermissionError(f"Domain '{domain}' is outside allowed scope")


def apply_ungated_overrides(policy: ScopePolicy) -> ScopePolicy:
    """Force lab-ungated behaviour after a YAML overlay (cannot turn gates back on)."""
    policy.ungated = True
    policy.require_scope = True
    policy.allow_high_risk = True
    seen = {mode.value: mode for mode in policy.allowed_modes}
    for mode in _ALL_MODES:
        seen.setdefault(mode.value, mode)
    policy.allowed_modes = list(seen.values())
    return policy


def _domain_in_scope(domain: str, allowed: list[str]) -> bool:
    needle = domain.lower().rstrip(".")
    for item in allowed:
        hay = item.lower().rstrip(".")
        if needle == hay or needle.endswith("." + hay):
            return True
    return False


def _target_in_scope(target: str, allowed_targets: list[str], allowed_domains: list[str]) -> bool:
    if _target_matches_any(target, allowed_targets):
        return True
    # FQDN under an allowed DNS suffix (CIDR alone cannot match hostnames).
    return bool(allowed_domains and _domain_in_scope(target, allowed_domains))


def _target_matches_any(target: str, allowed: list[str]) -> bool:
    for entry in allowed:
        if target.lower() == entry.lower():
            return True
        try:
            network = ipaddress.ip_network(entry, strict=False)
            address = ipaddress.ip_address(target)
            if address in network:
                return True
        except ValueError:
            continue
    return False


def resolve_profile_name(profile: str | None) -> str | None:
    if not profile:
        return None
    return PROFILE_ALIASES.get(profile, profile)


def load_scope_policy(path: str | None, profile: str | None = None) -> ScopePolicy:
    data: dict[str, object] = {}
    resolved = resolve_profile_name(profile)

    if resolved:
        if resolved not in POLICY_PROFILES:
            known = ", ".join(sorted(POLICY_PROFILES))
            raise ValueError(f"Unknown scope policy profile '{profile}'. Known: {known}")
        data.update(POLICY_PROFILES[resolved])

    if path:
        text = Path(path).read_text(encoding="utf-8")
        try:
            data.update(_parse_scope_text(text))
        except ValueError as exc:
            raise ValueError(f"Invalid scope policy: {exc}") from exc

    return ScopePolicy.model_validate(data)


def _parse_scope_text(text: str) -> dict[str, object]:
    data: dict[str, object] = {}
    current_key: str | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_inline_comment(raw_line).strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith(":"):
            current_key = line[:-1]
            data[current_key] = []
            continue
        if line.startswith("- ") and current_key:
            value = _parse_scalar(line[2:].strip())
            existing = data.setdefault(current_key, [])
            if isinstance(existing, list):
                existing.append(value)
            else:
                raise ValueError(f"Line {line_number}: key '{current_key}' is not a list")
            continue
        if line.startswith("- "):
            raise ValueError(f"Line {line_number}: list item has no parent key")
        if ":" in line:
            key, value = line.split(":", 1)
            current_key = None
            data[key.strip()] = _parse_value(value.strip())
            continue
        raise ValueError(f"Line {line_number}: unsupported scope policy syntax")

    return data


def _parse_value(value: str) -> object:
    if not value:
        return []
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item.strip()) for item in inner.split(",")]
    return _parse_scalar(value)


def _parse_scalar(value: str) -> str | bool | int | float:
    unquoted = _strip_quotes(value.strip())
    lowered = unquoted.lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    if unquoted.isdigit() or (unquoted.startswith("-") and unquoted[1:].isdigit()):
        return int(unquoted)
    try:
        if "." in unquoted:
            return float(unquoted)
    except ValueError:
        pass
    return unquoted


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _strip_inline_comment(line: str) -> str:
    quote: str | None = None
    for index, char in enumerate(line):
        if char in {"'", '"'}:
            quote = None if quote == char else char
            continue
        if char == "#" and quote is None:
            return line[:index]
    return line

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

DEFAULT_API_PROFILE = "standalone"
DEFAULT_CAMPAIGN_PROFILE = "campaign"

_READONLY_PROFILE: dict[str, object] = {
    "allowed_modes": [EngagementMode.OBSERVE, EngagementMode.ASSESS],
    "allow_high_risk": False,
    "max_concurrent_per_target": 1,
    "max_concurrent_per_domain": 3,
    "cooldown_seconds_per_target": 1.0,
    "cooldown_seconds_per_domain": 0.0,
}

_CAMPAIGN_PROFILE: dict[str, object] = {
    "allowed_modes": [
        EngagementMode.OBSERVE,
        EngagementMode.ASSESS,
        EngagementMode.VALIDATE,
    ],
    "allow_high_risk": True,
    "max_concurrent_per_target": 1,
    "max_concurrent_per_domain": 2,
    "cooldown_seconds_per_target": 1.0,
    "cooldown_seconds_per_domain": 0.5,
}

# User overlay: copy examples/scope.example.yaml → scope.yaml and pass --scope.
POLICY_PROFILES: dict[str, dict[str, object]] = {
    "standalone": dict(_READONLY_PROFILE),
    "lab-readonly": dict(_READONLY_PROFILE),
    "campaign": dict(_CAMPAIGN_PROFILE),
    "cadre-campaign": dict(_CAMPAIGN_PROFILE),  # deprecated alias
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
    "cadre-campaign": "campaign",
    "lab-readonly": "standalone",
}


class ScopePolicy(BaseModel):
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_modes: list[EngagementMode] = Field(
        default_factory=lambda: [EngagementMode.OBSERVE, EngagementMode.ASSESS]
    )
    allow_high_risk: bool = False
    max_concurrent_per_target: int = Field(default=1, ge=1)
    max_concurrent_per_domain: int = Field(default=3, ge=1)
    cooldown_seconds_per_target: float = Field(default=0.0, ge=0.0)
    cooldown_seconds_per_domain: float = Field(default=0.0, ge=0.0)
    rate_limit_requests: int = Field(default=60, ge=1)
    rate_limit_window_seconds: float = Field(default=60.0, ge=1.0)

    def assert_allowed(self, *, action: str, target: str, domain: str | None, mode: EngagementMode) -> None:
        if mode not in self.allowed_modes:
            raise PermissionError(f"Mode '{mode.value}' is not allowed by scope policy")

        if mode is EngagementMode.VALIDATE and not self.allow_high_risk:
            raise PermissionError("VALIDATE mode requires high-risk approval (allow_high_risk)")

        if action not in READ_ONLY_ACTIONS and not self.allow_high_risk:
            raise PermissionError(f"Action '{action}' requires high-risk approval")

        if self.allowed_targets and not _target_matches_any(target, self.allowed_targets):
            raise PermissionError(f"Target '{target}' is outside allowed scope")

        if domain and self.allowed_domains and domain.lower() not in {
            item.lower() for item in self.allowed_domains
        }:
            raise PermissionError(f"Domain '{domain}' is outside allowed scope")


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

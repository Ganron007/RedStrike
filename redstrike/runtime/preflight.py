from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class PreflightResult:
    profile: str
    required_hosts: list[str]
    host_ips: dict[str, str]
    ok: bool
    warnings: list[str]
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "required_hosts": self.required_hosts,
            "host_ips": self.host_ips,
            "ok": self.ok,
            "warnings": self.warnings,
            "notes": self.notes,
        }


def resolve_profiles_path(
    *,
    explicit: Path | str | None = None,
) -> Path | None:
    if explicit is not None:
        path = Path(explicit)
        return path if path.is_file() else None
    for candidate_name in ("lab-profiles.yaml", "profiles.yaml", "examples/profiles.yaml"):
        candidate = Path(candidate_name)
        if candidate.is_file():
            return candidate
    return None


def load_lab_profiles(path: Path | str) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("lab-profiles.yaml must be a mapping")
    return data


def resolve_profile_for_branches(
    data: dict[str, Any],
    branches: set[str],
    *,
    explicit_profile: str | None = None,
) -> str:
    if explicit_profile:
        profiles = data.get("profiles") or {}
        if explicit_profile not in profiles:
            raise ValueError(f"unknown profile '{explicit_profile}'")
        return explicit_profile
    defaults = data.get("branch_defaults") or {}
    # Highest-demand wins: P-DFIR > P-FULL > P-FOREST > P-LINUX/P-NETDEF/P-SUPPLY > P-CHILD
    rank = {
        "P-DFIR": 5,
        "P-FULL": 4,
        "P-FOREST": 3,
        "P-LINUX": 2,
        "P-NETDEF": 2,
        "P-SUPPLY": 2,
        "P-DELEG": 2,
        "P-CREDS": 1,
        "P-CHILD": 1,
        "P-BEACH": 0,
    }
    best = "P-CHILD"
    best_score = -1
    for branch in branches:
        name = defaults.get(branch) or "P-CHILD"
        score = rank.get(name, 0)
        if score > best_score:
            best, best_score = name, score
    return best


def preflight(
    branches: set[str],
    *,
    profile: str | None = None,
    profiles_path: Path | str | None = None,
    require_file: bool = False,
) -> PreflightResult:
    """Advisory preflight from lab profiles yaml (no live ping by default)."""
    path = resolve_profiles_path(explicit=profiles_path)
    if path is None:
        if require_file:
            raise FileNotFoundError("profiles.yaml not found")
        return PreflightResult(
            profile=profile or "unknown",
            required_hosts=[],
            host_ips={},
            ok=True,
            warnings=["profiles.yaml not found — skipping preflight checks"],
            notes="No profiles.yaml found; pass --profiles for environment inventory checks.",
        )

    data = load_lab_profiles(path)
    chosen = resolve_profile_for_branches(data, branches, explicit_profile=profile)
    profiles = data.get("profiles") or {}
    entry = profiles.get(chosen) or {}
    required = list(entry.get("required_hosts") or [])
    hosts = data.get("hosts") or {}
    host_ips = {h: str(hosts[h]) for h in required if h in hosts}
    warnings: list[str] = []
    if "C" in branches and chosen not in {"P-FOREST", "P-FULL", "P-DFIR"}:
        warnings.append("Branch C (SCCM) typically needs P-FOREST (dc03 + mbr02)")
    if "D" in branches and chosen not in {"P-LINUX", "P-FULL", "P-DFIR"}:
        warnings.append("Branch D typically needs P-LINUX (linux01)")
    notes = (
        f"Power on required hosts for {chosen} before --execute. "
        "Live ICMP/WinRM checks are optional (not run here)."
    )
    return PreflightResult(
        profile=chosen,
        required_hosts=required,
        host_ips=host_ips,
        ok=True,
        warnings=warnings,
        notes=notes,
    )

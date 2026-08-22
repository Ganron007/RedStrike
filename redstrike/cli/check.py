from __future__ import annotations

import json
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from redstrike import __version__
from redstrike.core.policy import (
    DEFAULT_API_PROFILE,
    POLICY_PROFILES,
    apply_ungated_overrides,
    load_scope_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = REPO_ROOT / "examples"

# Operator binaries used by live --execute. Dry-run does not need them.
_EXECUTE_TOOLS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("nxc", "netexec"), "AD assessment / NetExec API", "Install NetExec and keep it on PATH."),
    (("certipy",), "ADCS typed intents", "Install Certipy and keep it on PATH."),
    (("bloodyAD", "bloodyad"), "ACL / object intents", "Install bloodyAD and keep it on PATH."),
    (("ssh",), "Hybrid Windows beachhead transport", "OpenSSH client on PATH."),
    (("bash",), "Campaign script runner", "bash on PATH (Git Bash or WSL on Windows)."),
)


@dataclass
class CheckItem:
    name: str
    ok: bool
    detail: str
    required_for_execute: bool = False
    required_for_core: bool = True


def _which_any(names: tuple[str, ...]) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def collect_checks(*, scope_path: Path, ungated: bool = False) -> list[CheckItem]:
    items: list[CheckItem] = [
        CheckItem("python", True, f"{sys.version.split()[0]} (>=3.10)"),
        CheckItem("redstrike", True, f"v{__version__} import ok"),
        CheckItem(
            "demo-graph",
            (EXAMPLES / "campaign-graph.m1.yaml").is_file(),
            str(EXAMPLES / "campaign-graph.m1.yaml"),
        ),
        CheckItem(
            "demo-seed",
            (EXAMPLES / "seed.example.json").is_file(),
            str(EXAMPLES / "seed.example.json"),
        ),
        CheckItem(
            "demo-automation",
            (EXAMPLES / "automation" / "campaign-a" / "demo-recon.sh").is_file(),
            str(EXAMPLES / "automation"),
        ),
        CheckItem(
            "scope",
            scope_path.is_file(),
            (
                str(scope_path)
                if scope_path.is_file()
                else f"missing {scope_path} -> copy examples/scope.example.yaml and edit targets"
            ),
            required_for_core=ungated,
        ),
        CheckItem(
            "api-profile",
            DEFAULT_API_PROFILE in POLICY_PROFILES,
            f"default API profile '{DEFAULT_API_PROFILE}' (overlay with --scope)",
        ),
    ]
    if ungated:
        detail = "lab-ungated not ready"
        ok = False
        if scope_path.is_file():
            try:
                policy = load_scope_policy(str(scope_path), profile="lab-ungated")
                apply_ungated_overrides(policy)
                policy.require_scope_ready()
                ok = True
                detail = (
                    f"ungated ok: {len(policy.allowed_targets)} targets, "
                    f"{len(policy.allowed_domains)} domains"
                )
            except (OSError, PermissionError, ValueError) as extra:
                detail = str(extra)
        else:
            detail = f"--ungated requires {scope_path} with allowed_targets and allowed_domains"
        items.append(CheckItem("ungated-scope", ok, detail, required_for_core=True))
    for names, purpose, hint in _EXECUTE_TOOLS:
        found = _which_any(names)
        items.append(
            CheckItem(
                names[0],
                found is not None,
                f"{found} ({purpose})" if found else f"not on PATH -> {purpose}. {hint}",
                required_for_execute=True,
                required_for_core=False,
            )
        )
    return items


def run_check(*, scope: str = "scope.yaml", execute_ready: bool = False, as_json: bool = False, ungated: bool = False) -> int:
    items = collect_checks(scope_path=Path(scope), ungated=ungated)
    core = [i for i in items if i.required_for_core]
    tools = [i for i in items if i.required_for_execute]
    core_ok = all(i.ok for i in core)
    tools_ok = all(i.ok for i in tools)

    payload = {
        "version": __version__,
        "core_ok": core_ok,
        "execute_ready": tools_ok,
        "items": [asdict(i) for i in items],
        "next": [
            "Copy examples/scope.example.yaml to scope.yaml and set your targets/domains.",
            "API (read-only): redstrike-api --scope scope.yaml --profile standalone",
            "API (lab ungated): redstrike-api --ungated --scope scope.yaml",
            (
                "Campaign dry-run: redstrike-campaign run --phase 1-3 --beachhead windows "
                "--operator provisioning --engage demo --graph examples/campaign-graph.m1.yaml "
                "--seed examples/seed.example.json --automation-root examples/automation"
            ),
            "Live standalone --execute needs PATH tools plus HITL. Lab: --ungated --scope (no HITL).",
        ],
    }
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"RedStrike {__version__} check")
        print("Core (dry-run / API):")
        for item in core:
            mark = "ok" if item.ok else "FAIL"
            print(f"  [{mark}] {item.name}: {item.detail}")
        print("Scope (create your own policy):")
        for item in items:
            if item.required_for_core or item.required_for_execute:
                continue
            mark = "ok" if item.ok else "todo"
            print(f"  [{mark}] {item.name}: {item.detail}")
        print("Operator tools (live --execute only):")
        for item in tools:
            mark = "ok" if item.ok else "missing"
            print(f"  [{mark}] {item.name}: {item.detail}")
        print()
        if core_ok:
            print("Dry-run is ready. Create/edit scope.yaml, then start the API or campaign dry-run.")
        else:
            print("Core install is incomplete. See docs/SETUP.md.")
        if execute_ready and not tools_ok:
            print("--execute-ready: install missing PATH tools before live runs.")
        for line in payload["next"]:
            print(f"  next: {line}")

    if not core_ok:
        return 1
    if execute_ready and not tools_ok:
        return 2
    return 0

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from redstrike import __version__
from redstrike.core.env import (
    unmsys,
    windows_host,
    windows_key,
    windows_tools_dir,
    windows_user,
)
from redstrike.core.manifest import (
    TOOL_MANIFEST,
    ToolVersionStatus,
    audit_toolchain,
    stage_display_name,
)
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


def linux_container() -> str | None:
    name = os.environ.get("REDSTRIKE_LINUX_CONTAINER", "").strip()
    return name or None


def _ssh_probe_once(ssh_base: list[str]) -> bool:
    """Single reachability probe before any per-tool ssh auditing."""
    try:
        done = subprocess.run(
            [*ssh_base, "true"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return done.returncode == 0


def topology() -> dict[str, str | None]:
    """Where each execution domain currently resolves (for `check --json` and the future UI)."""
    from redstrike.core.runner import linux_ssh_base, local_tools_dirs

    container = linux_container()
    ssh_base = linux_ssh_base()
    ws_host = windows_host() or None
    ws_dir = (windows_tools_dir().split(";")[0].strip() or None)
    local_dir = (local_tools_dirs() or [None])[0]
    if container and ssh_base:
        linux_target = f"CONFLICT: container '{container}' + ssh '{ssh_base[-1]}'"
    elif container:
        linux_target = f"container:{container}"
    elif ssh_base:
        linux_target = f"ssh:{ssh_base[-1]}"
    else:
        linux_target = "local"
    return {
        "linux_execution": linux_target,
        "linux_ssh": ssh_base[-1] if ssh_base else None,
        "linux_container": container,
        "windows_execution": f"ssh:{ws_host}" if ws_host else "local (no beachhead configured)",
        "windows_tools_dir": ws_dir,
        "local_tools_dir": local_dir,
    }


def _windows_tools_probe() -> tuple[bool, str]:
    """One batched SSH probe for Windows-side tools in the beachhead tools dir."""
    host = windows_host()
    if not host:
        return True, "not configured (set REDSTRIKE_WINDOWS_HOST to probe)"
    raw_dir = windows_tools_dir()
    if not raw_dir:
        return False, "set REDSTRIKE_WINDOWS_TOOLS_DIR so run-time resolution and staging agree"
    tools_dir = raw_dir.split(";")[0].strip().rstrip("\\/")
    user = windows_user() or "operator"
    key = windows_key()

    names = [
        stage_display_name(spec)
        for spec in TOOL_MANIFEST
        if spec.platform == "windows"
    ]
    ps_list = ",".join(f"'{name}'" for name in names)
    command = (
        "powershell -NoProfile -Command "
        f"\"@({ps_list}) | ForEach-Object {{ $_ + '=' + (Test-Path (Join-Path '{tools_dir}' $_)) }}\""
    )
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
    if key:
        ssh += ["-i", key]
    try:
        done = subprocess.run(
            [*ssh, f"{user}@{host}", command],
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return False, f"probe failed: {exc}"
    if done.returncode != 0:
        return False, f"beachhead unreachable: {done.stderr.strip()[:120]}"
    missing = []
    for line in done.stdout.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        name, _, present = line.partition("=")
        if present.strip().lower() not in ("true", "false"):
            continue
        if present.strip().lower() != "true":
            missing.append(name.strip())
    if missing:
        return False, (
            f"{len(names) - len(missing)}/{len(names)} present in {tools_dir}; "
            f"missing: {', '.join(missing)} (stage with: redstrike stage --tool <name>)"
        )
    return True, f"all {len(names)} Windows tools present in {tools_dir}"


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
    container = linux_container()
    from redstrike.core.runner import linux_ssh_base

    ssh_base = linux_ssh_base()
    if container and ssh_base:
        items.append(
            CheckItem(
                "linux-target",
                False,
                (
                    f"CONFLICT: REDSTRIKE_LINUX_CONTAINER='{container}' and "
                    f"REDSTRIKE_LINUX_SSH='{ssh_base[-1]}' are both set — pick one; "
                    "runs will refuse until resolved"
                ),
                required_for_execute=True,
                required_for_core=False,
            )
        )
    if container:
        docker = shutil.which("docker")
        items.append(
            CheckItem(
                "linux-container",
                docker is not None,
                (
                    f"tools execute via `docker exec -i {container}` "
                    f"(docker: {docker or 'NOT FOUND'})"
                ),
                required_for_execute=True,
                required_for_core=False,
            )
        )
        # Linux tools may live ONLY in the container; do not fail the
        # execute-ready gate on host PATH when a container is configured.
        for item in items:
            if item.required_for_execute and item.name in ("nxc", "certipy", "bloodyAD") and not item.ok:
                item.ok = docker is not None
                item.detail = (
                    f"execution delegated to container '{container}' "
                    f"(host PATH check skipped; see the manifest rows for in-container presence)"
                )
    if ssh_base:
        ssh_bin = shutil.which("ssh")
        reachable = ssh_bin is not None and _ssh_probe_once(ssh_base)
        items.append(
            CheckItem(
                "linux-ssh",
                reachable,
                (
                    f"tools execute on ssh target '{ssh_base[-1]}'"
                    + ("" if reachable else " — UNREACHABLE (check key/host/firewall)")
                ),
                required_for_execute=True,
                required_for_core=False,
            )
        )
        for item in items:
            if item.required_for_execute and item.name in ("nxc", "certipy", "bloodyAD") and not item.ok:
                item.ok = reachable
                item.detail = (
                    f"execution delegated to ssh target '{ssh_base[-1]}'"
                    + ("" if reachable else " (unreachable)")
                )
    ws01_ok, ws01_detail = _windows_tools_probe()
    if windows_host():
        items.append(
            CheckItem(
                "ws01-tools",
                ws01_ok,
                ws01_detail,
                required_for_execute=False,
                required_for_core=False,
            )
        )
    return items


def run_check(
    *,
    scope: str = "scope.yaml",
    execute_ready: bool = False,
    version_gated: bool = False,
    as_json: bool = False,
    ungated: bool = False,
) -> int:
    items = collect_checks(scope_path=Path(scope), ungated=ungated)
    from redstrike.core.runner import linux_ssh_base

    ssh_base = linux_ssh_base()
    ssh_reachable = True
    if ssh_base and not (linux_container()):
        ssh_reachable = shutil.which("ssh") is not None and _ssh_probe_once(ssh_base)
    manifest_statuses: list[ToolVersionStatus] = audit_toolchain(
        container=linux_container(),
        ssh_base=tuple(ssh_base) if ssh_base else None,
        ssh_reachable=ssh_reachable,
        remote_tools_dir=unmsys(os.environ.get("REDSTRIKE_LINUX_TOOLS_DIR", "").strip()) or None,
    )
    topo = topology()
    core = [i for i in items if i.required_for_core]
    tools = [i for i in items if i.required_for_execute]
    core_ok = all(i.ok for i in core)
    tools_ok = all(i.ok for i in tools)
    manifest_ok = all(m.is_compatible for m in manifest_statuses if m.found)

    payload = {
        "version": __version__,
        "core_ok": core_ok,
        "execute_ready": tools_ok,
        "manifest_ok": manifest_ok,
        "topology": topo,
        "items": [asdict(i) for i in items],
        "toolchain_manifest": [asdict(m) for m in manifest_statuses],
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
        print("2024-2026 AD/ADCS Toolchain Manifest:")
        for m in manifest_statuses:
            if m.status == "ok":
                mark = "ok"
            elif m.status == "outdated":
                mark = "WARN"
            else:
                mark = "missing"
            print(f"  [{mark}] {m.name}: {m.detail}")
        print()
        if core_ok:
            print("Dry-run is ready. Create/edit scope.yaml, then start the API or campaign dry-run.")
        else:
            print("Core install is incomplete. See docs/SETUP.md.")
        if execute_ready and not tools_ok:
            print("--execute-ready: install missing PATH tools before live runs.")
        if version_gated and not manifest_ok:
            print("--version-gated: some operator tools are outdated. Upgrade to recommended versions.")
        for line in payload["next"]:
            print(f"  next: {line}")

    if not core_ok:
        return 1
    if execute_ready and not tools_ok:
        return 2
    if version_gated and not manifest_ok:
        return 3
    return 0

"""`redstrike install` — provision the LINUX tool host from manifest recipes.

Mirrors `redstrike stage` (Windows side) for the Linux side: the manifest's
`install` recipes are executed on the selected Linux target — the local
machine, a container (`REDSTRIKE_LINUX_CONTAINER`), or a remote host over SSH
(`REDSTRIKE_LINUX_SSH`) — using the same CommandRunner dispatch as every other
tool invocation, so transport wrapping (and redaction) are identical.

Recipes that are real commands (`pip install …`, `go install …`, `apt …`) run;
prose recipes (e.g. the Azure CLI installer notes, PowerShell modules) are
listed as manual — nothing is invented or guessed.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from redstrike.core.manifest import TOOL_MANIFEST, ToolSpec
from redstrike.core.runner import CommandRunner, linux_container, linux_ssh_base

#: First words that make a recipe an executable command (everything else is prose).
_EXECUTABLE_HEADS = {
    "pip",
    "pip3",
    "python",
    "python3",
    "go",
    "apt",
    "apt-get",
    "sudo",
    "git",
    "curl",
    "wget",
    "bash",
}


def executable_recipe(recipe: str | None) -> list[str] | None:
    """Return argv for an executable recipe, or None when it is prose."""
    if not recipe:
        return None
    # Strip trailing comments ("pip install netexec  # or: apt install netexec")
    command = recipe.split("#", 1)[0].strip()
    if not command:
        return None
    if command.split()[0] not in _EXECUTABLE_HEADS:
        return None
    return command.split()


def _linux_specs() -> list[ToolSpec]:
    return [s for s in TOOL_MANIFEST if s.platform in ("linux", "both")]


def _target_label() -> str:
    container = linux_container()
    ssh = linux_ssh_base()
    if container and ssh:
        return f"CONFLICT: container '{container}' + ssh '{ssh[-1]}' (pick one)"
    if container:
        return f"container:{container}"
    if ssh:
        return f"ssh:{ssh[-1]}"
    return "local"


def _plan(*, as_json: bool) -> int:
    rows: list[dict[str, Any]] = []
    for spec in _linux_specs():
        argv = executable_recipe(spec.install)
        rows.append(
            {
                "tool": spec.name,
                "executable": argv is not None,
                "command": " ".join(argv) if argv else None,
                "recipe": spec.install,
            }
        )
    payload = {"target": _target_label(), "linux_tools": rows}
    if as_json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"Linux tool host provisioning (target: {payload['target']})")
    for row in rows:
        mark = "run  " if row["executable"] else "manual"
        text = row["command"] or row["recipe"] or "(no recipe)"
        print(f"  [{mark}] {row['tool']:12s} {text}")
    print()
    print("  apply:  redstrike install --apply [--only certipy,impacket]")
    return 0


def _apply(*, only: str | None, as_json: bool, venv: str | None = None) -> int:
    wanted = {part.strip() for part in (only or "").split(",") if part.strip()}
    results: list[dict[str, Any]] = []
    failed = 0
    runner = CommandRunner()

    venv_prefix: list[str] | None = None
    if venv:
        # Isolated toolchain: a dedicated venv on the target keeps RedStrike
        # independent of whatever the host's system Python ships. go/apt-style
        # recipes still run normally; pip recipes go into the venv.
        setup = runner.run(["python3", "-m", "venv", venv], timeout_seconds=300)
        if setup.return_code != 0:
            payload = {
                "target": _target_label(),
                "venv": venv,
                "error": f"python3 -m venv failed: {(setup.stderr or '').strip()[:200]}",
            }
            print(json.dumps(payload, indent=2) if as_json else payload["error"], file=sys.stdout if as_json else sys.stderr)
            return 1
        venv_prefix = [f"{venv}/bin"] if not venv.endswith("/bin") else [venv]
        if not as_json:
            print(f"  venv ready: {venv} (pip tools install there)")

    for spec in _linux_specs():
        if wanted and spec.name not in wanted:
            continue
        argv = executable_recipe(spec.install)
        if argv is None:
            results.append(
                {
                    "tool": spec.name,
                    "status": "manual",
                    "recipe": spec.install,
                }
            )
            continue
        if venv_prefix and argv[0] in ("pip", "pip3", "python", "python3"):
            argv = [f"{venv}/bin/pip", *argv[argv.index("install"):]] if "install" in argv else argv
        try:
            result = runner.run(argv, timeout_seconds=600)
            retried = False
            if result.return_code != 0 and "externally-managed" in (result.stderr or ""):
                # Debian/Kali/Ubuntu mark the system Python as externally
                # managed; the same pip line needs the explicit override.
                retry_argv = [*argv, "--break-system-packages"]
                if not as_json:
                    print(f"  [retry] {spec.name}: externally-managed python -> {' '.join(retry_argv)}")
                result = runner.run(retry_argv, timeout_seconds=600)
                argv = retry_argv
                retried = True
        except (FileNotFoundError, ValueError) as exc:
            results.append({"tool": spec.name, "status": "error", "error": str(exc)})
            failed += 1
            continue
        ok = result.return_code == 0
        if not ok:
            failed += 1
        results.append(
            {
                "tool": spec.name,
                "status": "installed" if ok else "failed",
                "command": " ".join(argv),
                "return_code": result.return_code,
                "stderr": (result.stderr or "")[-300:] if not ok else "",
                **({"note": "system python is externally-managed; used --break-system-packages"} if retried else {}),
            }
        )
        if not as_json:
            mark = "ok" if ok else "FAIL"
            print(f"  [{mark}] {spec.name}: {' '.join(argv)}")
    payload: dict[str, Any] = {"target": _target_label(), "results": results, "failed": failed}
    if venv:
        payload["venv"] = venv
        payload["next"] = f"export REDSTRIKE_LINUX_TOOLS_DIR={venv}/bin   # run-time resolution uses this dir"
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        manual = [r for r in results if r["status"] == "manual"]
        if manual:
            print(f"\n  manual steps ({len(manual)}):")
            for row in manual:
                print(f"    {row['tool']}: {row['recipe']}")
        if venv:
            print(f"\n  isolated toolchain ready. Set:\n    export REDSTRIKE_LINUX_TOOLS_DIR={venv}/bin")
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redstrike install",
        description="Provision LINUX tooling from the manifest recipes "
        "(local / container / remote-Linux-ssh targets).",
    )
    parser.add_argument("--plan", action="store_true", help="Show the install plan (default action)")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Execute the executable recipes (prose recipes are listed as manual)",
    )
    parser.add_argument("--only", default=None, help="Comma-separated tool names to limit --apply")
    parser.add_argument(
        "--venv",
        default=None,
        help="Isolated toolchain: create this venv on the target and install pip tools there (e.g. /opt/redstrike/venv); prints the REDSTRIKE_LINUX_TOOLS_DIR to set",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.apply:
        return _apply(only=args.only, as_json=args.json, venv=args.venv)
    return _plan(as_json=args.json)


if __name__ == "__main__":
    sys.exit(main())

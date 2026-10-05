from __future__ import annotations

import logging
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    aliases: tuple[str, ...]
    category: str
    purpose: str
    min_version: str | None = None
    recommended_version: str | None = None
    version_cmd: tuple[str, ...] | None = None
    version_regex: str | None = None
    python_module: str | None = None
    ps_module: str | None = None  # PowerShell module probed via pwsh/powershell
    hint: str = ""
    # --- provisioning (tool setup: see `redstrike stage` / `redstrike check`) ---
    platform: str = "linux"  # linux | windows | both
    stage_name: str | None = None  # remote filename when staging to the Windows beachhead
    install: str | None = None  # one-line install recipe (shown by check --json / stage --plan)
    source_url: str | None = None  # pinned upstream release artifact for `stage --download`
    source_member: str | None = None  # path inside the archive to extract (zip)
    sha256: str | None = None  # pin; enforced when present, recorded otherwise


@dataclass
class ToolVersionStatus:
    name: str
    category: str
    path: str | None
    found: bool
    version: str | None
    min_version: str | None
    recommended_version: str | None
    is_compatible: bool
    status: str  # "ok", "outdated", "missing", "unversioned"
    detail: str


# Pinned Active Directory / ADCS Toolchain Manifest (2024–2026 Engagement Standards)
TOOL_MANIFEST: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="netexec",
        aliases=("nxc", "netexec"),
        category="Enumeration & Execution",
        purpose="SMB/LDAP/WinRM enumeration, RID brute, and remote execution",
        min_version="1.1.0",
        recommended_version="1.5.1",
        version_cmd=("nxc", "--version"),
        version_regex=r"(?:v|version\s+)?(?P<v>\d+\.\d+\.\d+)",
        hint="Install NetExec from its git repo (github.com/Pennyw0rth/NetExec) — "
        "there is no 'netexec' package on PyPI (verified 2026-10-04: 404).",
        install="pip install git+https://github.com/Pennyw0rth/NetExec",
    ),
    ToolSpec(
        name="certipy",
        aliases=("certipy", "certipy-ad"),
        category="ADCS Abuse",
        purpose="ESC1–ESC15 ADCS certificate abuse and PKINIT authentication",
        min_version="4.8.0",
        recommended_version="5.1.0",
        version_cmd=("certipy", "-v"),
        version_regex=r"(?:v|Certipy\s+v)?(?P<v>\d+\.\d+\.\d+)",
        hint="Install Certipy (pip install certipy-ad).",
        install="pip install certipy-ad",
    ),
    ToolSpec(
        name="bloodyAD",
        aliases=("bloodyAD", "bloodyad"),
        category="ACL & Object Abuse",
        purpose="Active Directory LDAP object modification, password reset, and DACL takeover",
        min_version="1.8.0",
        recommended_version="2.5.5",
        # No --version flag exists (argparse usage exits 2 — verified live);
        # version comes from the pip metadata instead.
        python_module="bloodyad",
        version_regex=r"(?:v|version\s+)?(?P<v>\d+\.\d+\.\d+)",
        hint="Install bloodyAD (pip install bloodyAD).",
        install="pip install bloodyAD",
    ),
    ToolSpec(
        name="kerbrute",
        aliases=("kerbrute", "kerbrute_linux_amd64"),
        category="Initial Access & Spray",
        purpose="Fast, lockout-safe Kerberos user enumeration and password spraying",
        min_version="1.0.3",
        recommended_version="1.0.3",
        version_cmd=("kerbrute", "version"),
        version_regex=r"(?:v|version\s+)?(?P<v>\d+\.\d+\.\d+)",
        hint="Download kerbrute from github.com/ropnop/kerbrute and place on PATH.",
        install="go install github.com/ropnop/kerbrute@latest  # or grab a release binary",
    ),
    ToolSpec(
        name="impacket",
        aliases=("secretsdump.py", "GetUserSPNs.py", "wmiexec.py", "ntlmrelayx.py"),
        category="Relay & Credential Extraction",
        purpose="DCSync replication dumps, Kerberoasting, and NTLM relaying",
        min_version="0.11.0",
        recommended_version="0.13.1",
        python_module="impacket",
        hint="Install Impacket (pip install impacket).",
        install="pip install impacket",
    ),
    ToolSpec(
        name="rubeus",
        aliases=("Rubeus.exe", "rubeus.exe", "rubeus"),
        category="Windows Kerberos",
        purpose="Kerberoasting, AS-REProasting, S4U RBCD, and ticket forging on Windows",
        min_version="1.6.4",
        recommended_version="2.3.0",
        hint="GhostPack canonical release is 1.6.4; v2.x (e.g. s4u) ships only via community builds "
        "(mirrors such as github.com/arbaaz29/rubeus-v2.3.3) - verify binary provenance before staging.",
        platform="windows",
        stage_name="Rubeus.exe",
        install="upstream is SOURCE-ONLY (v1.6.4 has no binary assets) — compile it or use a mirror and verify provenance; stage with: redstrike stage --tool rubeus --file <Rubeus.exe>",
    ),
    ToolSpec(
        name="sharpsccm",
        aliases=("SharpSCCM.exe", "sharpsccm.exe", "sharpsccm"),
        category="MECM / SCCM",
        purpose="SCCM NAA extraction, PXE recovery, client push, and CMPivot abuse",
        min_version="2.0.0",
        recommended_version="2.0.13",
        hint="Place compiled SharpSCCM.exe into C:\\Tools\\ or PATH on Windows beachheads.",
        platform="windows",
        stage_name="SharpSCCM.exe",
        source_url="https://github.com/Mayyhem/SharpSCCM/releases/download/v2.0.14/SharpSCCM.exe",
        sha256="97a048bcb55c0108c68f87fcb71396fcee936008757a9573e4aecdba0391f26e",
        install="redstrike stage --tool sharpsccm --download",
    ),
    ToolSpec(
        name="mimikatz",
        aliases=("mimikatz.exe", "mimikatz"),
        category="LSASS & Credential Dump",
        purpose="In-memory credential dumping, SAM hashes, and DCSync extraction",
        min_version="2.2.0",
        recommended_version="2.2.0",
        hint="Place compiled mimikatz.exe into C:\\Tools\\ or PATH on Windows beachheads.",
        platform="windows",
        stage_name="mimikatz.exe",
        source_url="https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip",
        source_member="x64/mimikatz.exe",
        sha256="7accd179e8a6b2fc907e7e8d087c52a7f48084852724b03d25bebcada1acbca5",
        install="redstrike stage --tool mimikatz --download",
    ),
    ToolSpec(
        name="sharphound",
        aliases=("SharpHound.exe", "bloodhound-python"),
        category="Graph Telemetry",
        purpose="Active Directory relationship and permission graph collection",
        min_version="2.0.0",
        hint="Ensure SharpHound.exe or bloodhound-python is staged.",
        recommended_version="2.17.0",
        platform="windows",
        stage_name="SharpHound.exe",
        source_url="https://github.com/SpecterOps/SharpHound/releases/download/v2.17.0/SharpHound_v2.17.0_windows_x86.zip",
        source_member="SharpHound.exe",
        sha256="09ef123ada22be00a6af4dbfa28f9aa357930205f88991374373d634609efb03",
        install="redstrike stage --tool sharphound --download",
    ),
    # ------------------------------------------------------------------
    # Hybrid Identity (Entra ID) — Phase 9.1
    # Version probes/flag contracts cross-checked against upstream (2026-10):
    #   az          — Microsoft Learn azure-cli reference (GA)
    #   azurehound  — SpecterOps BloodHound CE collection docs (v2 CLI)
    #   roadtools   — ROADtools wiki (Getting started with ROADrecon)
    #   AADInternals— o365blog/aadinternals cmdlet reference
    # ------------------------------------------------------------------
    ToolSpec(
        name="az",
        aliases=("az",),
        category="Hybrid Identity (Entra ID)",
        purpose="Entra ID/ARM discovery via `az rest` and tenant sign-in helpers",
        version_cmd=("az", "version"),
        version_regex=r'"azure-cli"\s*:\s*"(?P<v>[^"]+)"',
        hint="Install the Azure CLI (learn.microsoft.com/cli/azure/install-azure-cli).",
        platform="both",
        install="Linux: apt/curl azure-cli | Windows: MSI installer",
    ),
    ToolSpec(
        name="azurehound",
        aliases=("azurehound",),
        category="Hybrid Identity (Entra ID)",
        purpose="Entra ID object/role collection for BloodHound (v2 list subcommand)",
        min_version="2.0.0",
        recommended_version="2.1.0",
        hint="Download AzureHound v2 from SpecterOps/BloodHound releases; "
        "collect with: azurehound -u <user> -p <pass> -t <tenant> list users -o out.json",
        platform="both",
        stage_name="azurehound.exe",
        install="Download the AzureHound v2 release for your OS (SpecterOps/BloodHound releases)",
    ),
    ToolSpec(
        name="roadtools",
        aliases=("roadrecon", "roadtx"),
        category="Hybrid Identity (Entra ID)",
        purpose="ROADrecon object dumps + roadtx hybrid flows (PRT, sync-API tokens)",
        # PyPI metadata reports 0.0.2 regardless of release (verified live:
        # pip show roadtools → 0.0.2, dirkjanm/ROADtools) — a min_version gate
        # would always false-positive, so presence-only here.
        python_module="roadtools",
        hint="Install ROADtools (pip install roadtools); roadtx covers hybrid "
        "flows (gettokens -r aadgraph, prt --key-pem --cert-pem).",
        install="pip install roadtools",
    ),
    ToolSpec(
        name="aadinternals",
        aliases=(),
        category="Hybrid Identity (Entra ID)",
        purpose="Seamless-SSO/cloud-Kerberos ticket forging and PRT workflows",
        min_version="0.9.0",
        recommended_version="0.11.0",
        ps_module="AADInternals",
        hint="Install-Module AADInternals (see o365blog.com/aadinternals).",
        platform="windows",
        install="Install-Module AADInternals  # PowerShell (verified live at 0.9.7)",
    ),
    ToolSpec(
        name="adfspray",
        aliases=("ADFSpray.py", "adfspray.py", "adfs-spray.py"),
        category="Hybrid Identity (Entra ID)",
        purpose="ADFS password spraying (bring your own fork; use the raw-args shim)",
        hint="No single canonical ADFS spray tool: known upstreams are "
        "xFreed0m/ADFSpray and Mr-Un1k0d3r/RedTeamScripts adfs-spray.py. "
        "Stage your chosen script and drive it via the raw-args shim.",
        install="operator-supplied script (no canonical upstream) — use the raw-args shim",
    ),
    ToolSpec(
        name="monkey365",
        aliases=(),
        category="Hybrid Identity (Entra ID)",
        purpose="Entra/Azure security configuration assessment (attacker/auditor view)",
        ps_module="Monkey365",
        hint="Used in the CARTP lab (LO7): Invoke-Monkey365 -IncludeEntraID "
        "-ExportTo HTML -Instance Azure -ForceAuth -Collect All. "
        "Install from the Monkey365 project (github.com/silverhack/monkey365).",
        platform="windows",
        install="Clone github.com/silverhack/monkey365; Import-Module monkey365.psd1",
    ),
    ToolSpec(
        name="graphrunner",
        aliases=("GraphRunner.ps1",),
        category="Hybrid Identity (Entra ID)",
        purpose="Graph/Entra recon and device-code token capture (CARTE lab tool)",
        hint="CARTE lab: Import-Module GraphRunner.ps1; Get-GraphTokens / "
        "Invoke-GraphRecon (device-code phishing). "
        "Upstream: github.com/dafthack/GraphRunner.",
        platform="windows",
        install="Clone github.com/dafthack/GraphRunner; stage GraphRunner.ps1",
    ),
    ToolSpec(
        name="mfasweep",
        aliases=("MFASweep.ps1",),
        category="Hybrid Identity (Entra ID)",
        purpose="MFA/device-code configuration sweep across Microsoft services",
        hint="SANS 588 course tooling: stage MFASweep.ps1 and run under pwsh; "
        "upstream: github.com/dafthack/MFASweep.",
        platform="windows",
        install="Clone github.com/dafthack/MFASweep; stage MFASweep.ps1",
    ),
)


def stage_display_name(spec: ToolSpec) -> str:
    """Remote filename for staging/probing: stage_name, else an alias that
    already carries a real extension, else the tool name (never a fake .exe)."""
    if spec.stage_name:
        return spec.stage_name
    for alias in spec.aliases:
        if alias.lower().endswith((".exe", ".ps1", ".py", ".psd1")):
            return alias
    return spec.name


def _parse_semver(v_str: str) -> tuple[int, ...]:
    parts = []
    for part in v_str.strip().split("."):
        clean = re.sub(r"[^\d]", "", part)
        if clean:
            parts.append(int(clean))
    return tuple(parts) if parts else (0,)


def _probe_ps_module(module: str) -> tuple[str | None, str | None]:
    """Probe a PowerShell module via pwsh/powershell. Returns (host_path, version)."""
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        return None, None
    command = (
        f"(Get-Module -ListAvailable {module} | "
        "Select-Object -First 1).Version.ToString()"
    )
    try:
        res = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=20,  # PowerShell cold start is slow on Windows
            shell=False,
            check=False,
        )
    except (subprocess.SubprocessError, OSError, ValueError) as ex:
        logger.debug("PowerShell module probe failed for %s: %s", module, ex)
        return shell, None
    out = (res.stdout + " " + res.stderr).strip()
    m = re.search(r"(\d+\.\d+(?:\.\d+)*)", out)
    return shell, (m.group(1) if m else None)


def _status_from(found_path: str, detected_version: str | None, spec: ToolSpec) -> ToolVersionStatus:
    """Common status assembly once presence (and maybe version) are known."""
    is_compat = True
    status = "ok"
    if detected_version and spec.min_version:
        try:
            if _parse_semver(detected_version) < _parse_semver(spec.min_version):
                is_compat = False
                status = "outdated"
        except (ValueError, TypeError) as ex:
            logger.debug("Version comparison failed for %s: %s", detected_version, ex)
    version_str = f"v{detected_version}" if detected_version else "present (unversioned)"
    detail_str = f"{found_path} ({version_str}) - {spec.purpose}"
    if status == "outdated":
        detail_str += f" [WARN: Requires >= {spec.min_version}, recommended {spec.recommended_version}]"
    return ToolVersionStatus(
        name=spec.name,
        category=spec.category,
        path=found_path,
        found=True,
        version=detected_version,
        min_version=spec.min_version,
        recommended_version=spec.recommended_version,
        is_compatible=is_compat,
        status=status,
        detail=detail_str,
    )


def probe_tool_version(
    spec: ToolSpec,
    *,
    exec_prefix: tuple[str, ...] | None = None,
    ssh_base: tuple[str, ...] | None = None,
    remote_tools_dir: str | None = None,
) -> ToolVersionStatus:
    """Probe one tool's presence/version.

    Execution targets (mutually exclusive):
    * default — local PATH;
    * ``exec_prefix`` — inside a container (``docker exec -i <name> …``);
    * ``ssh_base`` — on a REMOTE Linux tool host (the whole command becomes
      one quoted shell string, matching the runner's ssh transport).
    """
    if ssh_base:
        remote_dir = (remote_tools_dir or "").rstrip("/") or None

        def _remote_tool(bare: str) -> str:
            """Resolve a bare name against REDSTRIKE_LINUX_TOOLS_DIR (venv bin)."""
            if remote_dir and "/" not in bare and " " not in bare:
                return f"{remote_dir}/{bare}"
            return bare

        found_path: str | None = None
        detected_version: str | None = None
        probe_name = spec.aliases[0] if spec.aliases else spec.name
        if spec.python_module and not spec.version_cmd:
            # Python-distribution tools: probe metadata with the venv python
            # when a tools dir is configured, else the remote system python.
            python_bin = _remote_tool("python3")
            metadata_cmd = (
                f"from importlib.metadata import version; print(version('{spec.python_module}'))"
            )
            candidates = [f"{shlex.quote(python_bin)} -c {shlex.quote(metadata_cmd)}"]
        elif spec.version_cmd:
            argv = list(spec.version_cmd)
            # Try the tools-dir path first, then bare PATH (go installs, system
            # packages). Some tools print a version but exit non-zero (nxc
            # writes its config on first run → rc=1), so a version-regex match
            # is accepted regardless of the exit code.
            prefixed = _remote_tool(argv[0])
            heads = [prefixed, argv[0]] if prefixed != argv[0] else [argv[0]]
            candidates = [
                " ".join(shlex.quote(part) for part in [head, *argv[1:]])
                for head in heads
            ]
        else:
            candidates = [
                f"command -v {shlex.quote(probe_name)} || test -x {shlex.quote(_remote_tool(probe_name))}"
            ]
        for remote in candidates:
            try:
                res = subprocess.run(
                    [*ssh_base, remote],
                    capture_output=True,
                    text=True,
                    timeout=25,
                    shell=False,
                    check=False,
                )
            except (subprocess.SubprocessError, OSError, ValueError) as ex:
                logger.debug("ssh probe failed for %s: %s", spec.name, ex)
                continue
            out = (res.stdout + " " + res.stderr).strip()
            matched = None
            if out:
                if spec.version_regex:
                    m = re.search(spec.version_regex, out, re.IGNORECASE)
                    if m:
                        matched = m.group("v")
                if not matched:
                    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", out)
                    if m:
                        matched = m.group(1)
            accepted = res.returncode == 0 and (bool(out) or not spec.version_cmd)
            if not accepted and matched and spec.version_cmd:
                # rc≠0 but the tool clearly answered with a version (nxc rc=1).
                accepted = True
            if accepted:
                found_path = f"{ssh_base[-1]}:{_remote_tool(probe_name)}"
                detected_version = matched
                break

        if not found_path:
            return ToolVersionStatus(
                name=spec.name,
                category=spec.category,
                path=None,
                found=False,
                version=None,
                min_version=spec.min_version,
                recommended_version=spec.recommended_version,
                is_compatible=False,
                status="missing",
                detail=f"not found on ssh target '{ssh_base[-1]}'. {spec.hint}",
            )
        return _status_from(found_path, detected_version, spec)

    if exec_prefix:
        found_path: str | None = None
        detected_version: str | None = None
        if spec.version_cmd:
            try:
                res = subprocess.run(
                    [*exec_prefix, *spec.version_cmd],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    shell=False,
                    check=False,
                )
                out = (res.stdout + " " + res.stderr).strip()
                if res.returncode == 0 and out:
                    found_path = f"{exec_prefix[-1]}:{spec.version_cmd[0]}"
                    if spec.version_regex:
                        m = re.search(spec.version_regex, out, re.IGNORECASE)
                        if m:
                            detected_version = m.group("v")
                    if not detected_version:
                        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", out)
                        if m:
                            detected_version = m.group(1)
            except (subprocess.SubprocessError, OSError, ValueError) as ex:
                logger.debug("container probe failed for %s: %s", spec.name, ex)
        else:
            probe_name = spec.aliases[0] if spec.aliases else spec.name
            try:
                res = subprocess.run(
                    [*exec_prefix, "sh", "-c", f"command -v {probe_name}"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    shell=False,
                    check=False,
                )
                if res.returncode == 0 and res.stdout.strip():
                    found_path = f"{exec_prefix[-1]}:{res.stdout.strip().splitlines()[0]}"
            except (subprocess.SubprocessError, OSError, ValueError) as ex:
                logger.debug("container presence probe failed for %s: %s", spec.name, ex)

        if not found_path:
            return ToolVersionStatus(
                name=spec.name,
                category=spec.category,
                path=None,
                found=False,
                version=None,
                min_version=spec.min_version,
                recommended_version=spec.recommended_version,
                is_compatible=False,
                status="missing",
                detail=f"not found in container '{exec_prefix[-1]}'. {spec.hint}",
            )
        return _status_from(found_path, detected_version, spec)

    # 1. Check executable on PATH
    found_path: str | None = None
    for alias in spec.aliases:
        found = shutil.which(alias)
        if found:
            found_path = found
            break

    # 2. Check Python module if available
    detected_version: str | None = None
    if spec.python_module:
        try:
            import importlib.metadata

            detected_version = importlib.metadata.version(spec.python_module)
            if not found_path:
                found_path = f"python-module:{spec.python_module}"
        except (ImportError, AttributeError, ValueError, OSError) as ex:
            logger.debug("Failed to read python metadata for %s: %s", spec.python_module, ex)

    # 2b. PowerShell module (AADInternals & friends): no PATH entry exists.
    if not found_path and spec.ps_module:
        shell, version = _probe_ps_module(spec.ps_module)
        if version:
            found_path = f"{spec.ps_module} (via {shell})"
            detected_version = version

    # 3. Probe version via CLI if found
    if found_path and spec.version_cmd and not detected_version:
        try:
            cmd = list(spec.version_cmd)
            cmd[0] = found_path
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3,
                shell=False,
                check=False,
            )
            out = (res.stdout + " " + res.stderr).strip()
            if spec.version_regex:
                m = re.search(spec.version_regex, out, re.IGNORECASE)
                if m:
                    detected_version = m.group("v")
            if not detected_version and out:
                m = re.search(r"(\d+\.\d+(?:\.\d+)?)", out)
                if m:
                    detected_version = m.group(1)
        except (subprocess.SubprocessError, OSError, ValueError) as ex:
            logger.debug("Failed to run version command for %s: %s", found_path, ex)

    if not found_path and not detected_version:
        return ToolVersionStatus(
            name=spec.name,
            category=spec.category,
            path=None,
            found=False,
            version=None,
            min_version=spec.min_version,
            recommended_version=spec.recommended_version,
            is_compatible=False,
            status="missing",
            detail=f"Not found on PATH. {spec.hint}",
        )

    is_compat = True
    status = "ok"
    if detected_version and spec.min_version:
        try:
            curr_parts = _parse_semver(detected_version)
            min_parts = _parse_semver(spec.min_version)
            if curr_parts < min_parts:
                is_compat = False
                status = "outdated"
        except (ValueError, TypeError) as ex:
            logger.debug("Version comparison failed for %s: %s", detected_version, ex)

    version_str = f"v{detected_version}" if detected_version else "present (unversioned)"
    detail_str = f"{found_path or spec.name} ({version_str}) - {spec.purpose}"
    if status == "outdated":
        detail_str += f" [WARN: Requires >= {spec.min_version}, recommended {spec.recommended_version}]"

    return ToolVersionStatus(
        name=spec.name,
        category=spec.category,
        path=found_path,
        found=True,
        version=detected_version,
        min_version=spec.min_version,
        recommended_version=spec.recommended_version,
        is_compatible=is_compat,
        status=status,
        detail=detail_str,
    )


def audit_toolchain(
    *,
    container: str | None = None,
    ssh_base: tuple[str, ...] | None = None,
    ssh_reachable: bool = True,
    remote_tools_dir: str | None = None,
) -> list[ToolVersionStatus]:
    """Audit all tools against the 2024–2026 AD toolchain manifest.

    Execution targets are mutually exclusive:
    * ``container`` — Linux tools probed inside that container
      (``docker exec -i <container> <version_cmd>``), e.g. ``c2stack-kali``;
    * ``ssh_base`` — Linux tools probed on a remote host over ssh (probed only
      when ``ssh_reachable`` — an unreachable host reports every Linux tool as
      not-probed rather than issuing N doomed connections).
    """
    if container and ssh_base:
        raise ValueError("audit_toolchain: container and ssh_base are mutually exclusive")
    prefix = ("docker", "exec", "-i", container) if container else None
    ssh_tuple = tuple(ssh_base) if ssh_base else None
    statuses: list[ToolVersionStatus] = []
    for spec in TOOL_MANIFEST:
        linux_side = spec.platform in ("linux", "both")
        if (prefix or ssh_tuple) and not linux_side:
            statuses.append(
                ToolVersionStatus(
                    name=spec.name,
                    category=spec.category,
                    path=None,
                    found=False,
                    version=None,
                    min_version=spec.min_version,
                    recommended_version=spec.recommended_version,
                    is_compatible=True,  # windows-side tool: not expected on the Linux target
                    status="missing",
                    detail=f"windows-side tool (stage to the beachhead via `redstrike stage`). {spec.hint}",
                )
            )
            continue
        if ssh_tuple and not ssh_reachable:
            statuses.append(
                ToolVersionStatus(
                    name=spec.name,
                    category=spec.category,
                    path=None,
                    found=False,
                    version=None,
                    min_version=spec.min_version,
                    recommended_version=spec.recommended_version,
                    is_compatible=True,  # unknown, not failed
                    status="missing",
                    detail=f"not probed — ssh target '{ssh_tuple[-1]}' unreachable",
                )
            )
            continue
        statuses.append(
            probe_tool_version(
                spec, exec_prefix=prefix, ssh_base=ssh_tuple, remote_tools_dir=remote_tools_dir
            )
        )
    return statuses

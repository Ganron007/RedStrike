from __future__ import annotations

import logging
import re
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
    hint: str = ""


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
        hint="Install NetExec (pip install netexec or apt install netexec).",
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
    ),
    ToolSpec(
        name="bloodyAD",
        aliases=("bloodyAD", "bloodyad"),
        category="ACL & Object Abuse",
        purpose="Active Directory LDAP object modification, password reset, and DACL takeover",
        min_version="1.8.0",
        recommended_version="2.5.5",
        version_cmd=("bloodyAD", "--version"),
        version_regex=r"(?:v|version\s+)?(?P<v>\d+\.\d+\.\d+)",
        hint="Install bloodyAD (pip install bloodyAD).",
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
    ),
    ToolSpec(
        name="sharpsccm",
        aliases=("SharpSCCM.exe", "sharpsccm.exe", "sharpsccm"),
        category="MECM / SCCM",
        purpose="SCCM NAA extraction, PXE recovery, client push, and CMPivot abuse",
        min_version="2.0.0",
        recommended_version="2.0.13",
        hint="Place compiled SharpSCCM.exe into C:\\Tools\\ or PATH on Windows beachheads.",
    ),
    ToolSpec(
        name="mimikatz",
        aliases=("mimikatz.exe", "mimikatz"),
        category="LSASS & Credential Dump",
        purpose="In-memory credential dumping, SAM hashes, and DCSync extraction",
        min_version="2.2.0",
        recommended_version="2.2.0",
        hint="Place compiled mimikatz.exe into C:\\Tools\\ or PATH on Windows beachheads.",
    ),
    ToolSpec(
        name="sharphound",
        aliases=("SharpHound.exe", "bloodhound-python"),
        category="Graph Telemetry",
        purpose="Active Directory relationship and permission graph collection",
        min_version="2.0.0",
        recommended_version="2.14.0",
        hint="Ensure SharpHound.exe or bloodhound-python is staged.",
    ),
)


def _parse_semver(v_str: str) -> tuple[int, ...]:
    parts = []
    for part in v_str.strip().split("."):
        clean = re.sub(r"[^\d]", "", part)
        if clean:
            parts.append(int(clean))
    return tuple(parts) if parts else (0,)


def probe_tool_version(spec: ToolSpec) -> ToolVersionStatus:
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


def audit_toolchain() -> list[ToolVersionStatus]:
    """Audit all tools against the 2024–2026 AD toolchain manifest."""
    return [probe_tool_version(spec) for spec in TOOL_MANIFEST]

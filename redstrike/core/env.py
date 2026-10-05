"""Canonical environment-variable naming with back-compat aliases.

RedStrike's transports must not bake in any lab's host names. The canonical
names are role-generic (``REDSTRIKE_WINDOWS_*`` / ``REDSTRIKE_LINUX_*``);
legacy ``REDSTRIKE_WS01_*`` names from early builds keep working as aliases so
existing operator notes don't break.
"""

from __future__ import annotations

import os
import re

# Git Bash (MSYS2) rewrites POSIX-looking env-var values when launching native
# Windows programs: REDSTRIKE_LINUX_TOOLS_DIR=/home/vagrant/venv/bin arrives as
# "C:/Program Files/Git/home/vagrant/venv/bin". That converted value is wrong
# for the REMOTE host, so strip the MSYS root prefix when it is clearly the
# artifact (value points under <git-root>/home or <git-root>/opt etc.).
_MSYS_ROOT_PREFIX = re.compile(
    r"^[A-Za-z]:[\\/](?:Program Files[\\/])?Git(?=[\\/](?:home|opt|root|usr|srv)[\\/])",
    re.IGNORECASE,
)


def unmsys(value: str) -> str:
    """Strip the Git-Bash MSYS-root prefix from a converted POSIX path value."""
    if not value:
        return value
    return _MSYS_ROOT_PREFIX.sub("", value)


def env_alias(canonical: str, *aliases: str) -> str:
    """First non-empty value among canonical + aliases (canonical wins)."""
    for name in (canonical, *aliases):
        value = os.environ.get(name, "").strip()
        if value:
            return unmsys(value)
    return ""


def windows_host() -> str:
    return env_alias("REDSTRIKE_WINDOWS_HOST", "REDSTRIKE_WS01_HOST")


def windows_user() -> str:
    return env_alias("REDSTRIKE_WINDOWS_USER", "REDSTRIKE_WS01_USER")


def windows_key() -> str:
    return env_alias("REDSTRIKE_WINDOWS_SSH_KEY", "REDSTRIKE_WS01_SSH_KEY")


def windows_tools_dir() -> str:
    return env_alias("REDSTRIKE_WINDOWS_TOOLS_DIR", "REDSTRIKE_WS01_TOOLS_DIR")


def windows_known_hosts() -> str:
    return env_alias("REDSTRIKE_WINDOWS_KNOWN_HOSTS", "REDSTRIKE_WS01_KNOWN_HOSTS")

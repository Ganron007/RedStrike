from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import secret_value


class AdcsModernBuilder:
    """Typed builder and shims for modern 2024-2026 ADCS vectors (ESC16 audit, ESC17 shim)."""

    def pyesc17(
        self,
        *,
        args: tuple[str, ...] = (),
        binary: str = "pyesc17.py",
    ) -> list[str]:
        """Operator-pinned ESC17 exploit shim.

        No canonical public ESC17 exploit exists (verified: no PyPI package, no
        GitHub repo as of Aug 2026), so this builder does not invent flags. The
        graph author must pass the exact argv for the exploit script they deploy
        (research PoCs / private forks) via ``args``; credentials inside args are
        redacted by the runner's argv redaction.
        """
        return [binary, *args]

    def esc16_audit(
        self,
        *,
        target: str,
        domain: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        dc_ip: str | None = None,
        binary: str = "certipy",
    ) -> list[str]:
        """Audit for ESC16 (Security Extension OID misconfiguration and weak mapping)."""
        user_spec = f"{username}@{domain}" if domain and "@" not in username else username
        argv = [binary, "find", "-target", target, "-u", user_spec]
        pw = secret_value(password)
        if pw:
            argv.extend(["-p", pw])
        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        argv.extend(["-vulnerable", "-stdout"])
        return argv

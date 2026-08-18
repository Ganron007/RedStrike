from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import extend_user_pass, secret_value


class CertipyBuilder:
    """Typed Certipy argv builder (ADCS)."""

    tool = "certipy"

    def find(
        self,
        *,
        target: str,
        username: str | None = None,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        vulnerable: bool = True,
        stdout: bool = True,
    ) -> list[str]:
        argv = [self.tool, "find", "-target", target]
        argv = extend_user_pass(
            argv, username=username, password=password, nt_hash=nt_hash, domain=domain
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if vulnerable:
            argv.append("-vulnerable")
        if stdout:
            argv.append("-stdout")
        return argv

    def req(
        self,
        *,
        ca: str,
        template: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        upn: str | None = None,
        dns: str | None = None,
    ) -> list[str]:
        argv = [self.tool, "req", "-ca", ca, "-template", template]
        argv = extend_user_pass(
            argv, username=username, password=password, nt_hash=nt_hash, domain=domain
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if upn:
            argv.extend(["-upn", upn])
        if dns:
            argv.extend(["-dns", dns])
        return argv

    def auth(
        self,
        *,
        pfx: str,
        username: str | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
    ) -> list[str]:
        argv = [self.tool, "auth", "-pfx", pfx]
        if username:
            argv.extend(["-username", username])
        if domain:
            argv.extend(["-domain", domain])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        return argv

    def shadow(
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
        if action not in {"auto", "add", "list", "clear", "remove"}:
            raise ValueError(f"unsupported shadow action: {action}")
        argv = [self.tool, "shadow", action, "-account", account, "-target", target]
        argv = extend_user_pass(
            argv, username=username, password=password, nt_hash=nt_hash, domain=domain
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        _ = secret_value(password)  # keep import used for typing clarity
        return argv

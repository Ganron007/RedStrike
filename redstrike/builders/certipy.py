from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import extend_user_pass, secret_value


def _extend_certipy_auth(
    argv: list[str],
    *,
    username: str | None = None,
    password: str | SecretStr | None = None,
    nt_hash: str | SecretStr | None = None,
    domain: str | None = None,
) -> list[str]:
    user = username
    if user and domain and "@" not in user:
        user = f"{user}@{domain}"
    return extend_user_pass(
        argv,
        username=user,
        password=password,
        nt_hash=nt_hash,
        domain=None,
        user_flag="-u",
        pass_flag="-p",
        hash_flag="-hashes",
    )


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
        argv = _extend_certipy_auth(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
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
        target: str | None = None,
        upn: str | None = None,
        dns: str | None = None,
        on_behalf_of: str | None = None,
        sid: str | None = None,
        key_size: int | None = None,
    ) -> list[str]:
        argv = [self.tool, "req", "-ca", ca, "-template", template]
        if target:
            argv.extend(["-target", target])
        argv = _extend_certipy_auth(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if upn:
            argv.extend(["-upn", upn])
        if dns:
            argv.extend(["-dns", dns])
        if on_behalf_of:
            argv.extend(["-on-behalf-of", on_behalf_of])
        if sid:
            argv.extend(["-sid", sid])
        if key_size:
            argv.extend(["-key-size", str(key_size)])
        return argv

    def auth(
        self,
        *,
        pfx: str,
        username: str | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        unpac_hash: bool = True,
        no_hash: bool = False,
        ldap_shell: bool = False,
    ) -> list[str]:
        argv = [self.tool, "auth", "-pfx", pfx]
        if username:
            argv.extend(["-username", username])
        if domain:
            argv.extend(["-domain", domain])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if no_hash:
            argv.append("-no-hash")
        if ldap_shell:
            argv.append("-ldap-shell")
        return argv

    def template(
        self,
        *,
        template: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        target: str | None = None,
        write_default: bool = False,
        configuration: str | None = None,
    ) -> list[str]:
        argv = [self.tool, "template", "-template", template]
        if target:
            argv.extend(["-target", target])
        argv = _extend_certipy_auth(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if write_default:
            argv.append("-write-default-configuration")
        if configuration:
            argv.extend(["-configuration", configuration])
        return argv

    def ca(
        self,
        *,
        ca: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        target: str | None = None,
        add_officer: str | None = None,
        issue_request: int | None = None,
    ) -> list[str]:
        argv = [self.tool, "ca", "-ca", ca]
        if target:
            argv.extend(["-target", target])
        argv = _extend_certipy_auth(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if add_officer:
            argv.extend(["-add-officer", add_officer])
        if issue_request is not None:
            argv.extend(["-issue-request", str(issue_request)])
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
        argv = _extend_certipy_auth(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        _ = secret_value(password)
        return argv

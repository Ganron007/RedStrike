from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import extend_user_pass


class BloodyADBuilder:
    """Typed bloodyAD argv builder (LDAP abuse helpers)."""

    tool = "bloodyAD"

    def _host(
        self,
        *,
        host: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
    ) -> list[str]:
        argv = [self.tool, "--host", host]
        return extend_user_pass(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
        )

    def get_object(
        self,
        *,
        host: str,
        username: str,
        target: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        attr: str | None = None,
    ) -> list[str]:
        argv = self._host(
            host=host, username=username, password=password, nt_hash=nt_hash, domain=domain
        )
        argv.extend(["get", "object", target])
        if attr:
            argv.extend(["--attr", attr])
        return argv

    def set_password(
        self,
        *,
        host: str,
        username: str,
        target: str,
        new_password: str | SecretStr,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
    ) -> list[str]:
        """High-risk ACL write — gate with HITL acl_write."""
        from redstrike.builders._auth import secret_value

        argv = self._host(
            host=host, username=username, password=password, nt_hash=nt_hash, domain=domain
        )
        argv.extend(["set", "password", target, secret_value(new_password) or ""])
        return argv

    def add_generic_all(
        self,
        *,
        host: str,
        username: str,
        target: str,
        trustee: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
    ) -> list[str]:
        """High-risk ACL write."""
        argv = self._host(
            host=host, username=username, password=password, nt_hash=nt_hash, domain=domain
        )
        argv.extend(["add", "genericAll", target, trustee])
        return argv

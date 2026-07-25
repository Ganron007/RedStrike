from __future__ import annotations

from pydantic import SecretStr

from cadre_strike.builders._auth import secret_value


class SqlBuilder:
    """Typed SQL access builders (impacket mssqlclient)."""

    def mssqlclient(
        self,
        *,
        target: str,
        username: str,
        password: str | SecretStr | None = None,
        domain: str | None = None,
        windows_auth: bool = True,
        hashes: str | SecretStr | None = None,
        port: int = 1433,
        query: str | None = None,
    ) -> list[str]:
        pw = secret_value(password)
        h = secret_value(hashes)
        if pw:
            spec = self._target_spec(
                user=username, password=pw, domain=domain if windows_auth else None, host=target
            )
        elif domain and windows_auth:
            spec = f"{domain}/{username}@{target}"
        else:
            spec = f"{username}@{target}"

        argv = ["impacket-mssqlclient", spec]
        if windows_auth:
            argv.append("-windows-auth")
        if h:
            argv.extend(["-hashes", h])
        if port != 1433:
            argv.extend(["-port", str(port)])
        if query:
            argv.extend(["-q", query])
        return argv

    def xp_cmdshell_query(self, command: str) -> str:
        safe = command.replace("'", "''")
        return f"EXEC master..xp_cmdshell '{safe}'"

    def with_xp_cmdshell(
        self,
        *,
        target: str,
        username: str,
        command: str,
        password: str | SecretStr | None = None,
        domain: str | None = None,
        windows_auth: bool = True,
    ) -> list[str]:
        return self.mssqlclient(
            target=target,
            username=username,
            password=password,
            domain=domain,
            windows_auth=windows_auth,
            query=self.xp_cmdshell_query(command),
        )

    @staticmethod
    def _target_spec(*, user: str, password: str, domain: str | None, host: str) -> str:
        if domain:
            return f"{domain}/{user}:{password}@{host}"
        return f"{user}:{password}@{host}"

from __future__ import annotations

from pydantic import SecretStr


class NetExecCommandBuilder:
    def base(
        self,
        *,
        protocol: str,
        target: str,
        username: str | None = None,
        password: SecretStr | None = None,
        nt_hash: SecretStr | None = None,
        domain: str | None = None,
        kdc_host: str | None = None,
    ) -> list[str]:
        if protocol not in {"smb", "ldap", "winrm"}:
            raise ValueError(f"Unsupported NetExec protocol: {protocol}")

        argv = ["nxc", protocol, target]
        if username:
            argv.extend(["-u", username])
        if password:
            argv.extend(["-p", password.get_secret_value()])
        if nt_hash:
            argv.extend(["-H", nt_hash.get_secret_value()])
        if domain:
            argv.extend(["-d", domain])
        if kdc_host:
            argv.extend(["--kdcHost", kdc_host])
        return argv

    def users(self, **kwargs: object) -> list[str]:
        return self.base(protocol="ldap", **kwargs) + ["--users"]

    def groups(self, **kwargs: object) -> list[str]:
        return self.base(protocol="ldap", **kwargs) + ["--groups"]

    def computers(self, **kwargs: object) -> list[str]:
        return self.base(protocol="ldap", **kwargs) + ["--computers"]

    def password_policy(self, **kwargs: object) -> list[str]:
        return self.base(protocol="smb", **kwargs) + ["--pass-pol"]

    def shares(self, **kwargs: object) -> list[str]:
        return self.base(protocol="smb", **kwargs) + ["--shares"]

    def asrep_roastable(self, output_file: str, **kwargs: object) -> list[str]:
        return self.base(protocol="ldap", **kwargs) + ["--asreproast", output_file]

    def kerberoastable(self, output_file: str, **kwargs: object) -> list[str]:
        return self.base(protocol="ldap", **kwargs) + ["--kerberoasting", output_file]

    def delegation(self, **kwargs: object) -> list[str]:
        return self.base(protocol="ldap", **kwargs) + ["--find-delegation"]

    def admin_count(self, **kwargs: object) -> list[str]:
        return self.base(protocol="ldap", **kwargs) + ["--admin-count"]

    def adcs_enum(self, **kwargs: object) -> list[str]:
        return self.base(protocol="ldap", **kwargs) + ["--adcs"]

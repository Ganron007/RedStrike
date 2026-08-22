from __future__ import annotations

from pydantic import SecretStr


class NetExecCommandBuilder:
    """Typed NetExec (nxc) command builder across SMB, LDAP, WinRM, and WMI."""

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
        if protocol not in {"smb", "ldap", "winrm", "wmi", "mssql"}:
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

    def laps(self, **kwargs: object) -> list[str]:
        """Extract LAPS passwords (nxc exposes --laps on the smb and winrm protocols only)."""
        return self.base(protocol="smb", **kwargs) + ["--laps"]

    def gpp_password(self, **kwargs: object) -> list[str]:
        """Extract GPP cpassword XML records from SYSVOL (gpp_password module via -M)."""
        return self.base(protocol="smb", **kwargs) + ["-M", "gpp_password"]

    def rid_brute(self, max_rid: int = 4000, **kwargs: object) -> list[str]:
        """Brute force Active Directory RIDs to enumerate hidden user accounts."""
        return self.base(protocol="smb", **kwargs) + ["--rid-brute", str(max_rid)]

    def smb_exec(
        self,
        command: str,
        *,
        use_powershell: bool = True,
        exec_method: str = "wmiexec",
        **kwargs: object,
    ) -> list[str]:
        """Execute command over SMB with specified execution method (wmiexec, smbexec, atexec, mmcexec)."""
        flag = "-X" if use_powershell else "-x"
        argv = self.base(protocol="smb", **kwargs) + [flag, command]
        if exec_method:
            argv.extend(["--exec-method", exec_method])
        return argv

    def winrm_exec(
        self,
        command: str,
        *,
        use_powershell: bool = True,
        exec_method: str | None = None,
        **kwargs: object,
    ) -> list[str]:
        """Execute command over WinRM."""
        flag = "-X" if use_powershell else "-x"
        argv = self.base(protocol="winrm", **kwargs) + [flag, command]
        if exec_method:
            argv.extend(["--exec-method", exec_method])
        return argv

    def wmi_exec(
        self,
        command: str,
        *,
        use_powershell: bool = True,
        **kwargs: object,
    ) -> list[str]:
        """Execute command over WMI."""
        flag = "-X" if use_powershell else "-x"
        return self.base(protocol="wmi", **kwargs) + [flag, command]

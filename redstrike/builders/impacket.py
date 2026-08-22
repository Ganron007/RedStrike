from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import secret_value


def _format_target_spec(
    target: str,
    *,
    username: str | None = None,
    password: str | SecretStr | None = None,
    domain: str | None = None,
) -> str:
    if not username:
        return target
    user_part = f"{domain}/{username}" if domain else username
    pw = secret_value(password)
    if pw:
        return f"{user_part}:{pw}@{target}"
    return f"{user_part}@{target}"


class ImpacketBuilder:
    """Typed builder for Impacket suite (secretsdump, GetUserSPNs, wmiexec, smbexec, atexec, psexec, ntlmrelayx)."""

    def secretsdump(
        self,
        *,
        target: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        just_dc_ntlm: bool = True,
        just_dc: bool = False,
        just_dc_user: str | None = None,
        ntds: str | None = None,
        history: bool = False,
        outputfile: str | None = None,
        binary: str = "secretsdump.py",
    ) -> list[str]:
        """Build secretsdump command for NTDS.dit / SAM / LSA replication dump."""
        argv = [binary, _format_target_spec(target, username=username, password=password, domain=domain)]
        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if just_dc_ntlm:
            argv.append("-just-dc-ntlm")
        elif just_dc:
            argv.append("-just-dc")
        if just_dc_user:
            argv.extend(["-just-dc-user", just_dc_user])
        if ntds:
            argv.extend(["-ntds", ntds])
        if history:
            argv.append("-history")
        if outputfile:
            argv.extend(["-outputfile", outputfile])
        return argv

    def getuserspns(
        self,
        *,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        request: bool = True,
        target_domain: str | None = None,
        outputfile: str | None = None,
        binary: str = "GetUserSPNs.py",
    ) -> list[str]:
        """Build GetUserSPNs command for Kerberoasting."""
        user_spec = f"{domain}/{username}" if domain else username
        pw = secret_value(password)
        if pw:
            user_spec = f"{user_spec}:{pw}"
        argv = [binary, user_spec]
        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if request:
            argv.append("-request")
        if target_domain:
            argv.extend(["-target-domain", target_domain])
        if outputfile:
            argv.extend(["-outputfile", outputfile])
        return argv

    def wmiexec(
        self,
        *,
        target: str,
        command: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        nooutput: bool = False,
        binary: str = "wmiexec.py",
    ) -> list[str]:
        """Build wmiexec command execution."""
        argv = [binary, _format_target_spec(target, username=username, password=password, domain=domain)]
        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if nooutput:
            argv.append("-nooutput")
        argv.append(command)
        return argv

    def smbexec(
        self,
        *,
        target: str,
        command: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        binary: str = "smbexec.py",
    ) -> list[str]:
        """Build smbexec command execution."""
        argv = [binary, _format_target_spec(target, username=username, password=password, domain=domain)]
        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        argv.append(command)
        return argv

    def atexec(
        self,
        *,
        target: str,
        command: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        binary: str = "atexec.py",
    ) -> list[str]:
        """Build atexec (Task Scheduler) command execution."""
        argv = [binary, _format_target_spec(target, username=username, password=password, domain=domain)]
        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        argv.append(command)
        return argv

    def psexec(
        self,
        *,
        target: str,
        command: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        binary: str = "psexec.py",
    ) -> list[str]:
        """Build psexec command execution."""
        argv = [binary, _format_target_spec(target, username=username, password=password, domain=domain)]
        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        argv.append(command)
        return argv

    def ntlmrelayx(
        self,
        *,
        target: str,
        smb2support: bool = True,
        adcs: bool = False,
        template: str | None = None,
        delegate_access: bool = False,
        escalate_user: str | None = None,
        outputfile: str | None = None,
        socks: bool = False,
        binary: str = "ntlmrelayx.py",
    ) -> list[str]:
        """Build ntlmrelayx relay listener command."""
        argv = [binary, "-t", target]
        if smb2support:
            argv.append("-smb2support")
        if adcs:
            argv.append("--adcs")
            if template:
                argv.extend(["--template", template])
        if delegate_access:
            argv.append("--delegate-access")
        if escalate_user:
            argv.extend(["--escalate-user", escalate_user])
        if outputfile:
            argv.extend(["-of", outputfile])
        if socks:
            argv.append("-socks")
        return argv

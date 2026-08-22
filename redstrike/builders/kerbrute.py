from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import secret_value


class KerbruteBuilder:
    """Typed builder for high-speed, lockout-safe Kerberos user enumeration and spraying (kerbrute)."""

    def __init__(self, binary: str = "kerbrute") -> None:
        self.binary = binary

    def userenum(
        self,
        *,
        userlist: str,
        domain: str,
        dc: str | None = None,
        threads: int | None = None,
        outfile: str | None = None,
    ) -> list[str]:
        """Enumerate valid Active Directory usernames without generating logon failure events."""
        argv = [self.binary, "userenum", "-d", domain]
        if dc:
            argv.extend(["--dc", dc])
        if threads:
            argv.extend(["--threads", str(threads)])
        if outfile:
            argv.extend(["-o", outfile])
        argv.append(userlist)
        return argv

    def passwordspray(
        self,
        *,
        userlist: str,
        password: str | SecretStr,
        domain: str,
        dc: str | None = None,
        delay_ms: int | None = None,
        threads: int | None = None,
        outfile: str | None = None,
    ) -> list[str]:
        """Perform password spraying against target domain with optional rate-limiting delay."""
        argv = [self.binary, "passwordspray", "-d", domain]
        if dc:
            argv.extend(["--dc", dc])
        if delay_ms is not None and delay_ms > 0:
            argv.extend(["--delay", str(delay_ms)])
        if threads:
            argv.extend(["--threads", str(threads)])
        if outfile:
            argv.extend(["-o", outfile])
        argv.extend([userlist, secret_value(password) or ""])
        return argv

    def bruteuser(
        self,
        *,
        username: str,
        passlist: str,
        domain: str,
        dc: str | None = None,
        threads: int | None = None,
        outfile: str | None = None,
    ) -> list[str]:
        """Brute-force a single account against a wordlist."""
        argv = [self.binary, "bruteuser", "-d", domain]
        if dc:
            argv.extend(["--dc", dc])
        if threads:
            argv.extend(["--threads", str(threads)])
        if outfile:
            argv.extend(["-o", outfile])
        argv.extend([passlist, username])
        return argv

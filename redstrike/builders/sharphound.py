from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import secret_value


class SharpHoundBuilder:
    """Typed builder for SharpHound and bloodhound-python data collection."""

    def sharphound(
        self,
        *,
        collection_methods: str = "All",
        domain: str | None = None,
        dc: str | None = None,
        zip_filename: str | None = None,
        output_dir: str | None = None,
        stealth: bool = False,
        binary: str = "SharpHound.exe",
    ) -> list[str]:
        """Build SharpHound.exe Windows collection command (flags verified against SharpHound v2 CLI)."""
        argv = [binary, "-c", collection_methods]
        if domain:
            argv.extend(["--domain", domain])
        if dc:
            argv.extend(["--domaincontroller", dc])
        if zip_filename:
            argv.extend(["--zipfilename", zip_filename])
        if output_dir:
            argv.extend(["--outputdirectory", output_dir])
        if stealth:
            argv.append("--stealth")
        return argv

    def bloodhound_python(
        self,
        *,
        username: str,
        domain: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        dc: str | None = None,
        nameserver: str | None = None,
        collection_methods: str = "All",
        zip_output: bool = True,
        binary: str = "bloodhound-python",
    ) -> list[str]:
        """Build bloodhound-python Linux collection command."""
        argv = [binary, "-u", username, "-d", domain, "-c", collection_methods]
        pw = secret_value(password)
        if pw:
            argv.extend(["-p", pw])
        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])
        if dc:
            argv.extend(["-dc", dc])
        if nameserver:
            argv.extend(["-ns", nameserver])
        if zip_output:
            argv.append("--zip")
        return argv

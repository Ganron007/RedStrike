from __future__ import annotations

import inspect
from typing import Any, Callable

from cadre_strike.builders import (
    BloodyADBuilder,
    CertipyBuilder,
    MimikatzBuilder,
    RubeusBuilder,
    SharpSCCMBuilder,
    SqlBuilder,
    WinRSBuilder,
)
from cadre_strike.runtime.ledger import Credential, CredentialLedger

IntentFn = Callable[..., list[str]]


class UnknownIntentError(KeyError):
    pass


class IntentRegistry:
    """Map graph `intent:` names to typed builder methods (shell=False argv)."""

    def __init__(self) -> None:
        self._certipy = CertipyBuilder()
        self._rubeus = RubeusBuilder()
        self._bloody = BloodyADBuilder()
        self._sql = SqlBuilder()
        self._sccm = SharpSCCMBuilder()
        self._mimikatz = MimikatzBuilder()
        self._winrs = WinRSBuilder()
        self._intents: dict[str, IntentFn] = {
            "certipy.find": self._certipy.find,
            "certipy.req": self._certipy.req,
            "certipy.auth": self._certipy.auth,
            "certipy.shadow": self._certipy.shadow,
            "rubeus.asreproast": self._rubeus.asreproast,
            "rubeus.kerberoast": self._rubeus.kerberoast,
            "rubeus.asktgt": self._rubeus.asktgt,
            "rubeus.golden": self._rubeus.golden,
            "bloodyad.get_object": self._bloody.get_object,
            "bloodyad.set_password": self._bloody.set_password,
            "bloodyad.add_generic_all": self._bloody.add_generic_all,
            "sql.mssqlclient": self._sql.mssqlclient,
            "sql.xp_cmdshell": self._sql.with_xp_cmdshell,
            "sharpsccm.get_naa": self._sccm.get_naa,
            "sharpsccm.get_pxe": self._sccm.get_pxe,
            "sharpsccm.client_push": self._sccm.client_push,
            "mimikatz.logonpasswords": self._mimikatz.logonpasswords,
            "mimikatz.dcsync": self._mimikatz.dcsync,
            "mimikatz.sam": self._mimikatz.sam,
            "winrs.command": self._winrs.run,
            "winrs.cmd": self._winrs.run_cmd,
        }

    def known(self) -> list[str]:
        return sorted(self._intents)

    def build(
        self,
        intent: str,
        args: dict[str, Any] | None = None,
        *,
        ledger: CredentialLedger | None = None,
        cred_name: str | None = None,
    ) -> list[str]:
        if intent not in self._intents:
            raise UnknownIntentError(
                f"unknown intent '{intent}'; known={self.known()}"
            )
        fn = self._intents[intent]
        kwargs = dict(args or {})
        if cred_name and ledger is not None:
            kwargs = merge_cred(kwargs, ledger.require(cred_name))
        params = inspect.signature(fn).parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            filtered = kwargs
        else:
            filtered = {k: v for k, v in kwargs.items() if k in params}
        return fn(**filtered)


def merge_cred(kwargs: dict[str, Any], cred: Credential) -> dict[str, Any]:
    """Fill username/password/hash/domain from ledger when not already set."""
    out = dict(kwargs)
    out.setdefault("username", cred.username)
    if "user" not in out and "username" in out:
        # rubeus uses user=
        pass
    out.setdefault("user", cred.username)
    if cred.password is not None:
        out.setdefault("password", cred.password)
    if cred.nt_hash is not None:
        out.setdefault("nt_hash", cred.nt_hash)
        out.setdefault("rc4", cred.nt_hash)
        out.setdefault("hashes", f"aad3b435b51404eeaad3b435b51404ee:{cred.nt_hash}")
    if cred.domain is not None:
        out.setdefault("domain", cred.domain)
    return out


DEFAULT_REGISTRY = IntentRegistry()

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from redstrike.ad.netexec import NetExecCommandBuilder
from redstrike.builders import (
    AdcsModernBuilder,
    BloodyADBuilder,
    CertipyBuilder,
    CoerceBuilder,
    EntraBuilder,
    ImpacketBuilder,
    KerbruteBuilder,
    MimikatzBuilder,
    RubeusBuilder,
    ShadowCredentialsBuilder,
    SharpHoundBuilder,
    SharpSCCMBuilder,
    SqlBuilder,
    WinRSBuilder,
)
from redstrike.core.models import C2Backend, C2TaskType, CallKind, CallSpec
from redstrike.runtime.ledger import Credential, CredentialLedger

IntentFn = Callable[..., list[str] | CallSpec]


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
        self._shadow = ShadowCredentialsBuilder()
        self._coerce = CoerceBuilder()
        self._impacket = ImpacketBuilder()
        self._kerbrute = KerbruteBuilder()
        self._sharphound = SharpHoundBuilder()
        self._adcs_modern = AdcsModernBuilder()
        self._netexec = NetExecCommandBuilder()
        self._entra = EntraBuilder()

        self._intents: dict[str, IntentFn] = {
            # ADCS (Certipy + Modern)
            "certipy.find": self._certipy.find,
            "certipy.req": self._certipy.req,
            "certipy.auth": self._certipy.auth,
            "certipy.shadow": self._certipy.shadow,
            "certipy.template": self._certipy.template,
            "certipy.ca": self._certipy.ca,
            "adcs.pyesc17": self._adcs_modern.pyesc17,
            "adcs.esc16_audit": self._adcs_modern.esc16_audit,
            # Kerberos & Tickets (Rubeus)
            "rubeus.asreproast": self._rubeus.asreproast,
            "rubeus.kerberoast": self._rubeus.kerberoast,
            "rubeus.asktgt": self._rubeus.asktgt,
            "rubeus.s4u": self._rubeus.s4u,
            "rubeus.golden": self._rubeus.golden,
            "rubeus.silver": self._rubeus.silver,
            "rubeus.diamond": self._rubeus.diamond,
            # Coercion
            "coerce.spoolsample": self._coerce.spoolsample,
            "coerce.petitpotam": self._coerce.petitpotam,
            "coerce.dfir": self._coerce.dfircoerce,
            "coerce.shadowcoerce": self._coerce.shadowcoerce,
            # Initial Access & Spraying (Kerbrute)
            "kerbrute.userenum": self._kerbrute.userenum,
            "kerbrute.spray": self._kerbrute.passwordspray,
            "kerbrute.bruteuser": self._kerbrute.bruteuser,
            # Impacket Suite & Relay
            "impacket.secretsdump": self._impacket.secretsdump,
            "impacket.getuserspns": self._impacket.getuserspns,
            "impacket.wmiexec": self._impacket.wmiexec,
            "impacket.smbexec": self._impacket.smbexec,
            "impacket.atexec": self._impacket.atexec,
            "impacket.psexec": self._impacket.psexec,
            "impacket.ntlmrelayx": self._impacket.ntlmrelayx,
            # NetExec Remote Execution & Probes
            "netexec.smb_exec": self._netexec.smb_exec,
            "netexec.winrm_exec": self._netexec.winrm_exec,
            "netexec.wmi_exec": self._netexec.wmi_exec,
            "netexec.rid_brute": self._netexec.rid_brute,
            "netexec.laps": self._netexec.laps,
            "netexec.gpp_password": self._netexec.gpp_password,
            # Shadow Credentials
            "shadowcreds.pywhiskey": self._shadow.pywhiskey,
            "shadowcreds.certipy_shadow": self._shadow.certipy_shadow,
            # LDAP & Object ACLs (BloodyAD)
            "bloodyad.get_object": self._bloody.get_object,
            "bloodyad.set_password": self._bloody.set_password,
            "bloodyad.add_generic_all": self._bloody.add_generic_all,
            # Database (SQL)
            "sql.mssqlclient": self._sql.mssqlclient,
            "sql.xp_cmdshell": self._sql.with_xp_cmdshell,
            # MECM / SCCM (SharpSCCM)
            "sharpsccm.get_naa": self._sccm.get_naa,
            "sharpsccm.get_pxe": self._sccm.get_pxe,
            "sharpsccm.client_push": self._sccm.client_push,
            "sharpsccm.exec_cmpivot": self._sccm.exec_cmpivot,
            "sharpsccm.app_deploy": self._sccm.app_deploy,
            "sharpsccm.exec_script": self._sccm.exec_script,
            "sharpsccm.adminservice": self._sccm.adminservice_query,
            # In-Memory & LSASS (Mimikatz)
            "mimikatz.logonpasswords": self._mimikatz.logonpasswords,
            "mimikatz.dcsync": self._mimikatz.dcsync,
            "mimikatz.sam": self._mimikatz.sam,
            # WinRM & WinRS
            "winrs.command": self._winrs.run,
            "winrs.cmd": self._winrs.run_cmd,
            # BloodHound Ingestion
            "sharphound.collect": self._sharphound.sharphound,
            "bloodhound.python_collect": self._sharphound.bloodhound_python,
            # C2 Framework Integration (Phase 8)
            "c2.sliver.execute_assembly": self._sliver_execute_assembly,
            "c2.sliver.psexec": self._sliver_psexec,
            "c2.sliver.shell": self._sliver_shell,
            "c2.sliver.list_sessions": self._sliver_list_sessions,
            "c2.meridian.task": self._meridian_task,
            "c2.meridian.shell": self._meridian_shell,
            "c2.meridian.execute_assembly": self._meridian_execute_assembly,
            # Mythic (REST API, priority 2)
            "c2.mythic.shell": self._mythic_shell,
            "c2.mythic.execute_assembly": self._mythic_execute_assembly,
            "c2.mythic.psexec": self._mythic_psexec,
            "c2.mythic.list_sessions": self._mythic_list_sessions,
            # Havoc & Adaptix via the C2Stack Flight Control portal (Phase 8.5)
            "c2.havoc.shell": self._c2_shell_builder(C2Backend.HAVOC),
            "c2.havoc.execute_assembly": self._c2_execute_assembly_builder(C2Backend.HAVOC),
            "c2.havoc.list_sessions": self._c2_list_sessions_builder(C2Backend.HAVOC),
            "c2.adaptix.shell": self._c2_shell_builder(C2Backend.ADAPTIX),
            "c2.adaptix.list_sessions": self._c2_list_sessions_builder(C2Backend.ADAPTIX),
            # Entra ID / Hybrid Identity (Phase 9.2). Cloud-takeover steps are
            # HITL-gated at the graph level via `hitl_gate: cloud_takeover`.
            "entra.az_login": self._entra.az_login_service_principal,
            "entra.account_show": self._entra.az_account_show,
            "entra.account_list": self._entra.az_account_list,
            "entra.signed_in_user": self._entra.az_signed_in_user,
            "entra.role_assignment_list": self._entra.az_role_assignment_list,
            "entra.token_artifacts": self._entra.token_artifacts,
            "entra.graph_query": self._entra.graph_query,
            "entra.azurehound_collect": self._entra.azurehound_collect,
            "entra.azurehound_collect_jwt": self._entra.azurehound_collect_jwt,
            "entra.user_role_enum": self._entra.user_role_enum,
            "entra.roadrecon_auth": self._entra.roadrecon_auth,
            "entra.roadrecon_auth_device_code": self._entra.roadrecon_auth_device_code,
            "entra.roadrecon_auth_token": self._entra.roadrecon_auth_token,
            "entra.roadrecon_auth_prt": self._entra.roadrecon_auth_prt,
            "entra.roadrecon_gather": self._entra.roadrecon_gather,
            "entra.roadtx_gettokens": self._entra.roadtx_gettokens,
            "entra.roadtx_prt": self._entra.roadtx_prt,
            "entra.hybrid_script": self._entra.hybrid_script,
            "entra.kerberos_ticket": self._entra.seamless_sso_ticket,
            "entra.prt_token": self._entra.prt_token,
            "entra.adfs_spray": self._entra.adfs_spray,
            "entra.monkey365": self._entra.monkey365,
            "entra.graphrunner": self._entra.graphrunner,
        }

    @staticmethod
    def _sliver_execute_assembly(session_id: str = "", assembly: str = "", args: list[str] | None = None, **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.SLIVER,
            c2_task_type=C2TaskType.EXECUTE_ASSEMBLY,
            session_id=session_id,
            assembly=assembly,
            args=args or [],
        )

    @staticmethod
    def _sliver_shell(session_id: str = "", command: str = "", **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.SLIVER,
            c2_task_type=C2TaskType.SHELL,
            session_id=session_id,
            args=[command] if command else [],
        )

    @staticmethod
    def _sliver_psexec(session_id: str = "", target: str = "", service: str = "RedStrikeSvc", bin_path: str = "", **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.SLIVER,
            c2_task_type=C2TaskType.PSEXEC,
            session_id=session_id,
            args=[target, service, bin_path],
        )

    @staticmethod
    def _sliver_list_sessions(**kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.SLIVER,
            c2_task_type=C2TaskType.LIST_SESSIONS,
        )

    @staticmethod
    def _meridian_task(session_id: str = "", module: str = "shell", action: str = "exec", params: dict[str, Any] | None = None, **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.MERIDIAN,
            c2_task_type=C2TaskType.TASK,
            session_id=session_id,
            body={"module": module, "action": action, "params": params or {}},
        )

    @staticmethod
    def _meridian_shell(session_id: str = "", command: str = "", **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.MERIDIAN,
            c2_task_type=C2TaskType.SHELL,
            session_id=session_id,
            args=[command] if command else [],
        )

    @staticmethod
    def _meridian_execute_assembly(session_id: str = "", assembly: str = "", args: list[str] | None = None, **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.MERIDIAN,
            c2_task_type=C2TaskType.EXECUTE_ASSEMBLY,
            session_id=session_id,
            assembly=assembly,
            args=args or [],
        )

    @staticmethod
    def _mythic_shell(session_id: str = "", command: str = "", **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.MYTHIC,
            c2_task_type=C2TaskType.SHELL,
            session_id=session_id,
            args=[command] if command else [],
        )

    @staticmethod
    def _mythic_execute_assembly(session_id: str = "", assembly: str = "", args: list[str] | None = None, **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.MYTHIC,
            c2_task_type=C2TaskType.EXECUTE_ASSEMBLY,
            session_id=session_id,
            assembly=assembly,
            args=args or [],
        )

    @staticmethod
    def _mythic_psexec(session_id: str = "", target: str = "", service: str = "RedStrikeSvc", bin_path: str = "", **kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.MYTHIC,
            c2_task_type=C2TaskType.PSEXEC,
            session_id=session_id,
            args=[target, service, bin_path],
        )

    @staticmethod
    def _mythic_list_sessions(**kwargs) -> CallSpec:
        return CallSpec(
            kind=CallKind.C2,
            c2_backend=C2Backend.MYTHIC,
            c2_task_type=C2TaskType.LIST_SESSIONS,
        )

    # Havoc & Adaptix share the portal transport, so their builders are
    # parameterized by backend instead of repeated per framework.
    def _c2_shell_builder(self, backend: C2Backend):
        def build(session_id: str = "", command: str = "", **kwargs) -> CallSpec:
            return CallSpec(
                kind=CallKind.C2,
                c2_backend=backend,
                c2_task_type=C2TaskType.SHELL,
                session_id=session_id,
                args=[command] if command else [],
            )
        return build

    def _c2_execute_assembly_builder(self, backend: C2Backend):
        def build(session_id: str = "", assembly: str = "", args: list[str] | None = None, **kwargs) -> CallSpec:
            return CallSpec(
                kind=CallKind.C2,
                c2_backend=backend,
                c2_task_type=C2TaskType.EXECUTE_ASSEMBLY,
                session_id=session_id,
                assembly=assembly,
                args=args or [],
            )
        return build

    def _c2_list_sessions_builder(self, backend: C2Backend):
        def build(**kwargs) -> CallSpec:
            return CallSpec(
                kind=CallKind.C2,
                c2_backend=backend,
                c2_task_type=C2TaskType.LIST_SESSIONS,
            )
        return build

    def known(self) -> list[str]:
        return sorted(self._intents)

    def build_spec(
        self,
        intent: str,
        args: dict[str, Any] | None = None,
        *,
        ledger: CredentialLedger | None = None,
        cred_name: str | None = None,
    ) -> CallSpec:
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
        
        result = fn(**filtered)
        if isinstance(result, CallSpec):
            return result
        return CallSpec(kind=CallKind.ARGV, argv=result)

    def build(
        self,
        intent: str,
        args: dict[str, Any] | None = None,
        *,
        ledger: CredentialLedger | None = None,
        cred_name: str | None = None,
    ) -> list[str]:
        spec = self.build_spec(intent, args, ledger=ledger, cred_name=cred_name)
        return spec.to_display_command()


def merge_cred(kwargs: dict[str, Any], cred: Credential) -> dict[str, Any]:
    """Fill username/password/hash/domain from ledger when not already set."""
    out = dict(kwargs)
    out.setdefault("username", cred.username)
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

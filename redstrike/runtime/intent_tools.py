"""Intent → manifest-tool mapping: which TOOL_MANIFEST entry each intent needs.

Used by ``redstrike check --graph`` (graph readiness before a live run) and by
the orchestrator to record the producing tool + version on every journal step.

Mapping rules:
- one intent family → one tool entry (the binary that actually runs);
- ``None`` means no manifest tool: operator-supplied scripts (pyesc17 shim,
  adfspray shim, hybrid_script shim), Windows-native commands (winrs — runs on
  the target host itself), C2 portal tasking (the C2 backend owns delivery), or
  PowerShell built-ins.
"""

from __future__ import annotations

# Full-intent mappings (intent name → manifest tool; None = no on-host tool).
INTENT_TOOLS: dict[str, str | None] = {
    # ADCS
    "certipy.find": "certipy",
    "certipy.req": "certipy",
    "certipy.auth": "certipy",
    "certipy.shadow": "certipy",
    "certipy.template": "certipy",
    "certipy.ca": "certipy",
    "adcs.esc16_audit": "certipy",
    "adcs.pyesc17": None,  # operator-pinned shim (no canonical tool)
    "shadowcreds.certipy_shadow": "certipy",
    "shadowcreds.pywhiskey": None,  # operator-pinned shim
    # LDAP / ACL / enum
    "bloodyad.get_object": "bloodyAD",
    "bloodyad.set_password": "bloodyAD",
    "bloodyad.add_generic_all": "bloodyAD",
    "netexec.gpp_password": "netexec",
    "netexec.laps": "netexec",
    "netexec.rid_brute": "netexec",
    "netexec.smb_exec": "netexec",
    "netexec.winrm_exec": "netexec",
    "netexec.wmi_exec": "netexec",
    # Kerberos / credentials
    "kerbrute.userenum": "kerbrute",
    "kerbrute.spray": "kerbrute",
    "kerbrute.bruteuser": "kerbrute",
    "impacket.secretsdump": "impacket",
    "impacket.getuserspns": "impacket",
    "impacket.wmiexec": "impacket",
    "impacket.smbexec": "impacket",
    "impacket.atexec": "impacket",
    "impacket.ntlmrelayx": "impacket",
    "sql.mssqlclient": "impacket",
    "sql.xp_cmdshell": "impacket",
    "rubeus.asreproast": "rubeus",
    "rubeus.kerberoast": "rubeus",
    "rubeus.asktgt": "rubeus",
    "rubeus.golden": "rubeus",
    "rubeus.silver": "rubeus",
    "rubeus.diamond": "rubeus",
    "rubeus.s4u": "rubeus",
    "mimikatz.logonpasswords": "mimikatz",
    "mimikatz.dcsync": "mimikatz",
    "mimikatz.sam": "mimikatz",
    "coerce.dfir": None,  # operator-staged coercion binaries
    "coerce.petitpotam": None,
    "coerce.shadowcoerce": None,
    "coerce.spoolsample": None,
    "winrs.command": None,  # Windows-native; runs on the target host itself
    "winrs.cmd": None,
    "sharphound.collect": "sharphound",
    "bloodhound.python_collect": "sharphound",
    "sharpsccm.get_naa": "sharpsccm",
    "sharpsccm.get_pxe": "sharpsccm",
    "sharpsccm.client_push": "sharpsccm",
    "sharpsccm.app_deploy": "sharpsccm",
    "sharpsccm.exec_script": "sharpsccm",
    "sharpsccm.exec_cmpivot": "sharpsccm",
    "sharpsccm.adminservice": "sharpsccm",
    # C2 portal tasking — delivery owned by the C2 backend, no on-host tool
    "c2.sliver.execute_assembly": None,
    "c2.sliver.psexec": None,
    "c2.sliver.shell": None,
    "c2.sliver.list_sessions": None,
    "c2.meridian.task": None,
    "c2.meridian.shell": None,
    "c2.meridian.execute_assembly": None,
    "c2.mythic.shell": None,
    "c2.mythic.execute_assembly": None,
    "c2.mythic.psexec": None,
    "c2.mythic.list_sessions": None,
    "c2.havoc.shell": None,
    "c2.havoc.execute_assembly": None,
    "c2.havoc.list_sessions": None,
    "c2.adaptix.shell": None,
    "c2.adaptix.list_sessions": None,
    # Entra ID / hybrid identity
    "entra.az_login": "az",
    "entra.account_show": "az",
    "entra.account_list": "az",
    "entra.signed_in_user": "az",
    "entra.role_assignment_list": "az",
    "entra.graph_query": "az",
    "entra.azurehound_collect": "azurehound",
    "entra.azurehound_collect_jwt": "azurehound",
    "entra.user_role_enum": "azurehound",
    "entra.roadrecon_auth": "roadtools",
    "entra.roadrecon_auth_device_code": "roadtools",
    "entra.roadrecon_auth_token": "roadtools",
    "entra.roadrecon_auth_prt": "roadtools",
    "entra.roadrecon_gather": "roadtools",
    "entra.roadtx_gettokens": "roadtools",
    "entra.roadtx_prt": "roadtools",
    "entra.hybrid_script": None,  # research scripts, operator-staged
    "entra.kerberos_ticket": "aadinternals",
    "entra.prt_token": "aadinternals",
    "entra.monkey365": "monkey365",
    "entra.graphrunner": "graphrunner",
    "entra.adfs_spray": "adfspray",
    "entra.token_artifacts": None,  # PowerShell built-in (Get-ChildItem)
}

# Family fallback for intents not listed above (e.g. future additions to a family).
FAMILY_TOOLS: dict[str, str | None] = {
    "certipy": "certipy",
    "shadowcreds": "certipy",
    "bloodyad": "bloodyAD",
    "netexec": "netexec",
    "kerbrute": "kerbrute",
    "impacket": "impacket",
    "sql": "impacket",
    "rubeus": "rubeus",
    "mimikatz": "mimikatz",
    "sharphound": "sharphound",
    "bloodhound": "sharphound",
    "sharpsccm": "sharpsccm",
    "coerce": None,
    "winrs": None,
    "c2": None,
    "entra": None,  # entra intents are enumerated explicitly above
}


def tools_for_intent(intent: str | None) -> list[str]:
    """Manifest tool names an intent requires (may be empty).

    Unknown intents return [] — ``check --graph`` still lists the node, but no
    tool claim is made (the intent may be operator-supplied).
    """
    if not intent:
        return []
    if intent in INTENT_TOOLS:
        tool = INTENT_TOOLS[intent]
        return [tool] if tool else []
    family = intent.split(".", 1)[0]
    tool = FAMILY_TOOLS.get(family)
    if tool is None:
        return []  # explicit None (no tool) or unknown family
    return [tool]

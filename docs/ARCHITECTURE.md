# RedStrike Architecture

RedStrike is a modular, policy-gated Active Directory, ADCS, and Hybrid Identity assessment framework. It provides two complementary execution models:

1. **Deterministic DAG Graph Engine** — Executes structured, repeatable YAML attack graphs with dependency resolution, conditional branching, and fail-closed verification.
2. **Autonomous LLM Agent Interface (FastMCP / REST API)** — Connects AI models (Claude, GPT-4o, Cursor, Cline) to explore and chain Active Directory attack paths dynamically via typed tool intents and BloodHound graph queries.

---

## High-Level Architecture Diagram

<p align="center">
  <img src="../assets/redstrike-architecture.svg" alt="RedStrike Architecture" width="100%">
</p>

---

## 1. Dual Execution Interface

### 1A. Deterministic DAG Graph Engine
- **CLI Commands:** `redstrike graph run` / `redstrike campaign run`
- **Execution Mechanism:** Reads declarative YAML graphs defining attack nodes, required credentials, execution beachheads, and success markers.
- **Use Cases:**
  - Automated Breach and Attack Simulation (BAS).
  - Continuous compliance validation and Active Directory hardening audits.
  - Repeatable, scripted red team scenarios.
- **Starter Templates (`examples/`):**
  - `generic-ad-recon.yaml`: LDAP user/group enumeration, AS-REP roasting, Kerberoasting, and ADCS discovery.
  - `generic-adcs-audit.yaml`: ESC1–ESC15 template auditing, vulnerable certificate request, and PKINIT NT hash recovery.
  - `generic-privilege-escalation.yaml`: Multi-hop attack chain from initial discovery to Shadow Credentials, ESC4 template ACL takeover, and DRS DCSync.
  - `generic-rbcd-coercion.yaml`: Modern lateral movement chaining MS-RPRN coercion, LDAPS NTLM relaying, Rubeus S4U RBCD ticket impersonation, and SMB execution.

### 1B. Autonomous LLM Agent (FastMCP / REST API)
- **Interface:** FastMCP protocol (`redstrike-mcp`) and REST API (`redstrike-api`).
- **Capabilities Exposed to AI Models:**
  - `bloodhound_query`: Executes parameterized Cypher queries against BloodHound Neo4j databases.
  - `recommend_next_steps`: Heuristic graph-based suggestions for reachable Active Directory privilege paths.
  - `execute_intent`: Atomic execution of typed tool intents (`certipy.find`, `rubeus.s4u`, `coerce.spoolsample`, `impacket.secretsdump`, `kerbrute.spray`, `bloodyad.get_object`).
- **Safety Boundary:** AI agents cannot pass arbitrary shell commands. Every request is parsed as a typed Pydantic intent validated by the policy engine.

---

## 2. 2-Tier Policy Engine & Safety Guardrails

Every operation—whether invoked via CLI graph or MCP agent—must pass through `ScopePolicy.assert_allowed()`:

### Profile 1: `GATED` (Default / Safe)
- Read-only discovery and non-intrusive enumeration run freely (`observe` and `assess` modes).
- High-risk operations pause execution and require human operator approval:
  - **`dcsync`**: Domain Controller directory replication dumps.
  - **`ticket`**: Kerberos Golden/Silver/S4U ticket generation and PKINIT forgery.
  - **`acl_write`**: Object DACL and certificate template permission modifications.
  - **`password_reset`**: Direct user account password resets.
  - **`relay`**: Active NTLM network relay listener engagements.
  - **`forest`**: Cross-forest Kerberos hop and trust abuse.
- Approval command: `redstrike graph approve --gate <name> --engage <id>`.

### Profile 2: `AUTONOMOUS` (Unrestricted AI Agency under Scope)
- Enables all engagement modes (`observe`, `assess`, `validate`, `report`).
- High-risk pauses are lifted, allowing AI agents to explore multi-hop attack graphs autonomously.
- **Strict Scope Boundary:** Enforces `scope.yaml` IP/CIDRs and allowed domain suffixes. Any request outside the defined scope is immediately rejected with a fail-closed policy exception.
- Target-level concurrency limits and cooldown rate-limits prevent Domain Controller lockouts and operational disruption.

---

## 3. Typed Intent Builders (`shell=False`)

RedStrike eliminates shell injection vulnerabilities by constructing argument vectors (`list[str]`) directly for Python's `subprocess.Popen`:

| Builder | Target Surface | Supported Operations |
|---|---|---|
| `NetExecBuilder` | SMB / LDAP / WinRM / WMI | User/computer enumeration, share audit, password policy, RID brute-force, LAPS/GPP dumping, and remote command execution (`smb_exec`, `winrm_exec`) |
| `CertipyBuilder` | ADCS Certificate Services | ESC1–ESC15 discovery (`find`), certificate request (`req`), PKINIT auth (`auth`), template takeover (`template`), shadow credentials (`shadow`) |
| `CoerceBuilder` | Authentication Coercion (RPC/SMB) | MS-RPRN (`spoolsample`/`printerbug`), MS-EFSR (`petitpotam`), DFIRCoerce (`dfircoerce`), and MS-FSRVP (`shadowcoerce`) |
| `RubeusBuilder` | Windows Kerberos | AS-REP roasting, Kerberoasting, TGT request (`asktgt`), S4U RBCD (`s4u`), Golden/Silver/Diamond ticket generation |
| `KerbruteBuilder` | Kerberos Pre-Auth Spraying | Pre-auth user enumeration (`userenum`), rate-limited password spraying (`passwordspray`), account brute-force (`bruteuser`) |
| `ImpacketBuilder` | Replication & Relay Suite | DCSync replication dumps (`secretsdump`), Kerberoasting (`getuserspns`), WMI/SMB/Task execution, and NTLM relaying (`ntlmrelayx`) |
| `BloodyADBuilder` | LDAP & Active Directory Objects | Object query (`get_object`), password reset (`set_password`), DACL grant (`add_generic_all`) |
| `ShadowCredentialsBuilder` | Key Credential Links | Certipy and KeyCredentialLink shadow credential injection |
| `SharpSCCMBuilder` | Configuration Manager (SCCM/MECM) | NAA credential recovery, PXE boot media extraction, CMPivot queries, Application deployment |
| `SharpHoundBuilder` | BloodHound Telemetry | Windows `SharpHound.exe` and Linux `bloodhound-python` relationship collectors |
| `AdcsModernBuilder` | 2024–2026 Modern ADCS Vectors | ESC16 weak mapping audits and ESC17 (`pyesc17`) cross-realm certificate abuse |
| `SqlBuilder` | MSSQL Database Instances | Linked database queries, `xp_cmdshell` execution |
| `WinRSBuilder` | Windows Remote Management | WinRM / WinRS command execution |
| `C2Adapters` | C2 Implants (Sliver & Meridian) | In-memory .NET `execute_assembly` (`Rubeus`, `SharpHound`), shell commands, PsExec lateral movement, covert DNS TXT tunneling |

**Secret Redaction Invariant:** All builders automatically mask plaintext passwords, NT hashes, and Kerberos keys in logging, telemetry streams, and generated report artifacts.

---

## 4. Multi-Platform Execution Transport

RedStrike seamlessly dispatches commands across heterogeneous infrastructure:

1. **Linux / Kali Local:** Native subprocess execution for Linux-native tooling (`netexec`, `certipy`, `bloodyAD`, `impacket`).
2. **Windows Beachhead:** Transparent OpenSSH wrapper or native PowerShell execution for Windows binaries (`Rubeus.exe`, `SharpSCCM.exe`, `Mimikatz.exe`). Configured via `REDSTRIKE_WS01_HOST`, `REDSTRIKE_WS01_USER`, and `REDSTRIKE_WS01_SSH_KEY`.
3. **C2 Implant Execution (via C2Stack):** Dispatches in-memory .NET tools and lateral movement directly through active C2 sessions via `CallSpec` primitives:
   - **Sliver**: In-memory assembly execution and interactive control over gRPC/CLI (`127.0.0.1:31337`).
   - **Meridian**: Custom Go stdlib implant with X25519/AES-GCM encryption and chunked DNS TXT covert egress over UDP 5353 (`http://127.0.0.1:8080`).
4. **Cloud & Azure (Entra ID):** Extensible runner interface for Microsoft Graph API queries, Az CLI cmdlets, Azure AD Connect sync abuse, and hybrid identity token replay.

---

## 5. Fail-Closed Verification & Teardown Queue

### Verification Pipeline
1. **Return Code Inspection:** Process exit code must be `0` (or expected return code).
2. **Pattern Verification:** Analyzes process output against known tool failure strings (`KDC_ERR_C_PRINCIPAL_UNKNOWN`, `Access Denied`, `STATUS_LOGON_FAILURE`).
3. **Cryptographic Success Markers:** Steps can declare deterministic success markers (`RECON_01_USERS_OK`) written to stdout upon confirmed execution.

### Teardown Queue
Tracks all post-exploitation state modifications:
- Generated certificates and `.pfx` files.
- Injected `msDS-KeyCredentialLink` shadow credentials.
- Modified Active Directory DACLs and template permissions.
- Staged persistence artifacts.

The orchestrator executes teardown tasks in reverse chronological order at engagement conclusion.

---

## 6. Credential Ledger (Single Source of Truth)

The `CredentialLedger` indexes and tracks all discovered credentials during an engagement:
- User accounts and plaintext passwords.
- NT and LM password hashes.
- Kerberos TGT and TGS tickets (base64 or `.kirbi` file paths).
- Active Directory Certificate Services `.pfx` certificates.
- Discovered Service Principal Names (SPNs) and delegation relationships.

Subsequent attack nodes in a graph (or follow-up LLM agent steps) dynamically pull credentials from the ledger by name (`requires_cred: "domain_admin_tgt"`).

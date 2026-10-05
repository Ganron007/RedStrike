# RedStrike

<p align="center">
  <img src="assets/redstrike-logo.svg" alt="RedStrike" width="620">
</p>

<p align="center">
  <a href="https://github.com/Ganron007/RedStrike/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Ganron007/RedStrike/ci.yml?label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Python-%E2%89%A53.10-blue.svg" alt="Python: >=3.10">
  <img src="https://img.shields.io/badge/Version-0.6.0-blue.svg" alt="Version: 0.6.0">
</p>

> [!IMPORTANT]
> **Authorized use only.** RedStrike is an offensive security assessment framework. Use it **only** for
> authorized security assessments against systems and accounts you are explicitly permitted
> to test. Unauthorized scanning, enumeration, or access attempts are illegal. The authors
> and contributors accept no liability for any misuse or damage.

RedStrike is an agentic Active Directory, ADCS, and Hybrid Identity assessment framework combining a **deterministic DAG attack-graph engine** with an **autonomous LLM agent (FastMCP)**, typed command builders (`shell=False`), scope policy, an HMAC-sealed credential ledger (optional AES-256-GCM at rest), human-in-the-loop safety gates, and **deep C2 framework integration via [C2Stack](https://github.com/Ganron007/C2Stack)** for in-memory implant execution (Sliver, Meridian, Mythic, Havoc, and Adaptix), covert DNS tunneling, and cross-platform lateral movement.

Bring your own target environments, attack graphs, and seeds. RedStrike ships fully standalone with generic starter templates in `examples/` and native dual-mode execution (direct standard vs C2-enabled).

| | |
|---|---|
| Package | `redstrike` |
| Commands | `redstrike` (`graph` / `campaign` / `report` / `c2` / `stage` / `console` / `check`) · `redstrike-api` · `redstrike-mcp` |
| C2 Integration | Native **[C2Stack](https://github.com/Ganron007/C2Stack)** (Sliver, Meridian, Mythic, Havoc & Adaptix — fleet view, server-side builds, staging, tasking) |
| Generic Graph Templates | [`generic-ad-recon.yaml`](examples/generic-ad-recon.yaml) · [`generic-adcs-audit.yaml`](examples/generic-adcs-audit.yaml) · [`generic-privilege-escalation.yaml`](examples/generic-privilege-escalation.yaml) · [`generic-rbcd-coercion.yaml`](examples/generic-rbcd-coercion.yaml) · [`generic-entra-recon.yaml`](examples/generic-entra-recon.yaml) |
| Architecture & Modes | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Practice & Operator Guide | [`docs/PRACTICE-GUIDE.md`](docs/PRACTICE-GUIDE.md) |
| Setup & Toolchain | [`docs/SETUP.md`](docs/SETUP.md) |
| Security & OPSEC | [`docs/SECURITY.md`](docs/SECURITY.md) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

---

## Dual Execution Engine & 2-Tier Safety Profiles

RedStrike bridges deterministic reproducibility with adaptive AI agency through two execution interfaces, two execution policy profiles, and dual transport modes (Direct vs C2-Enabled via [C2Stack](https://github.com/Ganron007/C2Stack)):

```
                          ┌────────────────────────────────────────────────────────┐
                          │                  REDSTRIKE INTERFACES                  │
                          └───────────────────────────┬────────────────────────────┘
                                                      │
                         ┌────────────────────────────┴────────────────────────────┐
                         ▼                                                         ▼
         ┌──────────────────────────────┐                          ┌──────────────────────────────┐
         │ 1A. Deterministic DAG Engine │                          │ 1B. Autonomous LLM Agent     │
         │  • redstrike graph run       │                          │  • FastMCP / REST API        │
         │  • YAML attack graphs        │                          │  • BloodHound Cypher queries │
         │  • Repeatable BAS & audits   │                          │  • Adaptive multi-hop goals  │
         └───────────────┬──────────────┘                          └──────────────┬───────────────┘
                         │                                                         │
                         └────────────────────────────┬────────────────────────────┘
                                                      ▼
                          ┌────────────────────────────────────────────────────────┐
                          │               2-TIER POLICY ENGINE                     │
                          │                                                        │
                          │  [GATED Profile] (Default / Safe)                      │
                          │   • Read-only discovery runs freely                    │
                          │   • High-risk jumps PAUSE for operator approval (HITL) │
                          │                                                        │
                          │  [AUTONOMOUS Profile] (Unrestricted Agency)            │
                          │   • AI explores multi-hop paths toward objectives      │
                          │   • Strictly bounded by scope.yaml IP/domain rules     │
                          └───────────────────────────┬────────────────────────────┘
                                                      ▼
                           ┌────────────────────────────────────────────────────────┐
                           │      TYPED BUILDERS, TRANSPORTS & C2STACK INTEGRATION  │
                           │   • Linux/Kali: nxc, certipy, bloodyAD, impacket, coerce│
                           │   • Windows Beachhead: Rubeus, SharpSCCM, Mimikatz     │
                           │   • C2Stack Implants: Sliver, Meridian, Mythic,     │
                           │     Havoc & Adaptix (Flight Control portal :8000)   │
                           │   • Cloud / Entra ID: Microsoft Graph API, Az CLI      │
                           └────────────────────────────────────────────────────────┘
```

### 1. Execution Profiles
- **`GATED` Mode (Default / Safe):** Reconnaissance, discovery, and non-intrusive checks execute freely. High-risk operations (**DCSync**, **Ticket/Certificate Forgery**, **ACL Writes**, **Password Resets**) pause execution and wait for human operator approval (`redstrike graph approve --gate <name>`).
- **`AUTONOMOUS` Mode (Unrestricted under Scope):** Allows AI agents (or automated pipelines) to explore and chain multi-hop paths without manual pauses, strictly enforced by `scope.yaml` IP/CIDR blocks, domain suffixes, and cooldown limits.

### 2. Execution Interfaces & Dual-Mode Transport
- **Deterministic DAG Graph Engine:** Run predefined or custom YAML attack graphs with dependency tracking, condition evaluation, and fail-closed verification (`redstrike graph run --graph <file.yaml>`).
- **Autonomous LLM Agent (FastMCP):** Connect AI coding assistants (Claude Desktop, Cursor, Cline, custom agent swarms) via FastMCP to query BloodHound graphs, request next-step recommendations, and invoke typed intent tools.
- **Direct Mode (Default):** Standard execution using local subprocesses or transparent OpenSSH wrapping without any external C2 dependencies.
- **C2-Enabled Mode (`--c2`):** Routes post-exploitation tooling in-memory through active **[C2Stack](https://github.com/Ganron007/C2Stack)** implant sessions (Sliver, Meridian, Mythic, Havoc, or Adaptix), executing `.NET` binaries via CLR hosting or running commands over covert DNS TXT tunnels.

---

## Architecture

<p align="center">
  <img src="assets/redstrike-architecture.svg" alt="RedStrike Architecture" width="100%">
</p>

1. **Ingress** — CLI (`redstrike graph`), HTTP (`/ad/*`, `/jobs`, `/c2/*`), or FastMCP tools (`redstrike-mcp`).
2. **Auth & Trust** — Local loopback trust by default; `X-API-Key` required for remote interfaces.
3. **Policy & Scope** — `ScopePolicy.assert_allowed` validates target IP/CIDRs and domains against `scope.yaml`.
4. **HITL Gatekeeper** — Pauses high-risk operations in `gated` profile until the operator approves (append-only approvals log in engagement state).
5. **Typed Builders (`shell=False`)** — Generates secure `list[str]` argument vectors or `CallSpec` C2 descriptors; eliminates shell injection.
6. **Cross-Platform & C2 Transport** — Direct Kali execution, OpenSSH to domain-joined Windows beachheads, [C2Stack](https://github.com/Ganron007/C2Stack) implant execution (Sliver, Meridian, Mythic, Havoc & Adaptix), or Cloud Graph APIs.
7. **Verification & Teardown** — Validates exit codes, output patterns, and success markers; graph nodes declare `teardown:` cleanup commands that are registered on success and executed with `redstrike campaign teardown --execute`.
8. **Credential Ledger (SSoT)** — Automatically indexes discovered NT hashes, Kerberos tickets, and privileges.

---

## Quick Start

### 1. Installation

```bash
git clone https://github.com/Ganron007/RedStrike.git
cd RedStrike
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev,mcp]"
```

### 2. Configure Scope

Copy the template and define your authorized targets:

```bash
cp examples/scope.example.yaml scope.yaml
# Edit scope.yaml to include your lab domain and domain controller IPs
```

### 3. Verify Environment

```bash
redstrike check
```

---

## Usage Examples

### Option A: Run a Generic Attack Graph

Execute one of the bundled generic Active Directory graphs:

```bash
# 1. Run Active Directory Reconnaissance Graph (dry run; --engage/--beachhead required)
redstrike graph run --engage default --beachhead windows --graph examples/generic-ad-recon.yaml --phase 1.0

# 2. Run ADCS Audit & Template Escalation Graph
redstrike graph run --engage default --beachhead windows --graph examples/generic-adcs-audit.yaml --phase 2-3

# 3. Approve a paused HITL gate (in Gated mode)
redstrike graph approve --engage default --gate ticket
```

Live execution (`--execute`) requires a scope policy: nodes that declare targets are checked against `--scope <file>` (or `REDSTRIKE_SCOPE`) and blocked fail-closed without one. `--resume` skips nodes already verified live in the engagement; `--stop-on-failure` halts at the first live step that fails verification.

### Option B: C2-Enabled Mode (via [C2Stack](https://github.com/Ganron007/C2Stack))

Dispatch post-exploitation tasks directly through in-memory C2 implants (Sliver, Meridian, Mythic, Havoc, or Adaptix) without dropping executables to disk:

```bash
# 0. (Optional) Launch C2Stack services from https://github.com/Ganron007/C2Stack
cd C2Stack/Docker && ./docker-bootstrap.ps1 -All   # or: ./docker-bootstrap.sh --all

# 1. Run campaign graph in C2 mode with Sliver backend (in-memory .NET assembly execution)
redstrike graph run --phase 1-3 --c2 --c2-backend sliver --c2-session <session-id>

# 2. Run with Meridian C2 backend (covert DNS TXT tunneling / HTTP; driven via its container CLI)
redstrike graph run --phase 1-3 --c2 --c2-backend meridian \
  --c2-endpoint "docker exec -i c2stack-meridian-1 meridian"

# 3. Havoc / Adaptix are driven through C2Stack's Flight Control portal API (port 8000)
redstrike graph run --phase 1-3 --c2 --c2-backend havoc --c2-endpoint http://127.0.0.1:8000
```

Available backends: `sliver` (CLI, `execute-assembly`), `meridian` (container CLI, DNS TXT egress), `mythic` (REST webhooks, Apollo agents), `havoc` and `adaptix` (C2Stack Flight Control portal at `http://127.0.0.1:8000`, set `C2STACK_PORTAL_URL` to override). Omit `--c2-session` to auto-select the first live session, or use `--c2-backend auto` to pick the first framework that has one.

### Option C: Full C2Stack Operations (`redstrike c2`)

Build implants server-side, stage files, and inspect the fleet — all through C2Stack's Flight Control API:

```bash
redstrike c2 status                              # container health, ports, URI prefixes
redstrike c2 sessions                            # unified fleet across all five frameworks
redstrike c2 capabilities                        # live per-framework capability probe
redstrike c2 catalogues --backend havoc          # tasking vocabulary per framework
redstrike c2 build --backend sliver --retrieve --out ./impl.exe   # garble build + docker cp
redstrike c2 build --backend havoc   --out ./demon.exe            # Demon (30-90s)
redstrike c2 build --backend adaptix --listener cadre_http --out ./beacon.exe
redstrike c2 build --backend mythic  --out ./apollo.exe           # async build, polled + downloaded
redstrike c2 stage ./payload.o                   # Mythic agent_file_id (COFF/assembly tasking)
redstrike c2 probe --path /gateway/v1/telemetry  # redirector: decoy vs backend routing
redstrike c2 task --backend havoc --session <id> --command "whoami"   # task ANY framework
```

Note: Adaptix 0.7/Demon builds are compiled server-side inside the C2Stack containers; retrieval for Sliver uses `docker cp` and Mythic builds are queued and polled (dotnet takes minutes).

### Option D: Reporting, Teardown & Dashboard

```bash
redstrike report --engage default                      # markdown deliverable (masked secrets)
redstrike report --engage default --format json --out report.json
redstrike report --engage default --include-secrets    # raw passwords/hashes (operator choice)
redstrike campaign teardown --engage default           # list pending cleanup actions
redstrike campaign teardown --engage default --execute # run them (nodes declare teardown: in the graph)
redstrike console --engage default                     # read-only live dashboard (--watch to follow)
```

Tools are provided, not vendored: `redstrike check` prints per-tool install recipes and probes versions (locally, inside a container, or on the Windows beachhead), `REDSTRIKE_LINUX_CONTAINER=c2stack-kali` runs Linux tooling via `docker exec` in C2Stack's Kali workstation, `REDSTRIKE_WS01_TOOLS_DIR` lets Windows intents resolve bare tool names on the target, and `redstrike stage --download` fetches **sha256-pinned** upstream releases (SharpHound/mimikatz/SharpSCCM) onto the beachhead (Rubeus upstream is source-only — `--file` with recorded hash). See `docs/SETUP.md` → *Tool provisioning*.

The credential ledger is HMAC-SHA256 sealed (tamper-evident; legacy files are re-sealed on next save, `REDSTRIKE_LEDGER_UNVERIFIED=1` is the recovery override). Install the `crypto` extra and set `REDSTRIKE_LEDGER_ENCRYPT=1` for AES-256-GCM encryption at rest.

### Option E: Entra ID / Hybrid Identity (Phase 9)

Entra ID intents ride the same engine (typed argv, scope targets, HITL gates, ledger, verification):

```bash
# Cloud nodes are scope-gated: add allowed_tenants / allowed_cloud_domains to scope.yaml
redstrike graph run --engage tenant-a --beachhead linux --phase 9-9.3   --graph examples/generic-entra-recon.yaml --seed entra-seed.json
```

- Intents: `entra.az_login`, `entra.account_show`, `entra.graph_query` (az rest), `entra.azurehound_collect[_cli_auth]`, `entra.user_role_enum`, `entra.roadrecon_auth[_token|_prt]`, `entra.roadrecon_gather`, `entra.kerberos_ticket` (Seamless-SSO/cloud-Kerberos, **HITL `cloud_takeover`**), `entra.prt_token`, `entra.adfs_spray` (raw-args shim — no canonical tool exists).
- Flags verified against upstream docs **and the installed CLIs** during live verification (az 2.82.0 `az rest --help`; AADInternals 0.9.7 cmdlet parameters — exact match).
- JSON-emitting tools verify structurally: a node can assert `success_json: {path: tenantId, equals: <guid>}` instead of a stdout marker.
- Tokens are first-class ledger material (`cred_type: token`) and JWTs/`access_token=`/`Bearer` values are scrubbed from every derived output.

### Option C: Start Autonomous LLM FastMCP Server

Connect RedStrike to Claude Desktop, Cursor, or your agent swarm:

```bash
# 1. Start the RedStrike API
export REDSTRIKE_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
redstrike-api --scope scope.yaml --profile autonomous --api-key "$REDSTRIKE_API_KEY" --host 127.0.0.1 --port 8890

# 2. Launch the FastMCP Bridge
redstrike-mcp --api http://127.0.0.1:8890
```

#### FastMCP Client Configuration

**Claude Desktop (`claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "redstrike": {
      "command": "redstrike-mcp",
      "args": ["--api", "http://127.0.0.1:8890"]
    }
  }
}
```

**Cursor / VS Code (`.vscode/mcp.json`):**
```json
{
  "mcpServers": {
    "redstrike": {
      "command": "redstrike-mcp",
      "args": ["--api", "http://127.0.0.1:8890"]
    }
  }
}
```

---

## Safety & Operational Guardrails

- **Default Profile (`gated`):** High-risk actions require explicit human operator approval.
- **Strict Scope Enforcement:** Out-of-scope targets and domains are rejected before any network traffic is generated.
- **Fail-Closed Verification:** Steps require non-zero return codes, expected markers, and absence of failure patterns.
- **Teardown Queue:** Nodes declare their own reversible cleanup (`teardown: {description, command}`); verified executions register the action and `redstrike campaign teardown` lists or executes it (operator-gated).
- **Zero Shell Injection:** All tool invocations use structured argument lists (`shell=False`) with real-time credential redaction in logs and streams.

---

## License

RedStrike is released under the [MIT License](LICENSE).

Copyright (c) 2026 RedStrike

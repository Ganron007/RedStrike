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

RedStrike is an agentic assessment framework for **Active Directory, ADCS, and Hybrid Identity (Entra ID)**. It gives you two ways to run the same engine:

- A **deterministic DAG engine** (`redstrike graph` / `redstrike campaign`) that executes declarative YAML attack graphs — repeatable, auditable, built for breach-and-attack simulation and hardening audits.
- An **autonomous LLM agent** (`redstrike-mcp`, FastMCP) that plans and executes multi-hop attack paths on its own.

Both run on the same safety rails: typed command builders (`shell=False`, no shell injection), a `scope.yaml` policy that fails closed on out-of-scope targets, a tamper-evident credential ledger, and human-in-the-loop gates on high-risk steps. Post-exploitation can run directly (Kali tools + Windows over SSH) or in-memory through C2 implants — Sliver, Meridian, Mythic, Havoc, and Adaptix — via [C2Stack](https://github.com/Ganron007/C2Stack).

Bring your own target environments, attack graphs, and seeds. RedStrike ships standalone with generic starter templates in `examples/`.

| | |
|---|---|
| Package | `redstrike` |
| Commands | `redstrike` (`graph` / `campaign` / `report` / `c2` / `stage` / `install` / `replay` / `api` / `console` / `ui` / `check`) · `redstrike-api` · `redstrike-mcp` |
| C2 Integration | Native **[C2Stack](https://github.com/Ganron007/C2Stack)** (Sliver, Meridian, Mythic, Havoc & Adaptix — fleet view, server-side builds, staging, tasking) |
| Generic Graph Templates | [`generic-ad-recon.yaml`](examples/generic-ad-recon.yaml) · [`generic-adcs-audit.yaml`](examples/generic-adcs-audit.yaml) · [`generic-privilege-escalation.yaml`](examples/generic-privilege-escalation.yaml) · [`generic-rbcd-coercion.yaml`](examples/generic-rbcd-coercion.yaml) · [`generic-entra-recon.yaml`](examples/generic-entra-recon.yaml) |
| Architecture & Modes | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Practice & Operator Guide | [`docs/PRACTICE-GUIDE.md`](docs/PRACTICE-GUIDE.md) |
| Setup & Toolchain | [`docs/SETUP.md`](docs/SETUP.md) |
| Security & OPSEC | [`docs/SECURITY.md`](docs/SECURITY.md) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

---

## How It Works

Two ways to drive the engine, two safety profiles, and two transports — all on the same typed builders:

```
┌──────────────────────────────────┐    ┌──────────────────────────────────┐
│ Deterministic DAG Engine         │    │ Autonomous LLM Agent             │
│ redstrike graph / campaign run   │    │ FastMCP / REST API               │
│ YAML attack graphs, repeatable   │    │ adaptive multi-hop goals,        │
│ BAS & hardening audits           │    │ BloodHound Cypher queries        │
└─────────────────┬────────────────┘    └─────────────────┬────────────────┘
                  └───────────────────┬───────────────────┘
                                      │
                                      ▼
        ┌────────────────────────────────────────────────────────────┐
        │ SAFETY PROFILES                                            │
        │ GATED (default): high-risk steps pause                     │
        │ for operator approval (HITL)                               │
        │ AUTONOMOUS: no pauses, strictly                            │
        │ bounded by scope.yaml targets                              │
        └─────────────────────────────┬──────────────────────────────┘
                                      │
                                      ▼
        ┌────────────────────────────────────────────────────────────┐
        │ WHERE TOOLS RUN                                            │
        │ Direct: Kali tools + Windows over SSH                      │
        │ C2: Sliver / Meridian / Mythic / Havoc /                   │
        │      Adaptix in-memory implants (C2Stack)                  │
        │ Cloud: Azure CLI + Microsoft Graph API                     │
        └────────────────────────────────────────────────────────────┘
```

### 1. Execution Profiles
- **`GATED` Mode (Default / Safe):** Reconnaissance, discovery, and non-intrusive checks execute freely. High-risk operations (**DCSync**, **Ticket/Certificate Forgery**, **ACL Writes**, **Forest Trusts**, **Persistence**, **Site Takeover**, **Cloud Takeover**) pause execution and wait for human operator approval (`redstrike graph approve --gate <name>`).
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

1. **Ingress** — CLI (`redstrike {graph|campaign} {run|start|approve|status|stream|teardown|check}`, `redstrike c2 …`, `redstrike replay`, `redstrike ui`), HTTP (`/ad/*`, `/jobs`, `/campaign/*`, `/builders/*`, `/c2/*`), or FastMCP tools (`redstrike-mcp`).
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
redstrike graph run --engage default --beachhead windows --phase 1-3 --c2 --c2-backend sliver --c2-session <session-id>

# 2. Run with Meridian C2 backend (covert DNS TXT tunneling / HTTP; driven via its container CLI)
redstrike graph run --engage default --beachhead windows --phase 1-3 --c2 --c2-backend meridian \
  --c2-endpoint "docker exec -i c2stack-meridian-1 meridian"

# 3. Havoc / Adaptix are driven through C2Stack's Flight Control portal API (port 8000)
redstrike graph run --engage default --beachhead windows --phase 1-3 --c2 --c2-backend havoc --c2-endpoint http://127.0.0.1:8000
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

Note: Adaptix/Demon builds are compiled server-side inside the C2Stack containers; retrieval for Sliver uses `docker cp` and Mythic builds are queued and polled (dotnet takes minutes).

### Option D: Reporting, Teardown & Dashboard

```bash
redstrike report --engage default                      # markdown deliverable (masked secrets)
redstrike report --engage default --format json --out report.json
redstrike report --engage default --include-secrets    # raw passwords/hashes (operator choice)
redstrike campaign teardown --engage default           # list pending cleanup actions
redstrike campaign teardown --engage default --execute # run them (nodes declare teardown: in the graph)
redstrike console --engage default                     # read-only live dashboard (--watch to follow)
```

Tools are provided, not vendored: `redstrike check` prints per-tool install recipes and probes versions (locally, inside a container, or on the Windows beachhead), `REDSTRIKE_LINUX_CONTAINER=c2stack-kali` runs Linux tooling via `docker exec` in C2Stack's Kali workstation, `REDSTRIKE_WINDOWS_TOOLS_DIR` lets Windows intents resolve bare tool names on the target, and `redstrike stage --download` fetches **sha256-pinned** upstream releases (SharpHound/mimikatz/SharpSCCM) onto the beachhead (Rubeus upstream is source-only — `--file` with recorded hash). See `docs/SETUP.md` → *Tool provisioning*.

The credential ledger is HMAC-SHA256 sealed (tamper-evident; legacy files are re-sealed on next save, `REDSTRIKE_LEDGER_UNVERIFIED=1` is the recovery override). Install the `crypto` extra and set `REDSTRIKE_LEDGER_ENCRYPT=1` for AES-256-GCM encryption at rest.

### Option E: Entra ID / Hybrid Identity

The bundled cloud-identity graph runs on the same engine — typed commands, scope checks, HITL gates, ledger, verification:

```bash
# 1. Allow your tenant in scope.yaml (cloud nodes fail closed without it):
#      allowed_tenants: [contoso.onmicrosoft.com]
# 2. Seed an operator credential the graph can use (see examples/seed.example.json)
redstrike graph run --engage tenant-a --beachhead linux --phase 1-4 \
  --graph examples/generic-entra-recon.yaml --seed entra-seed.json
```

- **23 `entra.*` intents** in four families:
  - **Azure CLI & Microsoft Graph** — `entra.az_login`, `entra.account_show`, `entra.account_list`, `entra.signed_in_user`, `entra.role_assignment_list`, `entra.token_artifacts`, `entra.graph_query`, `entra.user_role_enum`
  - **AzureHound collection** — `entra.azurehound_collect`, `entra.azurehound_collect_jwt`
  - **ROADtools / ROADrecon** — `entra.roadrecon_auth` (plus `_device_code` / `_token` / `_prt` variants), `entra.roadrecon_gather`, `entra.roadtx_gettokens`, `entra.roadtx_prt`, `entra.hybrid_script`
  - **Hybrid-identity attacks** — `entra.kerberos_ticket` (Seamless-SSO, **HITL `cloud_takeover`**), `entra.prt_token`, `entra.adfs_spray`, `entra.monkey365`, `entra.graphrunner`
- Tool builders track the upstream CLIs; `redstrike check` probes installed versions and warns on drift. Cloud steps can verify against structured JSON output (`success_json`) instead of stdout markers, and harvested tokens land in the ledger as `cred_type: token` with JWT/Bearer values scrubbed from derived output.
- Install recipes for the cloud tooling: [SETUP.md](docs/SETUP.md) → *Entra ID / hybrid tooling*.

### Option F: Start Autonomous LLM FastMCP Server

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

### Option G: Web Cockpit (`redstrike ui`)

Zero-install browser command center — the API serves a pre-built static SPA (no Node.js needed):

```bash
redstrike ui        # starts the API if needed, opens http://127.0.0.1:8890/ui/
```

The cockpit renders the attack graph (Cytoscape) with live node states (pending / executing / verified / gated / failed), a one-click HITL approval modal when a high-risk step pauses, the masked credential ledger (reveals are audited in the engagement state), and the SSE journal stream. Point it at any graph with `POST /campaign/graph`; live state comes from `POST /campaign/status` and `GET /campaign/events/{engagement}`.

### Reference agent loop (`examples/agent/redstrike_agent.py`)

A ~120-line example of driving RedStrike the way an LLM agent would — over the same gated REST endpoints an operator uses, so scope policy, HITL gates, and the audit trail apply identically. Ships with a deterministic offline stub (always picks the top recommendation — the replay/eval regression target) plus an optional Anthropic provider:

```bash
python examples/agent/redstrike_agent.py --api http://127.0.0.1:8890 --engage demo --offline
```

The agent **never bypasses a gate**: when a run pauses for approval, the loop stops and reports. Pair it with `redstrike replay` for a repeatable eval: record a live run (`--record-replay`), then check the agent reaches the same verified end-state.

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

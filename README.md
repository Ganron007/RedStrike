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

RedStrike is an agentic Active Directory, ADCS, and Hybrid Identity assessment framework combining a **deterministic DAG attack-graph engine** with an **autonomous LLM agent (FastMCP)**, typed command builders (`shell=False`), scope policy, a cryptographic credential ledger, human-in-the-loop safety gates, and cross-platform transport (Linux, Windows beachheads, and Cloud).

Bring your own target environments, attack graphs, and seeds. RedStrike ships fully standalone with generic starter templates in `examples/`.

| | |
|---|---|
| Package | `redstrike` |
| Commands | `redstrike` (`graph` / `campaign` / `console` / `check`) · `redstrike-api` · `redstrike-mcp` |
| Generic Graph Templates | [`examples/generic-ad-recon.yaml`](examples/generic-ad-recon.yaml) · [`examples/generic-adcs-audit.yaml`](examples/generic-adcs-audit.yaml) · [`examples/generic-privilege-escalation.yaml`](examples/generic-privilege-escalation.yaml) |
| Architecture & Modes | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Practice & Operator Guide | [`docs/PRACTICE-GUIDE.md`](docs/PRACTICE-GUIDE.md) |
| Setup & Toolchain | [`docs/SETUP.md`](docs/SETUP.md) |
| Security & OPSEC | [`docs/SECURITY.md`](docs/SECURITY.md) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

---

## Dual Execution Engine & 2-Tier Safety Profiles

RedStrike bridges deterministic reproducibility with adaptive AI agency through two execution interfaces and two execution policy profiles:

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
                          │           TYPED BUILDERS & CROSS-PLATFORM              │
                          │   • Linux Kali: netexec, certipy, bloodyAD, impacket   │
                          │   • Windows Beachhead: Rubeus, SharpSCCM, Mimikatz     │
                          │   • Cloud / Entra ID: Microsoft Graph API, Az CLI      │
                          └────────────────────────────────────────────────────────┘
```

### 1. Execution Profiles
- **`GATED` Mode (Default / Safe):** Reconnaissance, discovery, and non-intrusive checks execute freely. High-risk operations (**DCSync**, **Ticket/Certificate Forgery**, **ACL Writes**, **Password Resets**) pause execution and wait for human operator approval (`redstrike graph approve --gate <name>`).
- **`AUTONOMOUS` Mode (Unrestricted under Scope):** Allows AI agents (or automated pipelines) to explore and chain multi-hop paths without manual pauses, strictly enforced by `scope.yaml` IP/CIDR blocks, domain suffixes, and cooldown limits.

### 2. Execution Interfaces
- **Deterministic DAG Graph Engine:** Run predefined or custom YAML attack graphs with dependency tracking, condition evaluation, and fail-closed verification (`redstrike graph run --graph <file.yaml>`).
- **Autonomous LLM Agent (FastMCP):** Connect AI coding assistants (Claude Desktop, Cursor, Cline, custom agent swarms) via FastMCP to query BloodHound graphs, request next-step recommendations, and invoke typed intent tools.

---

## Architecture

<p align="center">
  <img src="assets/redstrike-architecture.svg" alt="RedStrike Architecture" width="100%">
</p>

1. **Ingress** — CLI (`redstrike graph`), HTTP (`/ad/*`, `/jobs`), or FastMCP tools (`redstrike-mcp`).
2. **Auth & Trust** — Local loopback trust by default; `X-API-Key` required for remote interfaces.
3. **Policy & Scope** — `ScopePolicy.assert_allowed` validates target IP/CIDRs and domains against `scope.yaml`.
4. **HITL Gatekeeper** — Pauses high-risk operations in `gated` profile until cryptographically approved.
5. **Typed Builders (`shell=False`)** — Generates secure `list[str]` argument vectors; eliminates shell injection.
6. **Cross-Platform Transport** — Direct Kali execution, OpenSSH to domain-joined Windows beachheads, or Cloud Graph APIs.
7. **Verification & Teardown** — Validates exit codes, output patterns, and success markers; tracks modified objects in `TeardownQueue` for cleanup.
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
# 1. Run Active Directory Reconnaissance Graph (Dry-run)
redstrike graph run --graph examples/generic-ad-recon.yaml --phase 1.0

# 2. Run ADCS Audit & Template Escalation Graph
redstrike graph run --graph examples/generic-adcs-audit.yaml --phase 2-3

# 3. Approve a paused HITL gate (in Gated mode)
redstrike graph approve --gate ticket --engage default
```

### Option B: Start Autonomous LLM FastMCP Server

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
- **Teardown Queue:** Tracks created certificates, shadow credentials, and ACL modifications for automated post-assessment cleanup.
- **Zero Shell Injection:** All tool invocations use structured argument lists (`shell=False`) with real-time credential redaction in logs and streams.

---

## License

RedStrike is released under the [MIT License](LICENSE).

Copyright (c) 2026 RedStrike

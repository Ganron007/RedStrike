# RedStrike Practice & Study Guide
### *A Hands-On Manual for Agentic Active Directory Security, Policy-Gated MCP Tooling, and Campaign Orchestration*

---

## 1. Executive Overview & Mental Model

Modern Active Directory (AD) and Active Directory Certificate Services (ADCS) environments present vast, graph-theoretic attack surfaces. In traditional penetration testing, operators manually execute disconnected command-line tools (`NetExec`, `Certipy`, `Rubeus`, `bloodyAD`), risking command injection, out-of-scope targets, and uncoordinated privilege jumps.

**RedStrike** bridges modern **Autonomous AI Agents (LLMs)** with **Deterministic, Safe Active Directory Execution**:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    THE REDSTRIKE MENTAL MODEL                                    │
├──────────────────────────────────────┬───────────────────────────────────────────────────────────┤
│ 🧠 THE BRAIN (Autonomous LLM)        │ 🛡️ THE BODY (RedStrike Policy & Execution Engine)          │
├──────────────────────────────────────┼───────────────────────────────────────────────────────────┤
│ • Analyzes domain topology & graphs  │ • Enforces hard boundaries (`scope.yaml` validation)     │
│ • Plans strategic kill-chains        │ • ✋ Pauses for Human Operator approval on high-risk jumps│
│ • Selects structured intent tools    │ • Generates typed subprocess `argv` (`shell=False`)       │
│ • Consumes factual `EvidenceRecord`  │ • Masks passwords and NT hashes in real time              │
└──────────────────────────────────────┴───────────────────────────────────────────────────────────┘
```

---

## 2. Infrastructure & Tool Setup

### Step 1: Verification with `redstrike check`
Run the built-in diagnostic tool to verify environment readiness:
```bash
redstrike check
```
- **Core (All `ok`)**: Dry-run simulation and API are ready out-of-the-box with zero third-party tool dependencies.
- **Scope (`todo`)**: Prompts you to create your custom `scope.yaml` policy.
- **Operator Tools (`missing`)**: PATH binaries (`nxc`, `certipy`, `bloodyAD`) required only when running live `--execute`.

### Step 2: Creating Your Scope Policy
RedStrike will never attack an unauthorized network. Copy and customize the example scope:

**Linux / macOS:**
```bash
cp examples/scope.example.yaml scope.yaml
```

**Windows (PowerShell):**
```powershell
Copy-Item examples\scope.example.yaml scope.yaml
```

Open `scope.yaml` and configure your targets:
```yaml
version: "1.0"
allowed_targets:
  - "192.168.1.10"
  - "192.168.1.11"
  - "dc01.example.lab"
allowed_domains:
  - "example.lab"
  - "corp.local"
allow_high_risk: false    # Set true only for active exploitation campaigns
```

Verify scope activation:
```bash
redstrike check --scope scope.yaml
```

---

## 3. Dry-Run Simulation & Campaign Engine

Before touching any live domain controller, test campaign orchestration using RedStrike's dry-run engine:

```bash
redstrike-campaign run --phase 1-3 --beachhead windows --operator provisioning --engage demo \
  --graph examples/campaign-graph.m1.yaml \
  --seed examples/seed.example.json \
  --automation-root examples/automation
```

### What Happens Behind the Scenes:
1. **DAG Graph Loader**: Ingests `examples/campaign-graph.m1.yaml` and validates node dependencies (`DEMO-RECON ➔ DEMO-CREDS ➔ DEMO-EXEC ➔ DEMO-LATERAL`).
2. **Credential Ledger (SSoT)**: Ingests `examples/seed.example.json` into memory, tracking discovered credentials and DA privileges.
3. **Dry-Run Execution**: Simulates step completion, generates mock telemetry, and outputs a clean execution trace.

---

## 4. Connecting Autonomous LLMs via MCP

RedStrike exposes an **Intent-Level MCP Server (`redstrike-mcp`)** enabling Claude Desktop, Cursor, and custom agent swarms to interact safely.

### Step 1: Start the Local API Server
Generate an internal API key and launch the service:

**Linux / macOS:**
```bash
export REDSTRIKE_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
redstrike-api --scope scope.yaml --profile standalone --api-key "$REDSTRIKE_API_KEY" --host 127.0.0.1 --port 8890
```

**Windows (PowerShell):**
```powershell
$env:REDSTRIKE_API_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
redstrike-api --scope scope.yaml --profile standalone --api-key $env:REDSTRIKE_API_KEY --host 127.0.0.1 --port 8890
```

### Step 2: Configure Your LLM Client

#### A. Claude Desktop
Add to `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):
```json
{
  "mcpServers": {
    "redstrike": {
      "command": "redstrike-mcp",
      "args": ["--api", "http://127.0.0.1:8890"],
      "env": {
        "REDSTRIKE_API_KEY": "YOUR_LOCAL_API_KEY"
      }
    }
  }
}
```

#### B. Cursor & VS Code
Add to `.vscode/mcp.json` in your workspace root:
```json
{
  "mcpServers": {
    "redstrike": {
      "command": "redstrike-mcp",
      "args": ["--api", "http://127.0.0.1:8890"],
      "env": {
        "REDSTRIKE_API_KEY": "YOUR_LOCAL_API_KEY"
      }
    }
  }
}
```

---

## 5. Hands-On Practice Modules

### Lab Module 1: Recon & Intent-Based Enumeration
**Objective**: Instruct your AI agent to discover Active Directory attack surfaces.

1. In Claude Desktop / Cursor, prompt the agent:
   > *"Enumerate the domain users and Kerberos delegation settings for target `dc01.example.lab` under domain `example.lab`."*
2. **What RedStrike Executes**:
   - Validates `dc01.example.lab` against `scope.yaml`.
   - Calls typed `NetExec` builders (`nxc ldap ... --users` and `nxc ldap ... --delegation`).
   - Parses stdout into typed entities (`UserEntity`, `DelegationEntity`).
   - Returns structured `EvidenceRecord` JSON back to the AI.

---

### Lab Module 2: ADCS ESC Vulnerability Auditing
**Objective**: Audit Certificate Templates and identify misconfigured enrollment policies.

1. Prompt the agent:
   > *"Run a Certipy find assessment on the CA at `192.168.1.10` and check for ESC1 through ESC4 misconfigurations."*
2. **What RedStrike Executes**:
   - Calls `redstrike/builders/certipy.py:find`.
   - Returns discovered vulnerable templates (`ESC1-SmartCard`, `ESC4-Template`).
   - Normalizes certificate attributes (`EnrolleeSuppliesSubject`, `ClientAuthentication`, `EnrollmentRights`).

---

### Lab Module 3: Human-in-the-Loop (`HITL`) Operator Approval Gate
**Objective**: Observe how RedStrike safely pauses on high-risk operations.

1. When an AI agent attempts a high-risk operation (e.g. requesting a Domain Admin certificate or writing an ACL):
2. **Execution Pauses**: RedStrike returns status `HITL_PENDING` with a unique gate ID.
3. **Operator Approval**:
   On your terminal, inspect the pending intent and approve:
   ```bash
   redstrike graph approve --gate dcsync --engage default
   ```
4. **Resumed Execution**: The command executes, masks secrets, and returns execution proof.

---

### Lab Module 4: In-Memory C2 Post-Exploitation via C2Stack
**Objective**: Execute post-exploitation tools inside an active implant session without dropping binaries to disk.

1. Launch C2Stack (Sliver or Meridian):
   ```bash
   # From C2Stack repository
   docker compose up -d sliver meridian
   ```
2. Run graph in C2-Enabled Mode:
   ```bash
   # Run campaign through an active Sliver session
   redstrike graph run --phase 1-3 --c2 --c2-backend sliver --c2-session <session-id>
   ```
3. **What RedStrike Executes**:
   - Constructs a `CallSpec(kind="c2", c2_backend="sliver", c2_task_type="execute_assembly")`.
   - Sliver injects `Rubeus.exe` or `SharpHound.exe` into remote process memory via CLR hosting.
   - Extracts Kerberos ticket / hash evidence and updates the local `CredentialLedger`.

---

## 6. Real-World Defensive Synergy (DFIR-Nexus & Purple Teaming)

RedStrike is designed for seamless purple-teaming alongside **DFIR-Nexus**:

| Attack Phase | RedStrike Intent | Expected Windows Telemetry | DFIR-Nexus Validation |
|---|---|---|---|
| **Reconnaissance** | `enumerate_domain_users` | Event ID 4662 (Directory Service Access) | Sigma rule `win_ad_ldap_recon` |
| **Credential Access**| `request_tgt` / Kerberoast | Event ID 4769 (Kerberos Ticket Request) | High-volume RC4 ticket alerts |
| **Privilege Escalation**| `certipy_req` (ESC1/4) | Event ID 4886/4887 (Certificate Issued) | SAN UPN mismatch detection |
| **Lateral Movement** | `winrs_exec` / `sql_query` | Event ID 4624 (Logon Type 3) & Sysmon 1 | Process tree anomaly analysis |

---

## 7. Operator Summary Checklist

- [ ] **Diagnostics Passed**: `redstrike check` reports core health OK.
- [ ] **Scope Defined**: `scope.yaml` contains only authorized subnets and domains.
- [ ] **Local API Key Set**: `REDSTRIKE_API_KEY` exported in environment.
- [ ] **MCP Connected**: Claude Desktop or Cursor configured with loopback endpoint.
- [ ] **HITL Monitored**: High-risk gates reviewed and approved via CLI terminal.
- [ ] **Telemetry Harvested**: Evidence records cross-referenced with DFIR-Nexus.

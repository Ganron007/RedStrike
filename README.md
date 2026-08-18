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
> **Authorized use only.** RedStrike is an offensive security tool. Use it **only** for
> authorized security assessments against systems and accounts you are explicitly permitted
> to test. Unauthorized scanning, enumeration, or access attempts are illegal. The authors
> and contributors accept no liability for any misuse or damage.

Standalone **agentic AD / ADCS** assessment API plus a generic campaign-graph engine.
Lab graphs, seeds, and attack scripts are **not** in this repository — pass your own
`--graph` / `--seed`, or use the bundled demo under `examples/`.

**New users:** follow **[`docs/SETUP.md`](docs/SETUP.md)** (clone → venv → install →
`redstrike check` → `scope.yaml` → dry-run). Secrets: [`docs/SECURITY.md`](docs/SECURITY.md).

### Two tracks

| Track | Engine | Graph / seeds | When |
|---|---|---|---|
| **Standalone (this repo)** | This clone | Yours, or `examples/` | Product use, or **practice** on any authorized lab (including CADRE VMs you operate) |
| **CADRE Plan 01** | Pin `CADRE/tools/red-strike/` | CADRE campaign files | Official CADRE campaign runs |

Standalone evolves here. New features are **adopted into the CADRE pin** after they land.
A standalone clone may target CADRE VMs with **your** graph and `scope.yaml`; that is
practice, not the integrated campaign path. Do not set `CADRE_ROOT` on a standalone
clone and treat it as Plan 01.

The Python package is `redstrike`. CLI: `redstrike`, `redstrike-api`, `redstrike-mcp`,
`redstrike-campaign`.

RedStrike is an advanced **agentic AD / ADCS pentesting and red-teaming toolset**:
intent-level ops, typed builders (`shell=False`), scope policy, credential ledger,
HITL gates, and a campaign-graph engine — built to beat free-form LLM shell wrappers
on fidelity and safety. It keeps improving as a standalone product.

## What is different

- AD-native workflows instead of one generic command execution endpoint.
- Typed command builders with `shell=False`.
- Scope policy before execution.
- Evidence records for every observation.
- Read-only first: no password spraying, dumping, persistence, or account changes in
  the default MVP.
- MCP and HTTP APIs expose intent-level operations such as `enumerate_domain_users`
  and `find_delegation`, not arbitrary command strings.

## Tool Flow

RedStrike runs as a single FastAPI process. Every request — whether it arrives over
HTTP or is proxied through the MCP server — flows through the same policy-gated
pipeline before a typed NetExec command is executed.

```mermaid
flowchart TD
    subgraph Clients["Clients"]
        HTTP["HTTP client<br/>(curl / script)"]
        MCP["MCP client<br/>(LLM agent)"]
    end

    subgraph API["RedStrike process (FastAPI)"]
        ROUTE["/ad/* routes + /jobs"]
        AUTH["API key + rate limiter<br/>(loopback exempt)"]
        SVC["ActiveDirectoryAssessmentService"]
        POLICY["ScopePolicy.assert_allowed<br/>(target / domain / mode / action)"]
        GUARD["Concurrency + cooldown<br/>guardrails"]
        JOBS["JobStore<br/>(async, dedupe)"]
    end

    subgraph Build["Command layer"]
        BUILDER["NetExecCommandBuilder<br/>(typed, shell=False)"]
        RUNNER["CommandRunner.run<br/>(subprocess, shell=False)"]
    end

    subgraph Evidence["Evidence layer"]
        PARSE["parsers.parse_for_action"]
        EVID["EvidenceRecord + Finding<br/>(Pydantic models)"]
        RESP["OperationResponse"]
    end

    subgraph Report["Reporting"]
        JSON["render_json_report"]
        MD["markdown"]
    end

    NXEC[("nxc (NetExec)<br/>on PATH")]

    HTTP --> ROUTE
    MCP -->|requests POST| ROUTE
    ROUTE --> AUTH --> SVC
    SVC --> POLICY --> GUARD
    GUARD --> BUILDER --> RUNNER --> NXEC
    RUNNER --> PARSE --> EVID --> RESP
    SVC --> RESP
    ROUTE --> JOBS
    JOBS --> SVC
    RESP --> JSON
    RESP --> MD
```

**Request lifecycle:**

1. **Ingress** — HTTP clients hit `/ad/*` directly; MCP clients call intent-level
   tools (`enumerate_domain_users`, `find_delegation`, …) that `POST` to the same
   HTTP routes via `requests`.
2. **Auth & throttle** — non-loopback callers must present a valid `X-API-Key` and
   pass the in-memory sliding-window `RateLimiter`.
3. **Policy gate** — `ScopePolicy.assert_allowed` rejects out-of-scope targets,
   domains, modes, or non-read-only actions before anything runs.
4. **Guardrails** — per-target/per-domain concurrency caps and cooldown windows are
   acquired, then released in a `finally` block.
5. **Build & execute** — `NetExecCommandBuilder` produces a typed `argv` (no shell),
   `CommandRunner` runs it as a `subprocess` with secret redaction and a timeout.
6. **Normalize** — `parsers.parse_for_action` turns raw output into entities; an
   `EvidenceRecord` (and any derived `Finding`) is attached to the
   `OperationResponse`.
7. **Report** — responses serialize through `render_json_report` / `markdown` for
   downstream consumption.

Long-running work can instead be submitted to `/jobs`; `JobStore` dedupes by
action/target/domain/mode and runs the same service method on a worker thread
(`PENDING → RUNNING → COMPLETED`).

## Quick Start

Full walkthrough (Windows included): [`docs/SETUP.md`](docs/SETUP.md). Short path:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev,mcp]"
cp examples/scope.example.yaml scope.yaml   # edit; never commit
redstrike check
redstrike-campaign run --phase 1-3 --beachhead windows --operator provisioning --engage demo \
  --graph examples/campaign-graph.m1.yaml \
  --seed examples/seed.example.json \
  --automation-root examples/automation
```

API (generate a **local** key; do not commit it):

```bash
export REDSTRIKE_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
redstrike-api --scope scope.yaml --profile standalone --api-key "$REDSTRIKE_API_KEY" --host 127.0.0.1 --port 8890
```

Health check:

```bash
curl http://127.0.0.1:8890/health
```

## Example API Call

Replace `dc.example.lab` with a host already listed in **your** `scope.yaml`.
`$REDSTRIKE_API_KEY` is an environment variable, not a real key in this file.

```bash
curl -X POST http://127.0.0.1:8890/ad/users \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $REDSTRIKE_API_KEY" \
  -d '{
    "target": "dc.example.lab",
    "domain": "example.lab",
    "username": "operator_user",
    "password": "<REDACTED>"
  }'
```

## Security Defaults

- Keep the API bound to `127.0.0.1` unless you have a deliberate network exposure plan.
- When `--api-key` is configured, non-loopback callers must provide `X-API-Key`.
- MCP rejects non-local plain HTTP API URLs; use HTTPS for remote API endpoints.
- Execution guardrails apply by policy profile (per-target/domain concurrency and cooldown windows).

## Deployment

RedStrike runs as a **single process**. The HTTP API and the job worker share the same
process and in-memory job store, so do not run multiple API replicas behind a load
balancer unless you have an external shared store — jobs created on one replica are not
visible to another.

```bash
redstrike-api --scope scope.yaml --profile standalone --api-key "$REDSTRIKE_API_KEY" --host 127.0.0.1 --port 8890
```

## Async Jobs API

Long-running assessments can be submitted as jobs and polled for status:

```bash
# Submit a job
curl -X POST http://127.0.0.1:8890/jobs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $REDSTRIKE_API_KEY" \
  -d '{"action": "domain_users", "target": "dc.example.lab", "domain": "example.lab"}'

# Poll for the result
curl http://127.0.0.1:8890/jobs/{job_id} -H "X-API-Key: $REDSTRIKE_API_KEY"
```

A job transitions `PENDING → RUNNING → COMPLETED` (or `FAILED`). Submitting the same
`action`/`target`/`domain`/`mode` again returns the existing in-flight or completed job
instead of starting a duplicate; a `FAILED` job can be retried.

## Campaign graph engine

The orchestrator is generic. This repo ships a **demo graph** only. Point it at your
own YAML graph and seed JSON, or use the examples:

```bash
pip install -e .
redstrike check
redstrike-campaign run --phase 1-3 --beachhead windows --operator provisioning --engage demo \
  --graph examples/campaign-graph.m1.yaml \
  --seed examples/seed.example.json \
  --automation-root examples/automation
```

SSH wrap to a Windows beachhead uses env vars (no lab defaults):
`REDSTRIKE_WS01_HOST`, `REDSTRIKE_WS01_USER`, `REDSTRIKE_WS01_SSH_KEY`.

Optional: a standalone clone can load CADRE files with `CADRE_ROOT` for **practice**.
CADRE **Plan 01** campaigns must use the pin `CADRE/tools/red-strike/` instead
(see [`docs/CADRE-PIN.md`](docs/CADRE-PIN.md)).

- `--branch …` · HITL gates (`approve --gate …`) · `--prefer-script` · `stream E|F`
- Typed intents (Certipy / Rubeus / bloodyAD / SQL / SharpSCCM / mimikatz) via MCP `build_intent`
- Live `--execute` is HITL-gated and needs operator tools on PATH (`redstrike check --execute-ready`)

## Reporting

Findings and evidence can be exported as a structured report:

```python
from redstrike.reporting.json_report import render_json_report

report = render_json_report(findings, evidence)
```

`render_json_report` returns a dict with `tool`, `generated_at`, `summary`, `findings`,
and `evidence`, ready to serialize to JSON for downstream consumption.

## License

RedStrike is released under the [MIT License](LICENSE). See the [LICENSE](LICENSE)
file for the full text.

> Copyright (c) 2026 RedStrike

## Safety Model

RedStrike currently allows only read-only AD assessment actions:

- Domain user enumeration
- Domain group enumeration
- Computer enumeration
- Password policy enumeration
- SMB share enumeration
- AS-REP roastability collection
- Kerberoastability collection
- Delegation discovery
- AdminCount discovery
- ADCS enumeration

Destructive or high-risk actions belong behind explicit approval gates in a later
`validate` mode.

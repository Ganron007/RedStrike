# RedStrike

RedStrike is a clean-room successor concept to generic offensive-tool wrappers.
It is part of the broader CADRE initiative, where CADRE represents
**CLOUD | AGENTIC | DFIR | REDTEAM | ENVIRONMENT**.

The goal is not to expose every command on the box. The goal is to run authorized,
policy-aware Active Directory assessment workflows, normalize evidence, rank attack
paths, and produce report-ready findings.

## What is different

- AD-native workflows instead of one generic command execution endpoint.
- Typed command builders with `shell=False`.
- Scope policy before execution.
- Evidence records for every observation.
- Read-only first: no password spraying, dumping, persistence, or account changes in
  the default MVP.
- MCP and HTTP APIs expose intent-level operations such as `enumerate_domain_users`
  and `find_delegation`, not arbitrary command strings.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp]"
cp examples/scope.example.yaml scope.yaml
redstrike-api --scope scope.yaml --profile lab-readonly --api-key "change-me" --host 127.0.0.1 --port 8890
```

Health check:

```bash
curl http://127.0.0.1:8890/health
```

## Example API Call

```bash
curl -X POST http://127.0.0.1:8890/ad/users \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me" \
  -d '{
    "target": "192.168.1.7",
    "domain": "ignite.local",
    "username": "raaz",
    "password": "<REDACTED_PASSWORD>"
  }'
```

## Security Defaults

- Keep the API bound to `127.0.0.1` unless you have a deliberate network exposure plan.
- When `--api-key` is configured, non-loopback callers must provide `X-API-Key`.
- MCP rejects non-local plain HTTP API URLs; use HTTPS for remote API endpoints.
- Execution guardrails apply by policy profile (per-target/domain concurrency and cooldown windows).

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

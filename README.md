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

## Deployment

RedStrike runs as a **single process**. The HTTP API and the job worker share the same
process and in-memory job store, so do not run multiple API replicas behind a load
balancer unless you have an external shared store — jobs created on one replica are not
visible to another.

```bash
redstrike-api --scope scope.yaml --profile lab-readonly --api-key "change-me" --host 127.0.0.1 --port 8890
```

## Async Jobs API

Long-running assessments can be submitted as jobs and polled for status:

```bash
# Submit a job
curl -X POST http://127.0.0.1:8890/jobs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me" \
  -d '{"action": "domain_users", "target": "192.168.1.7", "domain": "ignite.local"}'

# Poll for the result
curl http://127.0.0.1:8890/jobs/{job_id} -H "X-API-Key: change-me"
```

A job transitions `PENDING → RUNNING → COMPLETED` (or `FAILED`). Submitting the same
`action`/`target`/`domain`/`mode` again returns the existing in-flight or completed job
instead of starting a duplicate; a `FAILED` job can be retried.

## Reporting

Findings and evidence can be exported as a structured report:

```python
from cadre_strike.reporting.json_report import render_json_report

report = render_json_report(findings, evidence)
```

`render_json_report` returns a dict with `tool`, `generated_at`, `summary`, `findings`,
and `evidence`, ready to serialize to JSON for downstream consumption.

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

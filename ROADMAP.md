# RedStrike Roadmap

> **Campaign automation (planned):** see [`CAMPAIGN-AUTOMATION-PLAN.md`](CAMPAIGN-AUTOMATION-PLAN.md) — CADRE A–D/G orchestrator via provisioning→ws01 routing (M1–M5). Supersedes the generic 0.2–0.4 sketch below once implementation starts.

## 0.1 MVP

- Scoped read-only AD assessment API.
- MCP tools for AD intent-level operations.
- NetExec command builder with argument vectors and secret redaction.
- Evidence model and starter reporting.

## 0.1 Stabilization Tracker

- [x] Baseline tests pass for policy, NetExec builder, and password policy findings.
- [x] Align documented read-only actions with implemented API, service, and MCP tools.
- [x] Add ADCS enumeration as a read-only assessment operation.
- [x] Expose admin-count discovery through MCP.
- [x] Harden scope policy loading beyond the starter YAML subset.
- [x] Add focused tests for new API/MCP/policy behavior.

## 0.2 AD Reasoning

- BloodHound JSON import/export.
- LDAP parser enrichment for users, groups, computers, SPNs, delegation, and ACLs.
- Ranked attack-path graph with confidence scoring.
- Finding templates mapped to MITRE ATT&CK and detection guidance.

## 0.3 Validation Mode

- Explicit approval objects for high-risk operations.
- Password spray safety checks from password policy and lockout telemetry.
- ADCS ESC validation workflows.
- LAPS/gMSA delegated read validation.

## 0.4 Operator UX

- Web dashboard for scope, evidence, graph, and report generation.
- Markdown, HTML, and JSON evidence bundle exports.
- Sigma/Splunk/Elastic detections per finding.

# RedStrike Roadmap

> **Campaign automation:** see internal planning docs in `docs/internal/` (gitignored) (canonical in CADRE `plan1.1-campaign-automation/`). **SSoT = this repo**; sync major features → `CADRE/tools/red-strike/`.  
> **Plan 1.1 status:** ✅ **Complete** (2026-07-26) — engine **0.5.0**.

## Plan 1.1 — CampaignOrchestrator (done)

| Milestone | Status | Notes |
|-----------|--------|-------|
| **M0** (CADRE lab) | ✅ | ws01 Local Admin, routing, surfaces |
| **M1** prove path | ✅ | BeachheadRouter + ledger + P1–3; `redstrike-campaign` dry-run |
| **M2** spine + HITL | ✅ | Phase 0–8 graph, HITL gates, MCP/API `campaign_*`, workflow doc |
| **M3** branches | ✅ | `--branch` A–D/G/sql-ai; UnPAC stub; LAB-PROFILES preflight; CADRE glue split |
| **M4** typed builders | ✅ | Certipy/Rubeus/bloodyAD/SQL/SharpSCCM/mimikatz + `intent:` |
| **M5** E/F runners | ✅ | `stream E|F` · phase 9/10 · graph v5 · **0.5.0** |
| **P11.6** live smoke | ✅ | `.60` venv 0.5.0; dry-run P1–3 + stream E/F |
| **Docs** | ✅ | README / ROADMAP / CADRE integration 1-pager |

```bash
redstrike-campaign run --phase 1-3 --beachhead windows --engage lab1
redstrike-campaign stream E --engage lab1
redstrike-campaign stream F --engage lab1
```

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

# Changelog

All notable changes to RedStrike are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (2026-08-03 — dual operator modes)

- **`--operator provisioning|ws01`** — first-class dual simulation:
  - `provisioning` (default on Linux): orchestrator on Kali/.60 → SSH / `ws01-exec` hybrid (current path)
  - `ws01` (default on win32): orchestrator on domain-joined ws01 → `local-ws01` / no SSH wrap (Rule 1 strict)
- Env override: `REDSTRIKE_OPERATOR`. Persisted on engagement state; summary exposes `operator` + `local_ws01_count`.
- API/MCP accept optional `operator`. Tests cover native no-SSH wrap.

### Added (2026-08-03 — live camp-v3 + runner PATH fix)

- **Live Campaign v3** on provisioning — engagement `camp-v3-20260803`; documented in CADRE `Red-Strike-workflow.md`.
- **`resolve_executable`** in `CommandRunner` — finds `/usr/bin/bash` when PATH is stripped in non-interactive SSH.

### Added (2026-08-03 — ws01 SSH transport + graph v8 sync)

- **`cadre_strike.runtime.ws01_transport`** — typed intents on `path: ws01` wrap argv in OpenSSH → PowerShell on ws01 (`REDSTRIKE_WS01_*` env vars; default key `~/.ssh/cadre-ws01-key`). Bash harness scripts unchanged (`ws01-exec` mechanism).
- **Campaign graph v8** (CADRE glue): branch **H** (WT063–068 stubs), post-DA **T097–T109** stubs, fixed `certipy.find` / removed broken `rubeus.monitor`, Branch D linux script paths.
- **Tests:** 91 pytest (`test_ws01_transport.py`).

### Added (2026-07-26 — Plan 1.1 M5 + P11.6 — Plan 1.1 complete)

> **Scope:** E/F thin streams + live dry-run smoke on provisioning; close Plan 1.1.

**M5 engine (0.5.0):**
- Branches `E`/`F` · `STREAM_SPECS` (phase 9 / 10) · CLI `redstrike-campaign stream E|F`
- API `POST /campaign/stream` · MCP `campaign_stream`
- Path `external60_phase0` (no ws01 for E/F)
- Tests: **88** passed

**P11.6 ops:**
- Install: `~/RedStrike/.venv` + `~/CADRE` glue on `.60`
- Smoke RC=0: Phases 1–3 windows/linux · `stream E` · `stream F`
- Wrapper: `~/.local/bin/redstrike-campaign`

**Docs:** README, ROADMAP, this CHANGELOG; CADRE `red-strike.md`, CHECKLIST P11.*, plan1.1 README/plan, PLANS, registry, workflow, vm-access, pin sync.

**Next:** Plan 1 telemetry (CADRE). Live `--execute` operator-gated (HITL).

### Added (2026-07-25 — Plan 1.1 M4 typed builders)

> **Scope:** Intent-level typed argv for AD/ADCS tools — LLM ranks/explains; orchestrator builds.

**Builders:** `certipy` · `rubeus` · `bloodyad` · `sql` · `sharpsccm` · `mimikatz`  
**Graph:** `intent` / `intent_args` / `cred` (prefer over script; `--prefer-script` keeps harness)  
**API/MCP:** `POST /builders/preview` · `build_intent`  
**Version:** **0.4.0**

### Added (2026-07-25 — Plan 1.1 M3 + product identity)

> **Product:** RedStrike is an advanced **agentic AD/ADCS pentest / red-team toolset**. CADRE campaign graph/seeds/profiles are **integration glue** (not hardcoded product identity).

**What was done:**
- `--branch spine|A|B|C|D|G|sql-ai|all` + CADRE `lab-profiles.yaml` preflight.
- Default seed resolves from CADRE `lab-seed-creds.json`; standalone `examples/seed.example.json` is placeholder-only (lab passwords removed from this repo).
- Version **0.3.0**. Tests: **72** passed.

**Next:** M4 typed builders.

### Added (2026-07-25 — Plan 1.1 M2 spine + HITL + MCP)

> **Scope:** Phase 0–8 graph routing, HITL gates, MCP/API campaign surface, workflow doc.

**What was done:**
- `runtime/hitl.py`, `session.py` — engagement `state.json`, gate approvals.
- Orchestrator: stub skip, HITL pause on execute, float phases (`0.5-8`).
- CLI: `start` / `approve` / `run` / `status`.
- FastAPI `/campaign/*` + MCP `campaign_start|approve|run_phase|status`.
- CADRE: `campaign-graph.yaml` v2 + `Red-Strike-workflow.md`.
- Tests: full suite **66** passed. Version **0.2.1**.

**Next:** M3 — Branches A–D + UnPAC + SCCM + SQL AI + G.

### Added (2026-07-25 — Plan 1.1 M1 CampaignOrchestrator)

> **Scope:** Prove-path orchestrator — BeachheadRouter + CredentialLedger + Phases 1–3.

**What was done:**
- `cadre_strike/runtime/beachhead.py` — paths `ws01` | `linux60` | `stage_mbr01` | `external60_phase0`; windows→ws01-exec, linux→direct (no ws01-exec); mbr01 exception-only.
- `cadre_strike/runtime/ledger.py` — `~/.redstrike/engagements/<id>/creds.json` (or `REDSTRIKE_HOME`); fail-closed `require()`.
- `cadre_strike/runtime/graph.py` + `orchestrator.py` — load CADRE `campaign-graph.yaml` (fallback `examples/campaign-graph.m1.yaml`).
- CLI `redstrike-campaign` — `run --phase 1-3 --beachhead windows|linux --engage <id>` (dry-run default; `--execute` to run scripts).
- Scope profile `cadre-campaign`.
- Tests: `tests/test_m1_campaign.py` (10) — full suite 59 passed.
- Synced major pieces → `CADRE/tools/red-strike/`.
- Version **0.2.0**.

**CADRE glue (sister):** `attack-matrix/Campaign/automation/campaign-graph.yaml` (T003/T002/T041/T043).

**Next:** M2 — full spine + HITL gates + MCP `campaign_*`.

### Changed (2026-07-25 — Plan 1.1 M0 complete on CADRE; RedStrike next = M1)

> **Scope:** CADRE executed M0 (ws01 Local Admin, routing, campaign promotions, optional provisioning join). This repo plan/checklist mirrors updated; **M1 code still not started.** *(superseded by M1 entry above)*

**What was done (this repo):**
- Synced campaign-automation plan + [`ROADMAP.md`](ROADMAP.md) to ws01-primary / dual beachhead / M0 [x].

### Added (2026-07-25 — CADRE Campaign Automation Plan / Plan 1.1)

> **Scope:** Product direction for evolving RedStrike from read-only NetExec recon into a CADRE lab campaign orchestrator. Docs only — M1 implementation not started.

**What was done:**
- Added internal campaign-automation plan — M1–M5 plan for Campaign spine + Branches A–D + G automation under provisioning→ws01 routing, phase-gated HITL, hybrid script→typed-intent rollout. E/F deferred to thin runners (M5).
- Linked the plan from [`ROADMAP.md`](ROADMAP.md) (supersedes generic 0.2–0.4 sketch once implementation starts).
- CADRE mirror + checklist registration: umbrella campaign-automation plan (internal), CHECKLIST **P11.*** as next action.

---

## [0.2.0] — Plan 1.1 M1

CampaignOrchestrator prove path (see Unreleased M1 entry). Dry-run + unit tests; live lab execute tracked as CADRE P11.6.

## [0.1.0] — Testing Ready

### Added
- FastAPI + MCP surface for intent-level read-only AD assessment
- NetExec typed builders (`shell=False`) with secret redaction
- Scope policy + evidence model + starter reporting

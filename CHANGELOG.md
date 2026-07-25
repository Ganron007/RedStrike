# Changelog

All notable changes to RedStrike are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (2026-07-25 — CADRE Campaign Automation Plan / Plan 1.1)

> **Scope:** Product direction for evolving RedStrike from read-only NetExec recon into a CADRE lab campaign orchestrator. Docs only — M1 implementation not started.

**What was done:**
- Added [`CAMPAIGN-AUTOMATION-PLAN.md`](CAMPAIGN-AUTOMATION-PLAN.md) — M1–M5 plan for Campaign spine + Branches A–D + G automation under provisioning→ws01 routing, phase-gated HITL, hybrid script→typed-intent rollout. E/F deferred to thin runners (M5).
- Linked the plan from [`ROADMAP.md`](ROADMAP.md) (supersedes generic 0.2–0.4 sketch once implementation starts).
- CADRE mirror + checklist registration: `CADRE/docs/internal/plan1.1-campaign-automation/`, CHECKLIST **P11.*** as next action.

**Locked defaults in the plan:**
- Autonomy: phase-gated HITL (not full autopilot)
- Path: `ws01-exec` / `ws01-stage` only for Phase 0.5+ (no direct `.60`→DC for catalog attacks)
- Engine: hybrid (wrap existing `04-automation` scripts first, then typed builders)

**Next (implementation):** M1 — `Ws01Router` + `CredentialLedger` + Phases 1–3 graph (T003/T002/T041/T043).

---

## [0.1.0] — Testing Ready

### Added
- FastAPI + MCP surface for intent-level read-only AD assessment
- NetExec typed command builders (`shell=False`)
- Scope policy profiles, evidence model, jobs API, CI

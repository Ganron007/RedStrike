"""Engagement report bundle: state + journal + ledger + teardown -> md/json.

Unlike the finding/evidence renderers (which stay for API-driven flows), this
module turns a live engagement directory into a deliverable: what ran, what
verified, what credentials were captured, what cleanup is pending, and which
gates are awaiting approval.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redstrike.core.runner import redact_argv
from redstrike.core.secrets import scrub_output
from redstrike.runtime.activity import resolve_activity_log
from redstrike.runtime.evidence_store import EvidenceStore
from redstrike.runtime.hitl import EngagementStore
from redstrike.runtime.ledger import CredentialLedger
from redstrike.runtime.teardown import load_queue


def _mask(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 6:
        return "***"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def load_engagement_bundle(
    engagement_id: str,
    *,
    root: Path | None = None,
    include_secrets: bool = False,
) -> dict[str, Any]:
    """Everything a report needs for one engagement (secrets masked by default)."""
    store = EngagementStore(engagement_id, root=root)
    state = store.load()
    if state is None:
        raise FileNotFoundError(f"engagement '{engagement_id}' not found at {store.dir}")

    ledger = CredentialLedger(engagement_id, root=root)
    credentials: list[dict[str, Any]] = []
    for name in ledger.names():
        cred = ledger.get(name)
        if cred is None:
            continue
        entry: dict[str, Any] = {
            "name": cred.name,
            "username": cred.username,
            "domain": cred.domain,
            "source": cred.source,
            "notes": cred.notes,
            "has_password": bool(cred.password),
            "has_nt_hash": bool(cred.nt_hash),
        }
        if include_secrets:
            entry["password"] = cred.password
            entry["nt_hash"] = cred.nt_hash
        else:
            entry["password_mask"] = _mask(cred.password)
            entry["nt_hash_mask"] = _mask(cred.nt_hash)
        credentials.append(entry)

    journal_path = resolve_activity_log(engagement_id, ledger_dir=store.dir)
    steps: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    if journal_path and Path(journal_path).is_file():
        for line in Path(journal_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            events.append(record)
            if record.get("event") == "step_end":
                steps.append(
                    {
                        "node_id": record.get("node_id"),
                        "title": record.get("title"),
                        "phase": record.get("phase"),
                        "mechanism": record.get("mechanism"),
                        "dry_run": record.get("dry_run"),
                        "skipped": record.get("skipped"),
                        "skip_reason": record.get("skip_reason"),
                        "verified": record.get("verified"),
                        "verify_status": record.get("verify_status"),
                        "return_code": record.get("return_code"),
                        "started_at": record.get("started_at"),
                        "finished_at": record.get("finished_at"),
                        "tool": record.get("tool"),
                        "tool_version": record.get("tool_version"),
                    }
                )

    queue = load_queue(store.dir / "teardown.json")
    teardown = [
        {
            "name": action.name,
            "target": action.target,
            "description": action.description,
            "executed": action.executed,
            "success": action.success,
        }
        for action in queue.all_actions
    ]

    # Findings + evidence produced by AD-service flows for this engagement.
    evidence_store = EvidenceStore(engagement_id, root=root)
    findings: list[dict[str, Any]] = []
    try:
        from redstrike.ad.graph import ADKnowledgeGraph

        ranked = ADKnowledgeGraph().rank_findings(
            evidence_store.findings(), evidence_store.evidence()
        )
    except Exception:  # noqa: BLE001 - ranking is a nicety; raw order still renders
        ranked = evidence_store.findings()
    for finding in ranked:
        findings.append(
            {
                "id": finding.id,
                "title": finding.title,
                "risk": finding.risk.value,
                "target": finding.target,
                "summary": finding.summary,
                "evidence_ids": list(finding.evidence_ids),
                "mitre_attack": list(finding.mitre_attack),
                "remediation": list(finding.remediation),
            }
        )
    evidence: list[dict[str, Any]] = []
    for record in evidence_store.evidence():
        entry: dict[str, Any] = {
            "id": record.id,
            "observed_at": record.observed_at.isoformat(),
            "technique": record.technique,
            "target": record.target,
            "tool": record.tool,
            "command": redact_argv(list(record.command)),
            "confidence": record.confidence,
            "findings": [f["id"] for f in findings if record.id in f["evidence_ids"]],
        }
        if include_secrets:
            entry["raw_output"] = record.raw_output
        else:
            entry["raw_output"] = scrub_output(record.raw_output)
        evidence.append(entry)

    verified = [s for s in steps if s.get("verified")]
    unverified = [s for s in steps if not s.get("verified") and not s.get("skipped") and not s.get("dry_run")]
    return {
        "engagement_id": engagement_id,
        "generated_at": None,  # filled by the renderer (keeps this function pure)
        "state": state.to_dict(),
        "root": str(store.dir),
        "journal": str(journal_path) if journal_path else None,
        "summary": {
            "steps": len(steps),
            "verified": len(verified),
            "unverified": len(unverified),
            "credentials": len(credentials),
            "findings": len(findings),
            "evidence": len(evidence),
            "pending_gate": state.pending_gate,
            "status": state.status,
        },
        "steps": steps,
        "credentials": credentials,
        "approvals": state.approvals,
        "teardown": teardown,
        "findings": findings,
        "evidence": evidence,
    }


def render_engagement_markdown(bundle: dict[str, Any]) -> str:
    summary = bundle["summary"]
    state = bundle["state"]
    lines = [
        f"# RedStrike Engagement Report — `{bundle['engagement_id']}`",
        "",
        f"- Status: `{summary['status']}`",
        f"- Beachhead: `{state.get('beachhead')}` · Operator: `{state.get('operator')}`",
        f"- Steps: {summary['steps']} total · {summary['verified']} verified · {summary['unverified']} unverified",
        f"- Credentials in ledger: {summary['credentials']}",
    ]
    if summary.get("pending_gate"):
        lines.append(f"- **Pending HITL gate: `{summary['pending_gate']}`**")
    lines.append("")

    lines.append("## Approvals")
    lines.append("")
    approvals = bundle.get("approvals") or []
    if approvals:
        for entry in approvals:
            note = entry.get("note") or ""
            lines.append(f"- `{entry.get('gate')}` at {entry.get('ts')} — {note}")
    else:
        lines.append("No explicit operator approvals recorded.")
    lines.append("")

    lines.append("## Steps")
    lines.append("")
    steps = bundle.get("steps") or []
    if steps:
        lines.append("| Node | Phase | Verified | Status | Mechanism | Tool | Skip reason |")
        lines.append("|---|---|---|---|---|---|---|")
        for step in steps:
            tool = step.get("tool") or ""
            version = step.get("tool_version") or ""
            tool_cell = f"{tool} {version}".strip() if tool else ""
            lines.append(
                "| {node} | {phase} | {verified} | {status} | {mech} | {tool} | {skip} |".format(
                    node=step.get("node_id") or "",
                    phase=step.get("phase") or "",
                    verified="yes" if step.get("verified") else "no",
                    status=step.get("verify_status") or ("dry_run" if step.get("dry_run") else ""),
                    mech=step.get("mechanism") or "",
                    tool=tool_cell.replace("|", "/"),
                    skip=(step.get("skip_reason") or "").replace("|", "/"),
                )
            )
    else:
        lines.append("No journaled steps found for this engagement.")
    lines.append("")

    lines.append("## Credentials (ledger)")
    lines.append("")
    credentials = bundle.get("credentials") or []
    if credentials:
        lines.append("| Name | Username | Domain | Source | Password | NT hash |")
        lines.append("|---|---|---|---|---|---|")
        for cred in credentials:
            lines.append(
                "| {name} | {user} | {domain} | {source} | {pw} | {nt} |".format(
                    name=cred.get("name") or "",
                    user=cred.get("username") or "",
                    domain=cred.get("domain") or "",
                    source=cred.get("source") or "",
                    pw=cred.get("password") or cred.get("password_mask") or "—",
                    nt=cred.get("nt_hash") or cred.get("nt_hash_mask") or "—",
                )
            )
        lines.append("")
        lines.append(
            "> Secrets are masked unless the report is generated with `--include-secrets`."
        )
    else:
        lines.append("No credentials recorded.")
    lines.append("")

    lines.append("## Teardown queue")
    lines.append("")
    teardown = bundle.get("teardown") or []
    if teardown:
        for action in teardown:
            mark = "done" if action.get("executed") else "pending"
            lines.append(
                f"- [{mark}] `{action.get('name')}` on `{action.get('target')}` — {action.get('description')}"
            )
    else:
        lines.append("No teardown actions registered (nodes can declare `teardown:` in the graph).")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    findings = bundle.get("findings") or []
    if findings:
        for finding in findings:
            lines.append(f"### {finding.get('title')}  ·  risk `{finding.get('risk')}`")
            lines.append("")
            lines.append(f"- Target: `{finding.get('target')}`")
            if finding.get("mitre_attack"):
                lines.append(f"- MITRE ATT&CK: {', '.join(finding['mitre_attack'])}")
            lines.append(f"- {finding.get('summary')}")
            if finding.get("remediation"):
                lines.append("- Remediation:")
                for item in finding["remediation"]:
                    lines.append(f"  - {item}")
            lines.append("")
    else:
        lines.append(
            "No findings recorded for this engagement (findings are produced by `/ad/*` "
            "requests carrying an `engagement_id`)."
        )
    lines.append("")

    lines.append("## Evidence index")
    lines.append("")
    evidence = bundle.get("evidence") or []
    if evidence:
        lines.append("| Evidence | Technique | Target | Tool | Confidence |")
        lines.append("|---|---|---|---|---|")
        for record in evidence:
            lines.append(
                "| `{id}` | {tech} | {target} | {tool} | {conf} |".format(
                    id=record.get("id"),
                    tech=record.get("technique") or "",
                    target=record.get("target") or "",
                    tool=record.get("tool") or "",
                    conf=record.get("confidence"),
                )
            )
        lines.append("")
        lines.append(
            "> Raw tool output is stored with the engagement and scrubbed in this "
            "report; use `--include-secrets` for the raw form."
        )
    else:
        lines.append("No evidence records persisted for this engagement.")
    lines.append("")
    return "\n".join(lines)


def render_engagement_json(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "engagement_id": bundle["engagement_id"],
        "state": bundle["state"],
        "summary": bundle["summary"],
        "approvals": bundle.get("approvals") or [],
        "steps": bundle.get("steps") or [],
        "credentials": bundle.get("credentials") or [],
        "teardown": bundle.get("teardown") or [],
        "findings": bundle.get("findings") or [],
        "evidence": bundle.get("evidence") or [],
        "journal": bundle.get("journal"),
    }

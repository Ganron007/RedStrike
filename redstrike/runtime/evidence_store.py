"""Per-engagement evidence and findings persistence.

AD-service flows (`/ad/*`, `/jobs`) already produce `EvidenceRecord`s and
`Finding`s per response; nothing persisted them, so `redstrike report` could
not show them. This store appends evidence to JSONL (deduped by id) and merges
findings into a JSON map, next to the engagement state/ledger.

Persistence is best-effort at the service layer: a broken engagement directory
must never fail an assessment request.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from redstrike.core.models import EvidenceRecord, Finding


def _engagement_dir(engagement_id: str, root: Path | None) -> Path:
    if root is not None:
        base = Path(root)
    else:
        env_home = os.environ.get("REDSTRIKE_HOME")
        base = (
            Path(env_home) / "engagements"
            if env_home
            else Path.home() / ".redstrike" / "engagements"
        )
    return base / engagement_id


class EvidenceStore:
    """Append-only evidence records + merged findings for one engagement."""

    def __init__(self, engagement_id: str, *, root: Path | None = None) -> None:
        if not engagement_id or "/" in engagement_id or "\\" in engagement_id:
            raise ValueError("engagement_id must be a simple identifier")
        self.engagement_id = engagement_id
        self.dir = _engagement_dir(engagement_id, root)
        self.evidence_path = self.dir / "evidence.jsonl"
        self.findings_path = self.dir / "findings.json"
        self._evidence_ids: set[str] | None = None
        self._findings: dict[str, dict] | None = None

    # ------------------------------------------------------------- loading
    def _load_evidence_ids(self) -> set[str]:
        if self._evidence_ids is not None:
            return self._evidence_ids
        ids: set[str] = set()
        if self.evidence_path.is_file():
            for line in self.evidence_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ids.add(str(json.loads(line).get("id")))
                except ValueError:
                    continue
        self._evidence_ids = ids
        return ids

    def _load_findings(self) -> dict[str, dict]:
        if self._findings is not None:
            return self._findings
        payload: dict[str, dict] = {}
        if self.findings_path.is_file():
            try:
                data = json.loads(self.findings_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    payload = {
                        str(key): value
                        for key, value in data.items()
                        if isinstance(value, dict)
                    }
            except ValueError:
                payload = {}
        self._findings = payload
        return payload

    # ------------------------------------------------------------- writing
    def record(
        self,
        *,
        evidence: EvidenceRecord | None = None,
        findings: list[Finding] | None = None,
    ) -> int:
        """Persist one response's evidence + findings. Returns findings added."""
        added = 0
        self.dir.mkdir(parents=True, exist_ok=True)
        if evidence is not None:
            known = self._load_evidence_ids()
            if evidence.id not in known:
                with self.evidence_path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(evidence.model_dump(mode="json"), ensure_ascii=True) + "\n"
                    )
                known.add(evidence.id)
        if findings:
            merged = self._load_findings()
            for finding in findings:
                if finding.id in merged:
                    continue
                merged[finding.id] = finding.model_dump(mode="json")
                added += 1
            if added:
                tmp = self.findings_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
                os.replace(tmp, self.findings_path)
        return added

    # ------------------------------------------------------------- reading
    def evidence(self) -> list[EvidenceRecord]:
        records: list[EvidenceRecord] = []
        if not self.evidence_path.is_file():
            return records
        for line in self.evidence_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(EvidenceRecord.model_validate(json.loads(line)))
            except (ValueError, TypeError):
                continue
        return records

    def findings(self) -> list[Finding]:
        found: list[Finding] = []
        for payload in self._load_findings().values():
            try:
                found.append(Finding.model_validate(payload))
            except (ValueError, TypeError):
                continue
        return found

    def persisted(self) -> bool:
        return self.evidence_path.is_file() or self.findings_path.is_file()

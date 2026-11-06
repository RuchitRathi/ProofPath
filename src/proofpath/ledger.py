"""Content-addressed storage for raw tool output.

Evidence IDs look like EV-0001. The stored bytes are hashed with SHA-256.
Callers keep findings pointed at those IDs.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from proofpath.schemas import Evidence

_ID = re.compile(r"^EV-(\d+)$")


class Ledger:
    """Writes one artifact file and one metadata file per evidence ID."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def store(self, *, content: bytes, tool: str, command: list[str], status: str, summary: str, source_mode: str = "live") -> Evidence:
        """Persist raw bytes and return the evidence record."""
        evidence_id = self._next_id()
        artifact = self.root / f"{evidence_id}.bin"
        meta = self.root / f"{evidence_id}.json"
        artifact.write_bytes(content)
        evidence = Evidence(
            id=evidence_id,
            tool=tool,
            command=list(command),
            sha256=hashlib.sha256(content).hexdigest(),
            captured_at=datetime.now(timezone.utc),
            artifact_path=str(artifact),
            status=status,  # type: ignore[arg-type]
            summary=summary,
            source_mode=source_mode,
        )
        meta.write_text(evidence.model_dump_json(indent=2), encoding="utf-8")
        return evidence

    def load(self, evidence_id: str) -> Evidence:
        meta = self.root / f"{evidence_id}.json"
        return Evidence.model_validate_json(meta.read_text(encoding="utf-8"))

    def read_bytes(self, evidence_id: str) -> bytes:
        evidence = self.load(evidence_id)
        return Path(evidence.artifact_path).read_bytes()

    def verify_artifact(self, evidence_id: str) -> bool:
        """True when the file bytes still match the recorded SHA-256."""
        evidence = self.load(evidence_id)
        try:
            digest = hashlib.sha256(self.read_bytes(evidence_id)).hexdigest()
        except FileNotFoundError:
            return False
        return digest == evidence.sha256

    def verify_all(self) -> tuple[bool, str, set[str]]:
        """Check every metadata/artifact pair and return known evidence IDs."""
        known: set[str] = set()
        for meta in sorted(self.root.glob("EV-*.json")):
            evidence_id = meta.stem
            known.add(evidence_id)
            try:
                if not self.verify_artifact(evidence_id):
                    return False, f"artifact hash mismatch or missing artifact: {evidence_id}", known
            except (OSError, ValueError):
                return False, f"invalid ledger metadata or missing artifact: {evidence_id}", known
        return True, "ledger artifacts intact", known

    def _next_id(self) -> str:
        highest = 0
        for path in self.root.glob("EV-*.json"):
            match = _ID.fullmatch(path.stem)
            if match:
                highest = max(highest, int(match.group(1)))
        return f"EV-{highest + 1:04d}"

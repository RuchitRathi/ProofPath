"""Append-only hash-chained audit log.

Each entry stores the hash of the previous entry. `verify_chain` recomputes
every hash and reports the first break.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from proofpath.canonical import canonical_json
from proofpath.schemas import AuditEntry

GENESIS = "0" * 64


def entry_digest(prev_hash: str, body: dict[str, Any]) -> str:
    """Hash the previous link together with the canonical entry body."""
    material = (prev_hash + "\n" + canonical_json(body)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify_chain(entries: list[AuditEntry]) -> tuple[bool, str]:
    """Return whether every link and sequence number still matches."""
    prev = GENESIS
    for index, entry in enumerate(entries):
        if entry.seq != index:
            return False, f"sequence break at {index}"
        if entry.prev_hash != prev:
            return False, f"prev_hash mismatch at {index}"
        body = entry.model_dump(mode="json", exclude={"entry_hash"})
        digest = entry_digest(prev, body)
        if digest != entry.entry_hash:
            return False, f"hash mismatch at {index}"
        prev = entry.entry_hash
    return True, "chain intact"


class AuditLog:
    """JSONL audit log. One object per line."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def append(self, event_type: str, actor: str, details: dict[str, Any]) -> AuditEntry:
        """Write the next entry linked to the current tail."""
        existing = self.read_entries()
        prev = existing[-1].entry_hash if existing else GENESIS
        body = {
            "seq": len(existing),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prev_hash": prev,
            "event_type": event_type,
            "actor": actor,
            "details": details,
        }
        entry = AuditEntry(**body, entry_hash=entry_digest(prev, body))
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(entry.model_dump_json() + "\n")
        return entry

    def read_entries(self) -> list[AuditEntry]:
        text = self.path.read_text(encoding="utf-8")
        entries: list[AuditEntry] = []
        for line_no, line in enumerate(text.splitlines()):
            if line.strip():
                try:
                    entries.append(AuditEntry.model_validate_json(line))
                except Exception as exc:
                    raise ValueError(f"invalid audit seq {line_no}: {exc}") from exc
        return entries

    def verify(self) -> tuple[bool, str]:
        return verify_chain(self.read_entries())

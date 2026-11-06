"""Evidence ledger ids and hashes."""

import hashlib
from pathlib import Path

from proofpath.ledger import Ledger


def test_store_hashes_and_numbers_ids(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path)
    first = ledger.store(content=b"alpha", tool="nmap", command=["nmap", "-p", "80"], status="ok", summary="one")
    second = ledger.store(content=b"beta", tool="nmap", command=["nmap", "-p", "443"], status="ok", summary="two")
    assert first.id == "EV-0001"
    assert second.id == "EV-0002"
    assert first.sha256 == hashlib.sha256(b"alpha").hexdigest()
    assert ledger.read_bytes(first.id) == b"alpha"
    assert ledger.verify_artifact(first.id) is True
    assert first.command == ["nmap", "-p", "80"]


def test_modified_bytes_fail_verification(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path)
    evidence = ledger.store(content=b"alpha", tool="nmap", command=["nmap"], status="ok", summary="one")
    Path(evidence.artifact_path).write_bytes(b"changed")
    assert ledger.verify_artifact(evidence.id) is False

"""Hash-chain tamper detection."""

import json
from pathlib import Path

from proofpath.audit import GENESIS, AuditLog, entry_digest
from proofpath.cli import main
from proofpath.ledger import Ledger


def test_empty_chain_is_valid(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.verify() == (True, "chain intact")


def test_appended_entries_link(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.append("one", "analyst", {"value": "a"})
    second = log.append("two", "analyst", {"value": "b"})
    assert first.prev_hash == GENESIS
    assert second.prev_hash == first.entry_hash
    assert log.verify() == (True, "chain intact")
    assert main(["verify", "--audit", str(log.path)]) == 0


def test_edited_payload_breaks_the_hash(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("one", "analyst", {"value": "a"})
    log.append("two", "analyst", {"value": "b"})
    lines = log.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["details"]["value"] = "tampered"
    lines[0] = json.dumps(first)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, message = log.verify()
    assert ok is False
    assert "hash mismatch at 0" in message


def test_relinked_entry_breaks_the_next_pointer(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("one", "analyst", {"value": "a"})
    log.append("two", "analyst", {"value": "b"})
    lines = log.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["details"]["value"] = "tampered"
    body = {key: value for key, value in first.items() if key != "entry_hash"}
    first["entry_hash"] = entry_digest(first["prev_hash"], body)
    lines[0] = json.dumps(first)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, message = log.verify()
    assert ok is False
    assert "mismatch at 1" in message


def test_missing_audit_file_does_not_create_one(tmp_path: Path) -> None:
    missing = tmp_path / "missing.jsonl"
    assert main(["verify", "--audit", str(missing)]) == 1
    assert not missing.exists()


def test_verify_names_tampered_and_deleted_artifacts(tmp_path: Path, capsys) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    ev = ledger.store(content=b"alpha", tool="nmap", command=["nmap"], status="ok", summary="test")
    log.append("nmap_result", "test", {"evidence_id": ev.id})
    assert main(["verify", "--audit", str(log.path), "--ledger", str(ledger.root)]) == 0
    artifact = Path(ev.artifact_path)
    artifact.write_bytes(b"alphx")
    assert main(["verify", "--audit", str(log.path), "--ledger", str(ledger.root)]) == 1
    assert ev.id in capsys.readouterr().out
    artifact.write_bytes(b"alpha")
    artifact.unlink()
    assert main(["verify", "--audit", str(log.path), "--ledger", str(ledger.root)]) == 1
    assert ev.id in capsys.readouterr().out


def test_verify_names_tampered_audit_sequence(tmp_path: Path, capsys) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    log.append("one", "analyst", {"value": "clean"})
    lines = log.path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("clean", "dirty")
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main(["verify", "--audit", str(log.path), "--ledger", str(ledger.root)]) == 1
    assert "0" in capsys.readouterr().out


def test_verify_names_missing_cited_evidence_id(tmp_path: Path, capsys) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    log.append("nmap_result", "analyst", {"evidence_id": "EV-9999"})
    assert main(["verify", "--audit", str(log.path), "--ledger", str(ledger.root)]) == 1
    message = capsys.readouterr().out
    assert "audit seq 0" in message and "EV-9999" in message


def test_verify_detects_tampered_imported_artifact(tmp_path: Path, capsys) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    evidence = ledger.store(content=b"<synthetic-import/>", tool="burp", command=["import_burp"], status="ok", summary="synthetic", source_mode="imported")
    log.append("burp_import", "analyst", {"evidence_id": evidence.id, "source_mode": "imported"})
    args = ["verify", "--audit", str(log.path), "--ledger", str(ledger.root)]
    assert main(args) == 0
    Path(evidence.artifact_path).write_bytes(b"<synthetic-imporx/>")
    assert main(args) == 1
    assert evidence.id in capsys.readouterr().out

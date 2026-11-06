"""Nessus import tests use an explicitly synthetic .nessus document."""

from pathlib import Path
import xml.etree.ElementTree as ET

from proofpath.adapters.nessus_import import import_nessus_xml, parse_nessus_xml
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.scope_guard import ScopeGuard
from proofpath.selftest import demo_resolver

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT / "tests" / "fixtures" / "nessus_sample.nessus").read_bytes()


def _guard() -> ScopeGuard:
    return ScopeGuard.from_yaml(ROOT / "scope.yaml", resolver=demo_resolver)


def test_synthetic_nessus_import_emits_finding_with_verbatim_resolvable_ref(tmp_path: Path) -> None:
    document, items = parse_nessus_xml(RAW)
    assert len(items) == 1
    item = items[0]
    span = document.spans[item.locator]
    exact_fragment = RAW[span[0]:span[1]].decode("utf-8")
    assert item.excerpt == exact_fragment[:300]
    xpath = item.locator.removeprefix("/NessusClientData_v2/")
    assert ET.fromstring(RAW).find(xpath) is not None

    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    result = import_nessus_xml(RAW, _guard(), audit, ledger)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.asset.ip == "10.10.1.5"
    assert finding.severity == "medium"
    assert finding.cvss == 4.2
    assert finding.cves == ["CVE-2099-900001"]
    ref = finding.evidence[0]
    assert ref.evidence_id == result.evidence_id
    assert ref.locator == item.locator
    assert ref.excerpt == item.excerpt
    assert ref.excerpt in ledger.read_bytes(result.evidence_id).decode("utf-8")
    assert ledger.load(result.evidence_id).source_mode == "imported"
    assert audit.verify()[0]


def test_out_of_scope_nessus_host_is_dropped_and_audited(tmp_path: Path) -> None:
    outside = RAW.replace(b"10.10.1.5", b"8.8.8.8")
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    result = import_nessus_xml(outside, _guard(), audit, ledger)
    assert result.findings == []
    assert result.dropped_items == 1
    entries = audit.read_entries()
    assert any(entry.event_type == "out_of_scope" and entry.details["host"] == "8.8.8.8" for entry in entries)
    assert ledger.load(result.evidence_id).source_mode == "imported"


def test_import_hostname_normalization_and_bad_host_forms_are_scope_checked(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    canonical_host = RAW.replace(b'name="10.10.1.5"', b'name="IN-SCOPE.LAB."').replace(
        b'<tag name="host-ip">10.10.1.5</tag>', b'<tag name="host-ip">invalid</tag>'
    )
    accepted = import_nessus_xml(canonical_host, _guard(), audit, ledger)
    assert len(accepted.findings) == 1
    assert accepted.findings[0].asset.hostname == "IN-SCOPE.LAB."

    for host in (b" in-scope.lab ", b"2001:db8::1"):
        raw = RAW.replace(b'name="10.10.1.5"', b'name="' + host + b'"').replace(
            b'<tag name="host-ip">10.10.1.5</tag>', b'<tag name="host-ip">invalid</tag>'
        )
        dropped = import_nessus_xml(raw, _guard(), audit, ledger)
        assert dropped.findings == []
        assert dropped.dropped_items == 1


def test_nessus_parser_refuses_dtd_and_size_over_cap() -> None:
    import pytest

    with pytest.raises(ValueError, match="DOCTYPE"):
        parse_nessus_xml(b"<!DOCTYPE x [<!ENTITY y 'z'>]><NessusClientData_v2/>")
    with pytest.raises(ValueError, match="limit"):
        parse_nessus_xml(b" " * (25_000_001))

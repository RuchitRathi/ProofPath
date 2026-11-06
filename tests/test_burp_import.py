"""Burp importer tests use an explicitly synthetic XML export shape."""

from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from proofpath.adapters.burp_import import import_burp_xml, parse_burp_xml
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.scope_guard import ScopeGuard
from proofpath.selftest import demo_resolver

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT / "tests" / "fixtures" / "burp_sample.xml").read_bytes()


def _guard() -> ScopeGuard:
    return ScopeGuard.from_yaml(ROOT / "scope.yaml", resolver=demo_resolver)


def test_synthetic_burp_import_finding_locator_excerpt_and_raw_messages(tmp_path: Path) -> None:
    issue, = parse_burp_xml(RAW)
    assert issue.requestresponse_count == 1
    assert issue.request_present and issue.response_present
    assert issue.request_base64 and issue.response_base64
    xpath = issue.locator.removeprefix("/issues/")
    assert ET.fromstring(RAW).find(xpath) is not None
    assert issue.excerpt in RAW.decode("utf-8")

    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    result = import_burp_xml(RAW, _guard(), audit, ledger)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.asset.ip == "10.10.1.5"
    assert finding.asset.hostname is None
    assert finding.port == 443
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert finding.cvss is None and finding.cves == []
    assert finding.evidence[0].evidence_id == result.evidence_id
    assert finding.evidence[0].locator == issue.locator
    assert finding.evidence[0].excerpt == issue.excerpt
    assert ledger.read_bytes(result.evidence_id) == RAW
    assert ledger.load(result.evidence_id).source_mode == "imported"
    assert audit.verify()[0]


def test_out_of_scope_burp_host_is_dropped_and_audited(tmp_path: Path) -> None:
    outside = RAW.replace(b"10.10.1.5", b"8.8.8.8")
    audit = AuditLog(tmp_path / "audit.jsonl")
    result = import_burp_xml(outside, _guard(), audit, Ledger(tmp_path / "evidence"))
    assert result.findings == []
    assert result.dropped_issues == 1
    assert any(entry.event_type == "out_of_scope" for entry in audit.read_entries())


def test_burp_import_refuses_doctype_and_caps_size() -> None:
    with pytest.raises(ValueError, match="DOCTYPE|entity declarations"):
        parse_burp_xml(b"<!DOCTYPE issues [<!ENTITY x 'y'>]><issues/>")
    with pytest.raises(ValueError, match="limit"):
        parse_burp_xml(b" " * 25_000_001)


def test_burp_parser_accepts_host_ip_attribute_and_direct_message_elements() -> None:
    raw = b'''<issues><issue><name>Synthetic direct message</name><host ip="10.10.1.5">app.lab</host><path>/x</path><location>q</location><severity>Low</severity><confidence>Tentative</confidence><request base64="true">QUJD</request><response base64="true">REVG</response></issue></issues>'''
    issue, = parse_burp_xml(raw)
    assert issue.target == "app.lab"
    assert issue.asset_ip == "10.10.1.5"
    assert issue.request_present and issue.response_present
    assert issue.request_base64 and issue.response_base64


def test_burp_mixed_case_trailing_dot_hostname_is_scope_checked(tmp_path: Path) -> None:
    raw = RAW.replace(b"https://10.10.1.5:443", b"https://IN-SCOPE.LAB.:443")
    result = import_burp_xml(raw, _guard(), AuditLog(tmp_path / "audit.jsonl"), Ledger(tmp_path / "evidence"))
    assert len(result.findings) == 1
    assert result.dropped_issues == 0
    assert result.findings[0].asset.ip == "10.10.1.5"


def test_burp_safe_internal_element_attlist_dtd_imports_and_keeps_raw_base64(tmp_path: Path) -> None:
    dtd_raw = (ROOT / "tests" / "fixtures" / "burp_with_internal_dtd.xml").read_bytes()
    issue, = parse_burp_xml(dtd_raw)
    assert issue.title == "Synthetic internal-DTD issue"
    assert issue.request_base64 and issue.response_base64
    assert len(issue.excerpt) <= 300
    assert issue.excerpt.encode("utf-8") in dtd_raw
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    result = import_burp_xml(dtd_raw, _guard(), audit, ledger)
    assert len(result.findings) == 1
    assert ledger.read_bytes(result.evidence_id) == dtd_raw
    assert ledger.load(result.evidence_id).source_mode == "imported"


@pytest.mark.parametrize(
    "doctype",
    [
        b'<!DOCTYPE issues [<!ENTITY x "boom">]>',
        b'<!DOCTYPE issues [<!ENTITY x SYSTEM "file:///proofpath-secret">]>',
        b'<!DOCTYPE issues [<!ENTITY % x "payload"> %x;]>',
        b'<!DOCTYPE issues [<!ENTITY a "ha"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>',
        b'<!DOCTYPE issues PUBLIC "public-id" "file:///proofpath-secret">',
    ],
)
def test_burp_entity_and_external_identifier_dtds_are_refused_before_resolution(doctype: bytes) -> None:
    payload = doctype + b"<issues/>"
    with pytest.raises(ValueError, match="refused|only ELEMENT/ATTLIST"):
        parse_burp_xml(payload)

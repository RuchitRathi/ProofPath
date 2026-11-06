"""Synthetic seeded correlation cases; no scanner output is represented as real."""

from pathlib import Path
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

from proofpath.adapters.burp_import import import_burp_xml
from proofpath.adapters.nessus_import import import_nessus_xml
from proofpath.adapters.nmap import parse_nmap_xml
from proofpath.audit import AuditLog
from proofpath.correlator import correlate_findings
from proofpath.ledger import Ledger
from proofpath.normalizer import normalize_nmap_observations
from proofpath.scope_guard import ScopeGuard
from proofpath.selftest import demo_resolver
from proofpath.risk import rank_findings
from proofpath.risk import rank_findings

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "seeded"


def _guard() -> ScopeGuard:
    return ScopeGuard.from_yaml(ROOT / "scope.yaml", resolver=demo_resolver)


def test_seeded_conflicts_duplicate_host_separation_and_low_confidence_candidate(tmp_path: Path) -> None:
    nessus_raw = (FIXTURES / "nessus.nessus").read_bytes()
    burp_raw = (FIXTURES / "burp.xml").read_bytes()
    nmap_raw = (FIXTURES / "nmap.xml").read_bytes()
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    nessus = import_nessus_xml(nessus_raw, _guard(), audit, ledger)
    burp = import_burp_xml(burp_raw, _guard(), audit, ledger)
    nmap_evidence = ledger.store(content=nmap_raw, tool="nmap", command=["synthetic_import"], status="ok", summary="synthetic seeded nmap fixture", source_mode="imported")
    observations = normalize_nmap_observations(parse_nmap_xml(nmap_raw, nmap_evidence.id))

    findings = correlate_findings([*nessus.findings, *burp.findings], observations)
    assert len(findings) == 3

    host_one_shared = next(item for item in findings if item.asset.ip == "10.10.1.5" and item.port == 80)
    assert set(host_one_shared.source_tools) == {"nessus", "burp"}
    assert host_one_shared.confidence == "high"
    assert host_one_shared.status == "confirmed"
    assert len(host_one_shared.evidence) == 2

    same_cve = [item for item in findings if "CVE-2099-900001" in item.cves]
    assert {item.asset.ip for item in same_cve} == {"10.10.1.5", "10.10.1.6"}
    assert len(same_cve) == 2

    conflict = next(item for item in same_cve if item.asset.ip == "10.10.1.6")
    assert conflict.status == "suspected"
    assert any("Severity conflict" in note and "nessus" in note and "burp" in note for note in conflict.conflict_notes)
    assert conflict.severity == "not_provided"

    low_item = next(item for item in findings if item.port == 443)
    assert low_item.confidence == "low"
    assert low_item.status == "false_positive_candidate"
    assert any(reference.evidence_id == nmap_evidence.id for reference in low_item.evidence)

    for finding in findings:
        for reference in finding.evidence:
            evidence = ledger.load(reference.evidence_id)
            raw = Path(evidence.artifact_path).read_bytes()
            assert reference.excerpt in raw.decode("utf-8")
            root = ET.fromstring(raw)
            if root.tag == "nmaprun":
                path = "." + reference.locator.removeprefix("/nmaprun")
            elif root.tag == "NessusClientData_v2":
                path = reference.locator.removeprefix("/NessusClientData_v2/")
            else:
                path = reference.locator.removeprefix("/issues/")
            assert root.find(path) is not None
    assert audit.verify()[0]


def test_seeded_risk_ranking_exposes_factors_and_imported_ports_are_unknown(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    nessus = import_nessus_xml((FIXTURES / "nessus.nessus").read_bytes(), _guard(), audit, ledger)
    burp = import_burp_xml((FIXTURES / "burp.xml").read_bytes(), _guard(), audit, ledger)
    nmap_raw = (FIXTURES / "nmap.xml").read_bytes()
    nmap_evidence = ledger.store(content=nmap_raw, tool="nmap", command=["synthetic_import"], status="ok", summary="synthetic seeded nmap fixture", source_mode="imported")
    observations = [row.model_copy(update={"source_mode": "imported"}) for row in parse_nmap_xml(nmap_raw, nmap_evidence.id)]
    findings = correlate_findings([*nessus.findings, *burp.findings], observations)
    ranked = rank_findings(findings, observations)
    low = next(item for item in ranked if item.finding.port == 443)
    conflict = next(item for item in ranked if item.finding.asset.ip == "10.10.1.6" and item.finding.port == 80)
    assert low.rank > max(item.rank for item in ranked if item.finding.status in {"confirmed", "suspected"})
    cvss_factor = next(factor for factor in conflict.factors if factor.name == "reported_cvss")
    exposure_factor = next(factor for factor in low.factors if factor.name == "observed_exposure")
    assert conflict.finding.cvss is None and cvss_factor.value == "not provided" and not cvss_factor.included
    assert exposure_factor.value == "unknown" and not exposure_factor.included
    assert all(factor.source and 0 <= factor.weight <= 1 for row in ranked for factor in row.factors)


def test_seeded_risk_ranking_exposes_factors_and_imported_ports_are_unknown(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    nessus = import_nessus_xml((FIXTURES / "nessus.nessus").read_bytes(), _guard(), audit, ledger)
    burp = import_burp_xml((FIXTURES / "burp.xml").read_bytes(), _guard(), audit, ledger)
    nmap_raw = (FIXTURES / "nmap.xml").read_bytes()
    nmap_evidence = ledger.store(content=nmap_raw, tool="nmap", command=["synthetic_import"], status="ok", summary="synthetic seeded nmap fixture", source_mode="imported")
    observations = [row.model_copy(update={"source_mode": "imported"}) for row in parse_nmap_xml(nmap_raw, nmap_evidence.id)]
    findings = correlate_findings([*nessus.findings, *burp.findings], observations)
    ranked = rank_findings(findings, observations)
    low = next(item for item in ranked if item.finding.port == 443)
    conflict = next(item for item in ranked if item.finding.asset.ip == "10.10.1.6" and item.finding.port == 80)
    assert low.rank > max(item.rank for item in ranked if item.finding.status in {"confirmed", "suspected"})
    cvss_factor = next(factor for factor in conflict.factors if factor.name == "reported_cvss")
    exposure_factor = next(factor for factor in low.factors if factor.name == "observed_exposure")
    assert conflict.finding.cvss is None and cvss_factor.value == "not provided" and not cvss_factor.included
    assert exposure_factor.value == "unknown" and not exposure_factor.included
    assert all(factor.source and 0 <= factor.weight <= 1 for row in ranked for factor in row.factors)


def test_nmap_normalizer_never_creates_vulnerability_finding(tmp_path: Path) -> None:
    raw = (FIXTURES / "nmap.xml").read_bytes()
    ledger = Ledger(tmp_path / "evidence")
    evidence = ledger.store(content=raw, tool="nmap", command=["synthetic_import"], status="ok", summary="synthetic", source_mode="imported")
    observations = normalize_nmap_observations(parse_nmap_xml(raw, evidence.id))
    assert observations
    assert not hasattr(observations[0], "cves")
    assert not hasattr(observations[0], "cvss")


def test_normalized_nessus_finding_fields_are_bounded_by_source_xml(tmp_path: Path) -> None:
    raw = (ROOT / "tests" / "fixtures" / "nessus_sample.nessus").read_bytes()
    result = import_nessus_xml(raw, _guard(), AuditLog(tmp_path / "audit.jsonl"), Ledger(tmp_path / "evidence"))
    finding, = result.findings
    xml_text = raw.decode("utf-8")
    assert finding.asset.ip in xml_text
    assert finding.title in xml_text
    assert str(finding.cvss) in xml_text
    assert all(cve in xml_text for cve in finding.cves)
    assert all(cwe in xml_text for cwe in finding.cwes)
    assert finding.severity == "medium"  # derived only from the fixture's numeric severity=2
    assert finding.service == "https"


def test_correlation_preserves_every_evidence_reference(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    nessus = import_nessus_xml((FIXTURES / "nessus.nessus").read_bytes(), _guard(), audit, ledger)
    burp = import_burp_xml((FIXTURES / "burp.xml").read_bytes(), _guard(), audit, ledger)
    seeded = [*nessus.findings, *burp.findings]
    before = sum(len(item.evidence) for item in seeded)
    merged = correlate_findings(seeded)
    assert sum(len(item.evidence) for item in merged) == before


def test_title_normalization_merges_punctuation_but_distinct_cves_stay_separate() -> None:
    from proofpath.schemas import EvidenceRef, Finding, FindingAsset

    base = Finding(
        id="f-1", title="TLS, Weak!", asset=FindingAsset(ip="10.10.1.5"), port=443,
        protocol="tcp", source_tools=["nessus"], evidence=[EvidenceRef(evidence_id="EV-0001", locator="/a", excerpt="a")],
        observed="source", confidence="low", status="suspected",
        first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc),
    )
    same = base.model_copy(deep=True, update={
        "id": "f-2", "title": " tls   weak??? ", "source_tools": ["burp"],
        "evidence": [EvidenceRef(evidence_id="EV-0002", locator="/b", excerpt="b")],
    })
    merged = correlate_findings([base, same])
    assert len(merged) == 1
    assert {ref.evidence_id for ref in merged[0].evidence} == {"EV-0001", "EV-0002"}
    assert set(merged[0].source_tools) == {"nessus", "burp"}

    cve_a = base.model_copy(deep=True, update={"cves": ["CVE-2024-1111"]})
    cve_same = same.model_copy(deep=True, update={"cves": ["CVE-2024-1111"]})
    cve_b = same.model_copy(deep=True, update={"cves": ["CVE-2024-2222"]})
    assert len(correlate_findings([cve_a, cve_same])) == 1
    assert len(correlate_findings([cve_a, cve_b])) == 2

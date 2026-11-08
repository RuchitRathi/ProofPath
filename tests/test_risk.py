from datetime import datetime, timezone

from proofpath.risk import WEIGHTS, rank_findings
from proofpath.schemas import EvidenceRef, Finding, FindingAsset, ServiceObservation
from proofpath.threat_intel import EpssRecord, KevRecord, NvdRecord, PublicThreatIntel


def _finding(identifier: str, severity: str, cvss: float | None, status: str = "suspected") -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(id=identifier, title="Reported issue", asset=FindingAsset(ip="10.10.1.5"), port=443, protocol="tcp", source_tools=["nessus"], evidence=[EvidenceRef(evidence_id="EV-0001", locator="/ReportItem", excerpt="Reported issue")], observed="Port 443/tcp", severity=severity, cvss=cvss, confidence="low", status=status, first_seen=now, last_seen=now)


def test_risk_uses_reported_factors_and_keeps_missing_cvss_unprovided() -> None:
    open_row = ServiceObservation(evidence_id="EV-0002", ip="10.10.1.5", port=443, protocol="tcp", state="open")
    ranked = rank_findings([_finding("F-high", "high", None), _finding("F-low", "low", 2.0)], [open_row])
    assert ranked[0].finding.id == "F-high"
    cvss = next(item for item in ranked[0].factors if item.name == "reported_cvss")
    assert cvss.value == "not provided" and not cvss.included
    assert ranked[0].priority_score is not None
    assert next(item for item in ranked[0].factors if item.name == "observed_exposure").source == "nmap:EV-0002"
    assert sum(WEIGHTS.values()) == 1


def test_unknown_factors_are_excluded_and_remaining_documented_weights_are_renormalized() -> None:
    finding = _finding("F-unknown", "not_provided", None)
    row = rank_findings([finding], [])[0]
    assert row.priority_score is not None  # default criticality and correlator confidence are documented inputs
    assert all(not factor.included for factor in row.factors if factor.name not in {"analyst_criticality", "correlation_confidence"})


def test_imported_open_observation_does_not_count_as_live_exposure() -> None:
    finding = _finding("F-imported", "high", None)
    imported = ServiceObservation(evidence_id="EV-IMPORT", ip="10.10.1.5", port=443, protocol="tcp", state="open", source_mode="imported")
    row = rank_findings([finding], [imported])[0]
    exposure = next(factor for factor in row.factors if factor.name == "observed_exposure")
    assert exposure.value == "unknown" and not exposure.included


def test_status_tier_places_false_positive_and_refuted_below_suspected() -> None:
    rows = rank_findings([_finding("F-refuted", "critical", 10, "refuted"), _finding("F-confirmed", "low", 1, "confirmed"), _finding("F-fp", "critical", 10, "false_positive_candidate")], [])
    assert [row.finding.id for row in rows] == ["F-confirmed", "F-fp", "F-refuted"]


def test_public_threat_context_changes_risk_without_rewriting_scanner_cvss() -> None:
    finding = _finding("F-real-cve", "low", None).model_copy(update={"cves": ["CVE-2021-44228"]})
    intel = PublicThreatIntel(
        fetched_at="2026-11-07T00:00:00+00:00",
        kev={"CVE-2021-44228": KevRecord(date_added="2021-12-10", required_action="Apply vendor fixes")},
        epss={"CVE-2021-44228": EpssRecord(probability=0.97, percentile=0.99)},
        nvd={"CVE-2021-44228": NvdRecord(cvss=10.0, severity="critical", version="3.1", evidence_id="EV-0009")},
        kev_evidence_id="EV-0007",
        epss_evidence_id="EV-0008",
    )
    baseline = rank_findings([finding], [])[0]
    enriched = rank_findings([finding], [], public_intel=intel)[0]
    assert enriched.priority_score is not None and baseline.priority_score is not None
    assert enriched.priority_score > baseline.priority_score
    assert finding.cvss is None
    assert next(item for item in enriched.factors if item.name == "reported_cvss").value == "not provided"
    assert next(item for item in enriched.factors if item.name == "nvd_cvss_context").source == "NVD:EV-0009:CVE-2021-44228"
    assert next(item for item in enriched.factors if item.name == "epss_probability").source == "FIRST EPSS:EV-0008:CVE-2021-44228"
    assert next(item for item in enriched.factors if item.name == "cisa_kev_listing").included
    assert sum(WEIGHTS.values()) == 1


def test_absent_kev_listing_is_not_treated_as_negative_exploitation_evidence() -> None:
    finding = _finding("F-not-listed", "medium", None).model_copy(update={"cves": ["CVE-2025-12345"]})
    intel = PublicThreatIntel(
        fetched_at="2026-11-07T00:00:00+00:00",
        epss={"CVE-2025-12345": EpssRecord(probability=0.04, percentile=0.8)},
        kev_evidence_id="EV-0010",
        epss_evidence_id="EV-0011",
    )
    row = rank_findings([finding], [], public_intel=intel)[0]
    kev = next(item for item in row.factors if item.name == "cisa_kev_listing")
    assert kev.value == "not listed in current KEV snapshot"
    assert kev.normalized is None and not kev.included

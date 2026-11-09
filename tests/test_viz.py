"""Tests for the attack-path / asset-risk visualization helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from proofpath.schemas import EvidenceRef, Finding, FindingAsset
from proofpath.viz import (
    attack_bars_html,
    attack_coverage,
    heatmap_html,
    remediation_trend_html,
    severity_by_asset,
)


def _finding(
    fid: str = "F-001",
    ip: str = "10.0.0.2",
    severity: str = "high",
    mapped_to: list[str] | None = None,
) -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        id=fid,
        title="Sample finding",
        asset=FindingAsset(ip=ip),
        port=80,
        protocol="tcp",
        service="http",
        source_tools=["nessus"],
        evidence=[EvidenceRef(evidence_id="EV-0001", locator="/x", excerpt="excerpt")],
        observed="sample",
        inference="",
        severity=severity,
        cvss=7.5,
        confidence="medium",
        status="suspected",
        cves=[],
        cwes=[],
        mapped_to=mapped_to if mapped_to is not None else ["mapped to NIST SP 800-115"],
        first_seen=now,
        last_seen=now,
    )


def test_severity_by_asset_counts_and_sorts() -> None:
    findings = [
        _finding(fid="F-001", ip="10.0.0.2", severity="critical"),
        _finding(fid="F-002", ip="10.0.0.2", severity="high"),
        _finding(fid="F-003", ip="10.0.0.1", severity="low"),
    ]
    matrix = severity_by_asset(findings)
    assert list(matrix) == ["10.0.0.1", "10.0.0.2"]
    assert matrix["10.0.0.2"]["critical"] == 1
    assert matrix["10.0.0.2"]["high"] == 1
    assert matrix["10.0.0.1"]["low"] == 1


def test_heatmap_html_contains_assets_and_severities() -> None:
    html = heatmap_html([_finding(ip="10.0.0.2", severity="critical")])
    assert "10.0.0.2" in html
    assert "critical" in html
    assert heatmap_html([]) == ""


def test_attack_coverage_parses_techniques() -> None:
    mapping = ["mapped to MITRE ATT&CK:T1190 (Exploit Public-Facing Application)"]
    coverage = attack_coverage([_finding(fid="F-001", mapped_to=mapping), _finding(fid="F-002", mapped_to=mapping)])
    assert len(coverage) == 1
    assert coverage[0]["technique"] == "T1190"
    assert coverage[0]["name"] == "Exploit Public-Facing Application"
    assert coverage[0]["count"] == 2
    assert coverage[0]["findings"] == ["F-001", "F-002"]


def test_attack_bars_html_empty_when_no_technique_mappings() -> None:
    assert attack_bars_html([_finding(mapped_to=["mapped to NIST SP 800-115"])]) == ""
    assert attack_bars_html([]) == ""


def test_attack_bars_html_renders_technique_label() -> None:
    mapping = ["mapped to MITRE ATT&CK:T1083 (File and Directory Discovery)"]
    html = attack_bars_html([_finding(mapped_to=mapping)])
    assert "T1083" in html and "File and Directory Discovery" in html


def test_remediation_trend_html() -> None:
    html = remediation_trend_html(2, 1, 1)
    assert "Remediated" in html
    assert "Persisting" in html
    assert "New" in html
    assert remediation_trend_html(0, 0, 0) == ""

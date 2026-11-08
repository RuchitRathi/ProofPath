"""Tests for SARIF export and retesting change comparison diff engine."""

from datetime import datetime, timezone
from pathlib import Path
import json

from proofpath.diff import compare_assessments
from proofpath.report.sarif import export_sarif
from proofpath.schemas import EvidenceRef, Finding, FindingAsset


def _sample_finding(
    fid: str,
    title: str,
    ip: str = "10.10.1.5",
    port: int = 80,
    severity: str = "high",
    cves: list[str] | None = None,
    cwes: list[str] | None = None,
    status: str = "suspected",
) -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        id=fid,
        title=title,
        asset=FindingAsset(ip=ip),
        port=port,
        protocol="tcp",
        service="http",
        source_tools=["nessus"],
        evidence=[EvidenceRef(evidence_id="EV-0001", locator="/test", excerpt="sample excerpt")],
        observed="Sample observed text",
        inference="",
        severity=severity,
        cvss=7.5,
        confidence="medium",
        status=status,
        cves=cves or [],
        cwes=cwes or [],
        mapped_to=["mapped to NIST SP 800-115", "mapped to OWASP Top 10:2021-A03"],
        first_seen=now,
        last_seen=now,
    )


def test_sarif_export(tmp_path: Path) -> None:
    f1 = _sample_finding("F-001", "XSS Vulnerability", cwes=["CWE-79"])
    f2 = _sample_finding("F-002", "Path Traversal", cves=["CVE-2021-41773"], cwes=["CWE-22"])
    sarif_file = tmp_path / "test.sarif"

    doc = export_sarif([f1, f2], sarif_file)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert len(run["results"]) == 2
    assert len(run["tool"]["driver"]["rules"]) == 2

    # Check file on disk
    loaded = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert loaded["version"] == "2.1.0"
    result_messages = [r["message"]["text"] for r in loaded["runs"][0]["results"]]
    assert any("XSS" in m for m in result_messages)
    assert any("Path Traversal" in m for m in result_messages)


def test_retesting_diff_engine() -> None:
    # Baseline has F1 (XSS) and F2 (Path Traversal)
    f1 = _sample_finding("F-001", "XSS Vulnerability", cwes=["CWE-79"])
    f2 = _sample_finding("F-002", "Path Traversal", cves=["CVE-2021-41773"])
    baseline = [f1, f2]

    # Current has F1 (persisting), F2 (refuted by recheck), and F3 (new SQLi)
    f1_curr = _sample_finding("F-001", "XSS Vulnerability", cwes=["CWE-79"])
    f2_refuted = _sample_finding("F-002", "Path Traversal", cves=["CVE-2021-41773"], status="refuted")
    f3_new = _sample_finding("F-003", "SQL Injection", cwes=["CWE-89"])
    current = [f1_curr, f2_refuted, f3_new]

    diff = compare_assessments(baseline, current)
    assert diff.total_new == 1
    assert diff.new_findings[0].id == "F-003"
    assert diff.total_persisting == 1
    assert diff.persisting_findings[0][0].id == "F-001"
    assert diff.total_remediated == 1
    assert diff.remediated_findings[0].id == "F-002"
    assert diff.summary() == {"new": 1, "persisting": 1, "remediated": 1}


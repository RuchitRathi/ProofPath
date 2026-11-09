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
    mapped_to: list[str] | None = None,
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
        mapped_to=mapped_to if mapped_to is not None else ["mapped to NIST SP 800-115", "mapped to OWASP Top 10:2021-A03"],
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


def test_report_includes_retest_section_only_with_baseline(tmp_path: Path) -> None:
    from pypdf import PdfReader

    from proofpath.audit import AuditLog
    from proofpath.ledger import Ledger
    from proofpath.report.generator import generate_pdf

    ledger = Ledger(tmp_path / "evidence")
    ledger.store(content=b"sample", tool="nessus", command=["import"], status="ok", summary="synthetic fixture", source_mode="imported")

    baseline = [
        _sample_finding("F-001", "XSS Vulnerability", cwes=["CWE-79"]),
        _sample_finding("F-002", "Path Traversal", cves=["CVE-2021-41773"]),
    ]
    current = [
        _sample_finding("F-001", "XSS Vulnerability", cwes=["CWE-79"]),
        _sample_finding("F-003", "SQL Injection", cwes=["CWE-89"]),
    ]

    with_baseline = tmp_path / "with-baseline.pdf"
    generate_pdf(
        current, [], ledger, AuditLog(tmp_path / "a.jsonl"), with_baseline,
        engagement="test", scope_cidrs=["10.10.1.0/24"], baseline_findings=baseline,
    )
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(with_baseline)).pages)
    assert "Remediation Status (Retest vs Baseline)" in text
    assert text.index("7.7") < text.index("7.8") < text.index("Appendix A: Evidence Index")
    assert "Remediated" in text and "F-002" in text
    assert "Persisting" in text and "New" in text

    without = tmp_path / "without-baseline.pdf"
    generate_pdf(
        current, [], ledger, AuditLog(tmp_path / "b.jsonl"), without,
        engagement="test", scope_cidrs=["10.10.1.0/24"],
    )
    plain = "\n".join(page.extract_text() or "" for page in PdfReader(str(without)).pages)
    assert "Remediation Status" not in plain


def test_report_quality_upgrade_sections(tmp_path: Path) -> None:
    from pypdf import PdfReader

    from proofpath.audit import AuditLog
    from proofpath.ledger import Ledger
    from proofpath.report.generator import generate_pdf

    ledger = Ledger(tmp_path / "evidence")
    ledger.store(content=b"sample", tool="nessus", command=["import"], status="ok", summary="synthetic fixture", source_mode="imported")

    findings = [
        _sample_finding("F-001", "XSS Vulnerability", cwes=["CWE-79"], severity="critical"),
        _sample_finding(
            "F-002", "Path Traversal", cves=["CVE-2021-41773"], cwes=["CWE-22"], severity="high",
            mapped_to=["mapped to OWASP Top 10:2021-A01 (Broken Access Control)", "mapped to MITRE ATT&CK:T1083 (File and Directory Discovery)"],
        ),
    ]

    out = tmp_path / "quality.pdf"
    generate_pdf(
        findings, [], ledger, AuditLog(tmp_path / "a.jsonl"), out,
        engagement="test", scope_cidrs=["10.10.1.0/24"],
    )
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(out)).pages)

    # Executive-summary key themes with remediation horizon guidance
    assert "Key themes" in text
    assert "immediate (24 hours)" in text
    # Prioritised remediation roadmap inside section 7.5
    assert "Prioritised remediation roadmap" in text
    # ATT&CK / OWASP / NIST coverage mapped from observed CWEs
    assert "Observed coverage" in text
    assert "mapped to OWASP Top 10:2021-A03" in text
    assert "mapped to MITRE ATT&CK" in text
    # Evidence appendix index cross-reference
    assert "Finding" in text and "evidence cross-reference" in text
    assert text.index("Appendix A: Evidence Index") < text.index("Appendix B: Integration Status Matrix")



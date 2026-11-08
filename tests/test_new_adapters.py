"""Tests for OpenVAS, Nikto, OWASP ZAP, and Metasploit importers."""

from pathlib import Path
import pytest

from proofpath.adapters.openvas_import import import_openvas_xml
from proofpath.adapters.nikto_import import import_nikto_report
from proofpath.adapters.zap_import import import_zap_report
from proofpath.adapters.metasploit_import import import_metasploit_report
from proofpath.audit import AuditLog
from proofpath.correlator import correlate_findings
from proofpath.ledger import Ledger
from proofpath.scope_guard import ScopeGuard

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def test_openvas_import(tmp_path: Path) -> None:
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    raw = (FIXTURES / "openvas_sample.xml").read_bytes()

    result = import_openvas_xml(raw, guard, audit, ledger)
    assert result.parsed_items == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.asset.ip == "10.10.1.5"
    assert finding.port == 80
    assert "openvas" in finding.source_tools
    assert "CVE-2021-41773" in finding.cves
    assert "CWE-22" in finding.cwes
    assert any("mapped to OWASP Top 10" in s for s in finding.mapped_to)
    assert any("mapped to MITRE ATT&CK" in s for s in finding.mapped_to)


def test_nikto_import(tmp_path: Path) -> None:
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    raw = (FIXTURES / "nikto_sample.json").read_bytes()

    result = import_nikto_report(raw, guard, audit, ledger)
    assert result.parsed_items == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.asset.ip == "10.10.1.5"
    assert finding.port == 80
    assert "nikto" in finding.source_tools
    assert "CWE-200" in finding.cwes
    assert any("mapped to NIST SP 800-115" in s for s in finding.mapped_to)


def test_zap_import(tmp_path: Path) -> None:
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    raw = (FIXTURES / "zap_sample.xml").read_bytes()

    result = import_zap_report(raw, guard, audit, ledger)
    assert result.parsed_items == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.asset.ip == "10.10.1.5"
    assert finding.port == 80
    assert "zap" in finding.source_tools
    assert "CWE-79" in finding.cwes
    assert any("mapped to OWASP Top 10:2021-A03" in s for s in finding.mapped_to)


def test_metasploit_import(tmp_path: Path) -> None:
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    raw = (FIXTURES / "metasploit_sample.xml").read_bytes()

    result = import_metasploit_report(raw, guard, audit, ledger)
    assert result.parsed_items == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.asset.ip == "10.10.1.5"
    assert finding.port == 80
    assert "metasploit" in finding.source_tools
    assert "CVE-2021-41773" in finding.cves
    assert finding.validation_status == "validated_approved"


def test_cross_tool_correlation(tmp_path: Path) -> None:
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")

    # Import OpenVAS and Metasploit, both reporting on 10.10.1.5:80 with CVE-2021-41773
    ov_raw = (FIXTURES / "openvas_sample.xml").read_bytes()
    ms_raw = (FIXTURES / "metasploit_sample.xml").read_bytes()

    ov_result = import_openvas_xml(ov_raw, guard, audit, ledger)
    ms_result = import_metasploit_report(ms_raw, guard, audit, ledger)

    all_findings = [*ov_result.findings, *ms_result.findings]
    correlated = correlate_findings(all_findings)
    assert len(correlated) == 1
    merged = correlated[0]
    assert "openvas" in merged.source_tools
    assert "metasploit" in merged.source_tools
    assert merged.status == "confirmed"
    assert merged.confidence == "high"
    assert len(merged.evidence) == 2


def test_rule_planner_proposes_all_enabled_tools(tmp_path: Path) -> None:
    from proofpath.proposer import RulePlanner
    from proofpath.schemas import ActionName, ServiceObservation

    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    obs = [
        ServiceObservation(
            ip="10.10.1.5",
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            product="Apache",
            version="2.4.41",
            evidence_id="EV-0001",
            locator="/nmaprun/host/ports/port[1]",
            excerpt="port 80 open http Apache 2.4.41",
            source_mode="imported",
        )
    ]
    planner = RulePlanner()
    candidates = planner.candidates(
        obs,
        guard.policy.engagement,
        enabled_actions=set(guard.policy.enabled_actions),
    )
    action_names = {c.action.name for c in candidates}
    assert ActionName.NMAP_SCAN in action_names
    assert ActionName.IMPORT_BURP in action_names
    assert ActionName.IMPORT_NESSUS in action_names
    assert ActionName.IMPORT_NIKTO in action_names
    assert ActionName.IMPORT_ZAP in action_names
    assert ActionName.IMPORT_OPENVAS in action_names



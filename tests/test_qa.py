"""Tests for the grounded report Q&A: uncited or unverifiable answers are refused."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.qa import answer_report_question, critique_answer
from proofpath.schemas import EvidenceRef, Finding, FindingAsset

# Ledger bytes that the finding claims are derived from; verify_text checks against these.
LEDGER_TEXT = "CVE-2021-41773 Apache httpd 10.10.1.5 port 80 CWE-22 evidence sample"


def _finding(
    fid: str = "F-001",
    title: str = "Outdated Apache httpd",
    severity: str = "high",
    ip: str = "10.10.1.5",
    port: int = 80,
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
        evidence=[EvidenceRef(evidence_id="EV-0001", locator="/x", excerpt="excerpt")],
        observed="Apache httpd on port 80",
        inference="",
        severity=severity,
        cvss=7.5,
        confidence="medium",
        status=status,
        cves=cves or [],
        cwes=cwes or [],
        mapped_to=["mapped to NIST SP 800-115"],
        first_seen=now,
        last_seen=now,
    )


def _setup(tmp_path: Path) -> tuple[Ledger, AuditLog]:
    ledger = Ledger(tmp_path / "evidence")
    ledger.store(content=LEDGER_TEXT.encode(), tool="nessus", command=["import"], status="ok", summary="synthetic", source_mode="imported")
    return ledger, AuditLog(tmp_path / "audit.jsonl")


class _FakeClient:
    def __init__(self, answer: str, evidence_ids: list[str]) -> None:
        self._payload = json.dumps({"answer": answer, "evidence_ids": evidence_ids})

    def complete(self, messages, schema):  # noqa: ANN001 - mirrors ModelClient protocol
        return self._payload


def _event_types(audit: AuditLog) -> list[str]:
    return [entry.event_type for entry in audit.read_entries()]


def test_deterministic_answer_cites_evidence_without_model(tmp_path: Path) -> None:
    ledger, audit = _setup(tmp_path)
    answer = answer_report_question("Summarize the findings", [_finding()], [], ledger, audit)
    assert answer.model_used is False
    assert answer.grounded is True
    assert "EV-0001" in answer.cited_evidence_ids
    assert "F-001" in answer.answer
    assert "qa_answered" in _event_types(audit)


def test_model_answer_with_unknown_evidence_is_rejected(tmp_path: Path) -> None:
    ledger, audit = _setup(tmp_path)
    client = _FakeClient("See EV-9999 for details.", ["EV-9999"])
    answer = answer_report_question("Summarize", [_finding()], [], ledger, audit, model_client=client)
    assert answer.model_used is False
    assert "qa_model_rejected" in _event_types(audit)


def test_model_answer_with_fabricated_cve_is_rejected(tmp_path: Path) -> None:
    ledger, audit = _setup(tmp_path)
    client = _FakeClient("CVE-2020-1234 affects the service (evidence EV-0001).", ["EV-0001"])
    answer = answer_report_question("Summarize", [_finding()], [], ledger, audit, model_client=client)
    assert answer.model_used is False
    assert "qa_model_rejected" in _event_types(audit)


def test_grounded_model_answer_is_accepted(tmp_path: Path) -> None:
    ledger, audit = _setup(tmp_path)
    client = _FakeClient("CVE-2021-41773 affects the Apache httpd service (evidence EV-0001).", ["EV-0001"])
    answer = answer_report_question("Summarize", [_finding()], [], ledger, audit, model_client=client)
    assert answer.model_used is True
    assert answer.grounded is True
    assert answer.cited_evidence_ids == ["EV-0001"]


def test_compliance_wording_triggers_downgrade(tmp_path: Path) -> None:
    ledger, audit = _setup(tmp_path)
    client = _FakeClient("CVE-2021-41773 is fixed and the system is fully compliant (evidence EV-0001).", ["EV-0001"])
    answer = answer_report_question("Summarize", [_finding()], [], ledger, audit, model_client=client)
    assert answer.model_used is False
    assert "qa_critique_downgrade" in _event_types(audit)


def test_no_findings_returns_empty_state(tmp_path: Path) -> None:
    ledger, audit = _setup(tmp_path)
    answer = answer_report_question("Anything", [], [], ledger, audit)
    assert "No findings" in answer.answer
    assert answer.cited_evidence_ids == []
    assert answer.grounded is True


def test_critique_flags_live_provenance_without_live_evidence() -> None:
    issues = critique_answer(
        "The port is live and currently open (evidence EV-0001).",
        ["EV-0001"],
        {"EV-0001"},
        [_finding()],
        [],
    )
    assert any("live exposure" in issue for issue in issues)

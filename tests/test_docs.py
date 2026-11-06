"""Docs stay aligned with the integration table."""

from pathlib import Path

from proofpath.cli import main
from proofpath.integrations import INTEGRATIONS

ROOT = Path(__file__).resolve().parents[1]


def test_project_doc_lists_every_integration() -> None:
    text = (ROOT / "docs" / "PROJECT.md").read_text(encoding="utf-8")
    for item in INTEGRATIONS:
        assert f"| {item['tool']} | {item['mode']} |" in text


def test_project_schema_docs_match_finding_and_evidence_models() -> None:
    from proofpath.schemas import EvidenceRef, Finding

    project = (ROOT / "docs" / "PROJECT.md").read_text(encoding="utf-8")
    progress = (ROOT / "docs" / "PROGRESS.md").read_text(encoding="utf-8")
    finding_fields = set(Finding.model_fields)
    evidence_ref_fields = set(EvidenceRef.model_fields)
    for field in finding_fields:
        assert f"`{field}`" in project
    for field in evidence_ref_fields:
        assert f"`{field}`" in project
    assert "source_mode" in progress
    assert "ReportLab" in progress


def test_project_confidence_table_documents_code_cases() -> None:
    project = (ROOT / "docs" / "PROJECT.md").read_text(encoding="utf-8")
    for case in (
        "Two or more independent reporting sources, no scalar conflict | high | confirmed",
        "One reporting source, no contradiction | Retain that source's confidence | Retain that source's status",
        "Sources disagree on severity, CVSS, vector, or service | Lower of the source confidences | suspected",
        "Low-confidence, single-source finding contradicted by nmap `closed` | low | false_positive_candidate",
        "Other nmap `closed` contradiction | Retain existing confidence | suspected",
    ):
        assert case in project


def test_docs_do_not_claim_compliance() -> None:
    for path in (ROOT / "docs").rglob("*.md"):
        assert "compliant with" not in path.read_text(encoding="utf-8").lower()


def test_redteam_command() -> None:
    assert main(["redteam", "--scope", str(ROOT / "scope.yaml")]) == 0

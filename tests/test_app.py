"""Streamlit AppTest coverage for scope denials and empty ports."""

from pathlib import Path
from datetime import datetime, timezone
import subprocess

from streamlit.testing.v1 import AppTest
from streamlit.runtime.uploaded_file_manager import UploadedFile, UploadedFileRec

from proofpath.audit import AuditLog

ROOT = Path(__file__).resolve().parents[1]


def _submit(target: str, monkeypatch, ports: str = "80") -> str:
    def missing_nmap(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise FileNotFoundError("test fake: no executable started")

    monkeypatch.setattr(subprocess, "run", missing_nmap)
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=10).run()
    app.text_input[0].set_value("List services")
    app.text_input[1].set_value(target)
    app.text_input[2].set_value(ports)
    app.button[0].click().run()
    visible = [element.value for element in app.text if isinstance(element.value, str)]
    visible.extend(element.value for element in app.markdown if isinstance(element.value, str))
    visible.extend(element.value for element in app.error if isinstance(element.value, str))
    return "\n".join(visible)


def test_ui_denies_public_and_excluded_targets_and_empty_ports(monkeypatch) -> None:
    audit_path = ROOT / "data" / "audit.jsonl"
    audit = AuditLog(audit_path)
    initial_count = len(audit.read_entries())
    public = _submit("8.8.8.8", monkeypatch)
    assert "Scope allowed: **False**" in public
    assert "Status: `denied`" in public
    assert "Evidence ID: `none`" in public
    new_entries = AuditLog(audit_path).read_entries()[initial_count:]
    assert [entry.event_type for entry in new_entries[-2:]] == ["analyst_request", "scope_decision"]
    assert new_entries[-1].details["allowed"] is False

    excluded = _submit("10.10.0.1", monkeypatch)
    assert "Scope allowed: **False**" in excluded
    assert "excluded" in excluded

    empty_ports = _submit("10.10.1.5", monkeypatch, "")
    assert "ports are required" in empty_ports

    cidr_target = _submit("10.10.1.0/24", monkeypatch)
    assert "Scope allowed: **False**" in cidr_target
    assert "Evidence ID: `none`" in cidr_target

    live_without_binary = _submit("10.10.1.5", monkeypatch, "80")
    assert "Status: `tool_not_found`" in live_without_binary
    assert "source mode: **live**" in live_without_binary
    assert "Evidence ID: `none`" in live_without_binary


def test_ui_denies_cidr_range_wildcard_and_comma_list_targets(monkeypatch) -> None:
    for target in ("10.10.1.0/24", "10.10.1.1-20", "10.10.1.*", "10.10.1.5,10.10.1.6"):
        visible = _submit(target, monkeypatch)
        assert "Scope allowed: **False**" in visible
        assert "Evidence ID: `none`" in visible


def _import_upload(name: str, data: bytes) -> AppTest:
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=20).run()
    app.session_state["nessus_import_file"] = UploadedFile(
        UploadedFileRec(f"test-{name}", name, "application/xml", data), None
    )
    app.button[1].click().run()
    return app


def test_import_ui_reports_malformed_xml_without_crashing() -> None:
    app = _import_upload("bad.nessus", b"<not-xml>")
    assert not app.exception
    error = "\n".join(item.value for item in app.error)
    assert "filename: bad.nessus" in error
    assert "source_mode=imported" in error
    assert "parse errors: 1" in error
    assert "SHA-256:" in error


def test_import_ui_rejects_oversized_upload_before_parser() -> None:
    from proofpath.xml_evidence import MAX_IMPORT_BYTES

    app = _import_upload("too-large.nessus", b" " * (MAX_IMPORT_BYTES + 1))
    assert not app.exception
    error = "\n".join(item.value for item in app.error)
    assert "import limit" in error or "upload exceeds" in error
    assert "parse errors: 1" in error


def test_import_ui_rejects_doctype_nessus_upload_without_crashing() -> None:
    raw = b'<!DOCTYPE x [<!ENTITY y "z">]><NessusClientData_v2/>'
    app = _import_upload("doctype.nessus", raw)
    assert not app.exception
    error = "\n".join(item.value for item in app.error)
    assert "DOCTYPE" in error
    assert "evidence ID: none" in error


def test_blank_ollama_tag_shows_rule_plan_fallback_and_logs(tmp_path: Path, monkeypatch) -> None:
    from proofpath.schemas import ServiceObservation
    from proofpath.ledger import Ledger

    config_path = tmp_path / "blank-ollama.yaml"
    config_path.write_text('base_url: "http://127.0.0.1:11434"\nmodel_tag: ""\n', encoding="utf-8")
    monkeypatch.setenv("PROOFPATH_OLLAMA_CONFIG", str(config_path))
    data_root = tmp_path / "data"
    monkeypatch.setenv("PROOFPATH_DATA_DIR", str(data_root))
    evidence = Ledger(data_root / "evidence").store(content=b"synthetic open web service", tool="fixture", command=["fixture"], status="ok", summary="synthetic plan test", source_mode="imported")

    audit_path = data_root / "audit.jsonl"
    initial_count = len(AuditLog(audit_path).read_entries())
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=20).run()
    app.session_state["observations"] = [ServiceObservation(
        evidence_id=evidence.id, ip="10.10.250.250", port=8443, protocol="tcp", state="open", service="https", source_mode="imported"
    )]
    app.run()
    next(button for button in app.button if button.label == "Generate plan").click().run()
    warnings = "\n".join(item.value for item in app.warning)
    assert "Proposer unavailable: deterministic top rule-ranked candidate shown" in warnings
    plan_text = "\n".join([*(item.value for item in app.markdown), *(item.value for item in app.text), *(item.value for item in app.caption)])
    assert "Decision trace (code generated)" in plan_text
    assert "one-port Nmap TCP connect recheck" in plan_text
    assert "Expected result: A live Nmap service observation" in plan_text
    assert "Observed facts (code generated)" in plan_text
    assert not app.exception
    recent = AuditLog(audit_path).read_entries()[initial_count:]
    assert any(entry.event_type == "proposer_unavailable" for entry in recent)


def test_findings_ui_displays_conflict_note_and_both_sources() -> None:
    from proofpath.schemas import EvidenceRef, Finding, FindingAsset

    now = datetime.now(timezone.utc)
    findings = [
        Finding(
            id="nessus-1", title="Synthetic conflict", asset=FindingAsset(ip="10.10.1.5"), port=443,
            protocol="tcp", source_tools=[source], evidence=[EvidenceRef(evidence_id=evidence, locator="/issue", excerpt=source)],
            observed="synthetic", severity=severity, cves=["CVE-2024-12345"], confidence="low", status="suspected",
            first_seen=now, last_seen=now,
        )
        for source, evidence, severity in (("nessus", "EV-0001", "medium"), ("burp", "EV-0002", "high"))
    ]
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=20).run()
    app.session_state["raw_findings"] = findings
    app.run()
    warnings = "\n".join(item.value for item in app.warning)
    assert "Severity conflict: nessus=medium; burp=high" in warnings
    tables = "\n".join(str(item.value) for item in app.dataframe)
    assert "nessus, burp" in tables
    assert not app.exception

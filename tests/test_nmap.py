"""Nmap argv construction, XML parsing, and the execution choke point."""

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from proofpath.adapters.base import execute_action
from proofpath.adapters.nikto import run as nikto_run
from proofpath.adapters.nmap import NmapAdapter, NmapExecutionConfig, RecordedNmapXMLAdapter, build_argv, parse_nmap_xml
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName, GuardDecision
from proofpath.scope_guard import ScopeGuard
from proofpath.selftest import demo_resolver

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (ROOT / "tests" / "fixtures" / "nmap_sample.xml").read_bytes()
SCOPE = ROOT / "scope.yaml"


def _guard() -> ScopeGuard:
    return ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)


def _action(target: str = "in-scope.lab", ports: list[int] | None = None) -> Action:
    return Action(
        id="act-nmap",
        name=ActionName.NMAP_SCAN,
        target=target,
        ports=ports or [80, 443],
        arguments={"service_detection": True, "timing": 2, "host_timeout_seconds": 60},
        engagement_id="lab-01",
    )


def test_parser_reads_only_fixture_facts() -> None:
    rows = parse_nmap_xml(FIXTURE, "EV-0001")
    assert len(rows) == 2
    open_port = rows[0]
    assert open_port.evidence_id == "EV-0001"
    assert open_port.ip == "10.10.1.5"
    assert open_port.port == 80
    assert open_port.state == "open"
    assert open_port.service == "http"
    assert open_port.product == "nginx"
    assert open_port.version == "1.25.0"
    assert rows[1].port == 443
    assert rows[1].state == "closed"
    assert rows[1].service is None
    assert not hasattr(open_port, "cvss")
    root = ET.fromstring(FIXTURE)
    for row in rows:
        located = root.find("." + row.locator.removeprefix("/nmaprun"))
        assert located is not None
        assert row.excerpt in FIXTURE.decode("utf-8")


def test_parser_ignores_script_elements_and_refuses_doctype() -> None:
    xml = FIXTURE.replace(
        b'method="probed"/>',
        b'method="probed"/><script id="http-vuln" output="CVE-2099-0000"/>',
        1,
    )
    assert b"<script" in xml
    rows = parse_nmap_xml(xml, "EV-0009")
    assert rows[0].version == "1.25.0"
    assert "CVE-2099-0000" not in rows[0].model_dump().values()
    with pytest.raises(ValueError):
        parse_nmap_xml(b"<!DOCTYPE nmaprun [<!ENTITY x 'y'>]><nmaprun></nmaprun>", "EV-0001")


def test_execute_allowed_scan(tmp_path: Path) -> None:
    calls: list[tuple[list[str], dict]] = []

    def runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((list(argv), dict(kwargs)))
        return subprocess.CompletedProcess(argv, 0, stdout=FIXTURE, stderr=b"")

    guard = _guard()
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    result = execute_action(
        _action(),
        guard,
        audit,
        ledger,
        {ActionName.NMAP_SCAN: NmapAdapter(runner=runner)},
    )
    assert result.status == "ok"
    assert result.evidence_id == "EV-0001"
    assert result.services[0].version == "1.25.0"
    assert result.services[0].evidence_id == "EV-0001"
    assert ledger.verify_artifact("EV-0001") is True
    assert ledger.read_bytes("EV-0001") == FIXTURE
    argv, kwargs = calls[0]
    assert kwargs["shell"] is False
    assert argv[0] == "nmap"
    assert "-sV" in argv
    assert "--script" not in argv
    assert "in-scope.lab" not in argv
    assert "10.10.1.5" in argv
    assert audit.verify()[0] is True
    assert [entry.event_type for entry in audit.read_entries()] == ["scope_decision", "nmap_result"]


def test_denied_target_does_not_start_nmap(tmp_path: Path) -> None:
    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError("nmap was started")

    audit = AuditLog(tmp_path / "audit.jsonl")
    result = execute_action(
        _action("8.8.8.8"),
        _guard(),
        audit,
        Ledger(tmp_path / "evidence"),
        {ActionName.NMAP_SCAN: NmapAdapter(runner=runner)},
    )
    assert result.status == "denied"
    assert result.evidence_id is None
    assert result.services == []
    assert audit.read_entries()[0].details["allowed"] is False


def test_forged_decision_does_not_start_nmap(tmp_path: Path) -> None:
    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError("nmap was started")

    guard = _guard()
    decision = guard.check(_action("8.8.8.8"))
    forged = decision.model_copy(
        update={
            "allowed": True,
            "tool": "nmap",
            "resolved_ips": ["10.10.1.5"],
            "ports": [80],
            "normalized_arguments": {"service_detection": True, "timing": 2, "host_timeout_seconds": 60},
        }
    )
    result = NmapAdapter(runner=runner).run(
        forged,
        guard,
        AuditLog(tmp_path / "audit.jsonl"),
        Ledger(tmp_path / "evidence"),
        "analyst",
    )
    assert result.status == "denied"


def test_timeout_stores_bytes_without_services(tmp_path: Path) -> None:
    def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(cmd=argv, timeout=1, output=FIXTURE)

    guard = _guard()
    decision = guard.check(_action())
    result = NmapAdapter(runner=runner).run(
        decision,
        guard,
        AuditLog(tmp_path / "audit.jsonl"),
        Ledger(tmp_path / "evidence"),
        "analyst",
    )
    assert result.status == "timeout"
    assert result.services == []
    assert result.evidence_id == "EV-0001"
    assert Ledger(tmp_path / "evidence").read_bytes("EV-0001") == FIXTURE


def test_invalid_xml_is_an_error_without_services(tmp_path: Path) -> None:
    def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, stdout=b"not xml", stderr=b"")

    guard = _guard()
    decision = guard.check(_action())
    result = NmapAdapter(runner=runner).run(
        decision,
        guard,
        AuditLog(tmp_path / "audit.jsonl"),
        Ledger(tmp_path / "evidence"),
        "analyst",
    )
    assert result.status == "error"
    assert result.services == []
    assert result.evidence_id == "EV-0001"


def test_missing_binary(tmp_path: Path) -> None:
    guard = _guard()
    decision = guard.check(_action())
    result = NmapAdapter(binary="proofpath-nmap-missing").run(
        decision,
        guard,
        AuditLog(tmp_path / "audit.jsonl"),
        Ledger(tmp_path / "evidence"),
        "analyst",
    )
    assert result.status == "tool_not_found"
    assert result.evidence_id is None


def test_recorded_xml_import_is_labeled_imported(tmp_path: Path) -> None:
    guard = _guard()
    action = _action()
    action.name = ActionName.IMPORT_NMAP_XML
    ledger = Ledger(tmp_path / "evidence")
    result = execute_action(action, guard, AuditLog(tmp_path / "audit.jsonl"), ledger, {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(FIXTURE)})
    assert result.status == "ok"
    assert result.evidence_id == "EV-0001"
    assert ledger.load(result.evidence_id).source_mode == "imported"
    assert result.services[0].evidence_id == result.evidence_id


def test_recorded_xml_import_drops_and_audits_out_of_scope_observations(tmp_path: Path) -> None:
    guard = _guard()
    action = _action(ports=[80, 443])
    action.name = ActionName.IMPORT_NMAP_XML
    altered = FIXTURE.replace(b"10.10.1.5", b"8.8.8.8")
    ledger = Ledger(tmp_path / "evidence")
    audit = AuditLog(tmp_path / "audit.jsonl")
    result = execute_action(action, guard, audit, ledger, {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(altered)})
    assert result.status == "ok"
    assert result.evidence_id == "EV-0001"
    assert result.dropped_items == 2
    assert result.services == []
    assert any(entry.event_type == "out_of_scope" and entry.details["host"] == "8.8.8.8" for entry in audit.read_entries())
    assert ledger.load(result.evidence_id).source_mode == "imported"


def test_build_argv_rejects_raw_hostname() -> None:
    decision = GuardDecision(
        allowed=True,
        reason="test",
        resolved_ips=["in-scope.lab"],
        ports=[80],
        tool="nmap",
        normalized_arguments={"service_detection": True, "timing": 2, "host_timeout_seconds": 60},
        token="x",
    )
    with pytest.raises(ValueError):
        build_argv("nmap", decision)


def test_skip_host_discovery_adds_pn_only_when_guarded_true() -> None:
    guard = _guard()
    action = _action()
    action.arguments["skip_host_discovery"] = True
    decision = guard.check(action)
    assert guard.verify_decision(decision)
    assert "-Pn" in build_argv("nmap", decision)
    off = guard.check(_action())
    assert "-Pn" not in build_argv("nmap", off)


def test_wsl_argv_wraps_only_the_guarded_nmap_argument_list() -> None:
    decision = _guard().check(_action())
    argv = build_argv("nmap", decision, wsl_distribution="Ubuntu")
    assert argv[:5] == ["wsl.exe", "--distribution", "Ubuntu", "--exec", "nmap"]
    assert argv[5:8] == ["-sT", "-oX", "-"]
    assert "-sS" not in argv
    assert "10.10.1.5" in argv
    assert "--script" not in argv
    with pytest.raises(ValueError, match="distribution"):
        build_argv("nmap", decision, wsl_distribution="Ubuntu;bash")


def test_wsl_settings_file_selects_ubuntu() -> None:
    config = NmapExecutionConfig.from_yaml(ROOT / "nmap.yaml")
    assert config.runtime == "wsl"
    assert config.distribution == "Ubuntu"


def test_planned_nikto_refuses() -> None:
    with pytest.raises(RuntimeError):
        nikto_run()


def test_source_never_sets_shell_true() -> None:
    paths = [ROOT / "app.py", *(ROOT / "src").rglob("*.py")]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "shell=True" not in text
        assert "shell = True" not in text

"""Tests for Conversational Security Assistant."""

from pathlib import Path
from proofpath.assistant import SecurityAssistant
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import ActionName, Finding, FindingAsset, ServiceObservation
from proofpath.scope_guard import ScopeGuard
from proofpath.selftest import demo_resolver

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "scope.yaml"


def _assistant(tmp_path: Path) -> SecurityAssistant:
    guard = ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    return SecurityAssistant(guard, audit, ledger)


def test_assistant_verifies_in_scope_target(tmp_path: Path) -> None:
    assistant = _assistant(tmp_path)
    res = assistant.parse_request("Scan internal host 10.10.1.5 on port 80, 443 for web services")
    assert res.target == "10.10.1.5"
    assert res.ports == [80, 443]
    assert res.intent == "reconnaissance"
    assert res.scope_allowed is True
    assert "authorized" in res.assistant_reply.lower()
    assert res.staged_action is not None
    assert res.staged_action.name == ActionName.NMAP_SCAN


def test_assistant_rejects_out_of_scope_target(tmp_path: Path) -> None:
    assistant = _assistant(tmp_path)
    res = assistant.parse_request("Scan public server 8.8.8.8 on port 53")
    assert res.target == "8.8.8.8"
    assert res.scope_allowed is False
    assert "denied" in res.assistant_reply.lower()
    assert res.staged_action is None


def test_assistant_warns_on_active_exploitation(tmp_path: Path) -> None:
    assistant = _assistant(tmp_path)
    res = assistant.parse_request("Can we run a Metasploit exploit against 10.10.1.5?")
    assert res.intent == "validation_inquiry"
    assert "human approval" in res.assistant_reply.lower()
    assert "autonomous exploitation is strictly prohibited" in res.assistant_reply.lower()


def test_assistant_suggests_web_assessment_when_web_ports_open(tmp_path: Path) -> None:
    assistant = _assistant(tmp_path)
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
            source_mode="live",
        )
    ]
    res = assistant.parse_request("Assess web applications on 10.10.1.5", observations=obs)
    assert res.intent == "web_assessment"
    assert "zap" in res.assistant_reply.lower() or "burp" in res.assistant_reply.lower()
    assert "nikto" in res.assistant_reply.lower()


def test_assistant_audits_conversation(tmp_path: Path) -> None:
    assistant = _assistant(tmp_path)
    assistant.parse_request("Show me report status for this engagement")
    entries = assistant.audit.read_entries()
    conv_entries = [e for e in entries if e.event_type == "analyst_conversation"]
    assert len(conv_entries) == 1
    assert conv_entries[0].details["intent"] == "reporting_inquiry"

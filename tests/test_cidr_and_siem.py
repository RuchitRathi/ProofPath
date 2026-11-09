"""CIDR sweep orchestration, scope-bounded enumeration, and SIEM CEF export."""

from datetime import datetime, timezone
from pathlib import Path

import yaml

from proofpath.adapters.base import ToolResult
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.orchestrator import sweep_cidr
from proofpath.report.cef import export_cef, export_syslog, finding_to_cef, write_cef
from proofpath.schemas import ActionName, EvidenceRef, Finding, FindingAsset, GuardDecision, ServiceObservation
from proofpath.scope_guard import ScopeGuard, ScopePolicy
from proofpath.selftest import demo_resolver

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "scope.yaml"


def _guard(updates: dict | None = None) -> ScopeGuard:
    raw = yaml.safe_load(SCOPE.read_text(encoding="utf-8"))
    if updates:
        raw.update(updates)
    return ScopeGuard(ScopePolicy.model_validate(raw), resolver=demo_resolver)


def _finding(fid: str = "F-CEF-001", title: str = "Reported service issue", *, severity: str = "high") -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        id=fid,
        title=title,
        asset=FindingAsset(ip="10.10.1.5"),
        port=80,
        protocol="tcp",
        service="http",
        source_tools=["nessus"],
        evidence=[EvidenceRef(evidence_id="EV-0001", locator="/finding", excerpt="excerpt")],
        observed="Observed port 80/tcp open",
        severity=severity,
        cvss=7.5,
        confidence="medium",
        status="suspected",
        cves=["CVE-2021-41773"],
        cwes=["CWE-79"],
        first_seen=now,
        last_seen=now,
    )


# ---------------------------------------------------------------------------
# Scope-bounded enumeration
# ---------------------------------------------------------------------------

def test_enumerate_hosts_drops_network_and_broadcast() -> None:
    hosts, error = _guard().enumerate_hosts("10.20.0.0/29")
    assert error is None
    assert hosts == ["10.20.0.1", "10.20.0.2", "10.20.0.3", "10.20.0.4", "10.20.0.5", "10.20.0.6"]


def test_enumerate_hosts_respects_excluded_hosts() -> None:
    hosts, error = _guard().enumerate_hosts("10.10.0.0/30")
    assert error is None
    assert hosts == ["10.10.0.2"]


def test_enumerate_hosts_rejects_out_of_scope_range() -> None:
    hosts, error = _guard().enumerate_hosts("8.8.8.0/29")
    assert hosts == []
    assert error is not None and "not inside an allowed range" in error


def test_enumerate_hosts_rejects_range_above_cap() -> None:
    hosts, error = _guard().enumerate_hosts("10.20.0.0/16", max_hosts=256)
    assert hosts == []
    assert error is not None and "sweep cap" in error


def test_enumerate_hosts_single_host_cidr() -> None:
    hosts, error = _guard().enumerate_hosts("10.20.0.10/32")
    assert error is None
    assert hosts == ["10.20.0.10"]


# ---------------------------------------------------------------------------
# Sweep orchestration
# ---------------------------------------------------------------------------

class _RecordingAdapter:
    def __init__(self) -> None:
        self.targets: list[str] = []

    def run(self, decision: GuardDecision, guard: ScopeGuard, audit: AuditLog, ledger: Ledger, actor: str) -> ToolResult:
        ip = decision.resolved_ips[0]
        self.targets.append(ip)
        service = ServiceObservation(
            evidence_id=f"EV-{len(self.targets):04d}",
            ip=ip,
            port=decision.ports[0],
            protocol="tcp",
            state="open",
            service="http",
        )
        return ToolResult(
            status="ok",
            decision=decision,
            evidence_id=f"EV-{len(self.targets):04d}",
            services=[service],
            message="scan complete",
        )


def test_sweep_scans_every_in_scope_host(tmp_path: Path) -> None:
    guard = _guard({"allowed_cidrs": ["10.20.0.0/29"], "excluded_hosts": []})
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    adapter = _RecordingAdapter()

    report = sweep_cidr(guard, audit, ledger, {ActionName.NMAP_SCAN: adapter}, "10.20.0.0/29", [80], ["10.20.0.1", "10.20.0.2"])

    assert adapter.targets == ["10.20.0.1", "10.20.0.2"]
    assert report.scanned == 2
    assert len(report.services) == 2
    events = [entry.event_type for entry in audit.read_entries()]
    assert "cidr_sweep_planned" in events and "cidr_sweep_completed" in events
    assert events.count("scope_decision") == 2


def test_sweep_still_denies_out_of_scope_host(tmp_path: Path) -> None:
    guard = _guard({"allowed_cidrs": ["10.20.0.0/29"], "excluded_hosts": []})
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    adapter = _RecordingAdapter()

    report = sweep_cidr(guard, audit, ledger, {ActionName.NMAP_SCAN: adapter}, "10.20.0.0/29", [80], ["10.20.0.1", "8.8.8.8"])

    assert adapter.targets == ["10.20.0.1"]
    assert report.scanned == 1
    assert report.denied == 1
    denied = next(row for row in report.results if row.host == "8.8.8.8")
    assert denied.allowed is False and "outside allowed ranges" in denied.reason


# ---------------------------------------------------------------------------
# SIEM CEF / syslog export
# ---------------------------------------------------------------------------

def test_cef_record_shape_and_header_escaping() -> None:
    line = finding_to_cef(_finding(title="XSS | Injection"))
    assert line.startswith("CEF:0|ProofPath|ProofPath VAPT|0.1.0|CVE-2021-41773|")
    assert "XSS \\| Injection" in line
    assert "|src=10.10.1.5 dpt=80 proto=tcp" in line
    assert "externalId=F-CEF-001" in line
    assert "cs1Label=CVSS cs1=7.5" in line
    assert "cs2Label=CVE cs2=CVE-2021-41773" in line
    assert "cs3Label=CWE cs3=CWE-79" in line


def test_cef_export_writes_one_record_per_finding(tmp_path: Path) -> None:
    findings = [_finding("F-1"), _finding("F-2", severity="critical")]
    records = export_cef(findings)
    assert len(records) == 2

    out = tmp_path / "findings.cef"
    written = write_cef(findings, out)
    assert written == records
    assert out.read_text(encoding="utf-8").strip().splitlines() == records


def test_syslog_frames_cef_with_priority() -> None:
    lines = export_syslog([_finding()], facility=13, severity=5)
    assert len(lines) == 1
    assert lines[0].startswith("<109>")
    assert "CEF:0|ProofPath" in lines[0]

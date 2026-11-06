from datetime import datetime, timezone
from pathlib import Path

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import EvidenceRef, Finding, FindingAsset, ServiceObservation, ActionName
from proofpath.scope_guard import ScopeGuard
from proofpath.skeptic import analyze_findings, apply_observation_evidence, gate_recheck_proposal

ROOT = Path(__file__).resolve().parents[1]


def _finding() -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(id="F-SKEPTIC-1", title="Reported HTTP issue", asset=FindingAsset(ip="10.10.1.5"), port=80, protocol="tcp", service="http", source_tools=["nessus"], evidence=[EvidenceRef(evidence_id="EV-0001", locator="/ReportItem[1]", excerpt="Synthetic reported HTTP issue")], observed="Nessus reported an HTTP issue", severity="high", confidence="low", status="suspected", first_seen=now, last_seen=now)


def test_skeptic_proposes_guarded_single_port_recheck_without_running_it(tmp_path: Path) -> None:
    finding = _finding()
    proposals = analyze_findings([finding], [], "lab-01")
    assert len(proposals) == 1
    assert proposals[0].hypothesis.evidence_for[0].evidence_id == "EV-0001"
    assert proposals[0].hypothesis.evidence_against == []
    assert proposals[0].action.name == ActionName.NMAP_SCAN
    assert proposals[0].action.ports == [80]
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml", resolver=lambda _host: ["10.10.1.5"])
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    ledger.store(content=b"synthetic evidence", tool="nessus", command=["fixture"], status="ok", summary="synthetic", source_mode="imported")
    result = gate_recheck_proposal(proposals[0], guard, audit, ledger)
    assert result.status == "planned"
    assert any(item.event_type == "plan_candidate_queued" for item in audit.read_entries())


def test_skeptic_refutes_only_with_cited_contradictory_observation() -> None:
    finding = _finding()
    unchanged = apply_observation_evidence(finding, [])
    assert unchanged.status == "suspected"
    open_row = ServiceObservation(evidence_id="EV-0002", ip=finding.asset.ip, port=finding.port, protocol="tcp", state="open", locator="/nmap/port", excerpt="state open")
    assert apply_observation_evidence(finding, [open_row]).status == "suspected"
    closed_row = open_row.model_copy(update={"state": "closed", "evidence_id": "EV-0003", "excerpt": "state closed"})
    updated = apply_observation_evidence(finding, [closed_row])
    assert updated.status == "refuted"
    assert any(ref.evidence_id == "EV-0003" and ref.locator == "/nmap/port" for ref in updated.evidence)
    hypothesis = analyze_findings([finding], [closed_row], "lab-01")[0].hypothesis
    assert hypothesis.status == "refuted"
    assert any(ref.evidence_id == "EV-0003" for ref in hypothesis.evidence_against)

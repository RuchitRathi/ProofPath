"""Rule-based hypotheses and guarded recheck proposals; never executes a scan."""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict

from proofpath.schemas import Action, ActionName, EvidenceRef, Finding, Hypothesis, ServiceObservation
from proofpath.adapters.base import ToolResult, execute_action
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.proposer import ProposedAction, ProposalGateAdapter, Rationale
from proofpath.scope_guard import ScopeGuard


class SkepticProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hypothesis: Hypothesis
    action: Action
    planner_reason: str


def analyze_findings(
    findings: list[Finding], observations: list[ServiceObservation], engagement_id: str,
) -> list[SkepticProposal]:
    """Create hypotheses for suspected or single-source findings and a one-port nmap check."""
    results: list[SkepticProposal] = []
    for finding in findings:
        if finding.status not in {"suspected", "false_positive_candidate"} and len(finding.source_tools) != 1:
            continue
        matching = [row for row in observations if row.ip == finding.asset.ip and row.port == finding.port and row.protocol.casefold() == finding.protocol.casefold()]
        evidence_for = list(finding.evidence)
        evidence_against = [EvidenceRef(evidence_id=row.evidence_id, locator=row.locator, excerpt=row.excerpt) for row in matching if row.state.casefold() == "closed"]
        statement = f"Recheck whether {finding.title} is present on {finding.asset.ip}:{finding.port}/{finding.protocol}."
        hypothesis = Hypothesis(id="H-" + hashlib.sha256(finding.id.encode()).hexdigest()[:12], statement=statement, evidence_for=evidence_for, evidence_against=evidence_against, status="refuted" if evidence_against else "open")
        action = Action(
            id="skeptic-" + hashlib.sha256(f"{finding.id}|{finding.asset.ip}|{finding.port}".encode()).hexdigest()[:16],
            name=ActionName.NMAP_SCAN,
            target=finding.asset.ip,
            ports=[finding.port],
            arguments={"service_detection": True, "skip_host_discovery": False, "timing": 2, "host_timeout_seconds": 60},
            engagement_id=engagement_id,
            requested_by="skeptic",
        )
        results.append(SkepticProposal(hypothesis=hypothesis, action=action, planner_reason="Cheapest available safe discriminator: recheck this single in-scope port with nmap; execution remains a separate analyst action."))
    return results


def apply_observation_evidence(finding: Finding, observations: list[ServiceObservation]) -> Finding:
    """Mark refuted only when a cited matching closed-port observation exists."""
    contradicted = [row for row in observations if row.ip == finding.asset.ip and row.port == finding.port and row.protocol.casefold() == finding.protocol.casefold() and row.state.casefold() == "closed" and row.evidence_id and row.locator]
    if not contradicted:
        return finding.model_copy(deep=True)
    refs = list(finding.evidence)
    for row in contradicted:
        ref = EvidenceRef(evidence_id=row.evidence_id, locator=row.locator, excerpt=row.excerpt)
        if not any((item.evidence_id, item.locator, item.excerpt) == (ref.evidence_id, ref.locator, ref.excerpt) for item in refs):
            refs.append(ref)
    return finding.model_copy(update={"status": "refuted", "evidence": refs, "conflict_notes": list(dict.fromkeys([*finding.conflict_notes, "Recorded nmap closed-port observation contradicts the reported service endpoint."]))})



def gate_recheck_proposal(proposal: SkepticProposal, guard: ScopeGuard, audit: AuditLog, ledger: Ledger) -> ToolResult:
    """Queue the proposed single-port nmap check through execute_action and the guard."""
    evidence_ids = list(dict.fromkeys(ref.evidence_id for ref in proposal.hypothesis.evidence_for))
    rationale = Rationale(
        observed=[f"Finding cites {evidence_id}." for evidence_id in evidence_ids] or ["No evidence IDs were available."],
        inferred="Inference: a guarded single-port recheck can provide new endpoint evidence.",
        why=proposal.planner_reason,
    )
    model_shape = ProposedAction(action=proposal.action, rationale=rationale)
    return execute_action(
        proposal.action,
        guard,
        audit,
        ledger,
        {proposal.action.name: ProposalGateAdapter(candidate_match=True, proposal=model_shape)},
    )


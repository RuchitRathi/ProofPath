"""Run one live WSL Nmap scan and a guarded Qwen plan against local WSL loopback."""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from proofpath.adapters.base import execute_action
from proofpath.adapters.nmap import NmapAdapter, NmapExecutionConfig
from proofpath.audit import AuditLog
from proofpath.grounding import verify_text
from proofpath.ledger import Ledger
from proofpath.proposer import (
    OllamaClient,
    OllamaConfig,
    RulePlanner,
    executed_fingerprints,
    propose_and_gate,
)
from proofpath.schemas import Action, ActionName
from proofpath.scope_guard import ScopeGuard

TARGET = "127.0.0.1"
PORT = 8080
DATA = ROOT / ".pytest-tmp" / "local-lab"


def main() -> int:
    guard = ScopeGuard.from_yaml(ROOT / "scope.local-lab.yaml")
    audit = AuditLog(DATA / "audit.jsonl")
    ledger = Ledger(DATA / "evidence")
    runtime = NmapExecutionConfig.from_yaml(ROOT / "nmap.yaml")
    if runtime.runtime != "wsl" or not runtime.distribution:
        raise RuntimeError("local lab expects the configured WSL Nmap runtime")

    action = Action(
        id="local-lab-" + uuid.uuid4().hex[:16],
        name=ActionName.NMAP_SCAN,
        target=TARGET,
        ports=[PORT],
        arguments={
            "service_detection": False,
            "skip_host_discovery": True,
            "timing": 1,
            "host_timeout_seconds": 20,
        },
        engagement_id=guard.policy.engagement,
        requested_by="local-lab-runner",
    )
    scan = execute_action(
        action,
        guard,
        audit,
        ledger,
        {
            ActionName.NMAP_SCAN: NmapAdapter(
                wsl_distribution=runtime.distribution,
            )
        },
    )
    print(json.dumps({
        "stage": "scope_and_live_nmap",
        "scope_allowed": scan.decision.allowed,
        "scope_reason": scan.decision.reason,
        "target": TARGET,
        "ports": [PORT],
        "scan_status": scan.status,
        "evidence_id": scan.evidence_id,
        "sha256": scan.sha256,
        "artifact_verified": ledger.verify_artifact(scan.evidence_id) if scan.evidence_id else False,
        "nmap_command": ledger.load(scan.evidence_id).command if scan.evidence_id else [],
        "observations": [row.model_dump(mode="json") for row in scan.services],
    }, indent=2))
    if not scan.decision.allowed or scan.status != "ok" or not scan.services:
        return 1
    if not any(row.ip == TARGET and row.port == PORT and row.state.casefold() == "open" for row in scan.services):
        print("Local test service was not observed open; no proposer call was made.")
        return 1

    candidates = RulePlanner().candidates(
        scan.services,
        guard.policy.engagement,
        executed=executed_fingerprints(audit),
        findings=[],
        enabled_actions=set(guard.policy.enabled_actions),
    )
    if not candidates:
        print("No eligible next-step candidates were produced from the live observation.")
        return 1

    model = OllamaClient(OllamaConfig.from_yaml(ROOT / "ollama.yaml"))
    proposer_audit_start = len(audit.read_entries())
    proposal, queued, fallback = propose_and_gate(
        scan.services,
        candidates,
        model,
        guard,
        audit,
        ledger,
        findings=[],
    )
    proposer_events = audit.read_entries()[proposer_audit_start:]
    rationale_grounding = None
    if proposal is not None:
        rationale_text = " ".join([
            *proposal.rationale.observed,
            proposal.rationale.inferred,
            proposal.rationale.why,
        ])
        evidence_ids = list(dict.fromkeys(re.findall(r"\bEV-\d+\b", rationale_text)))
        grounding = verify_text(rationale_text, evidence_ids, ledger)
        rationale_grounding = {
            "accepted": grounding.accepted,
            "violations": list(grounding.violations),
        }
    print(json.dumps({
        "stage": "proposer_and_guarded_queue",
        "candidate_count": len(candidates),
        "candidates": [
            {"candidate_id": row.candidate_id, "action_type": row.action.name.value, "exposure_state": row.exposure_state, "evidence_ids": row.observed_evidence_ids, "risk_score": row.risk_score}
            for row in candidates
        ],
        "proposal": {
            "candidate_id": proposal.candidate_id,
            "action": proposal.action.model_dump(mode="json"),
            "rationale": proposal.rationale.model_dump(mode="json"),
            "rationale_grounding": rationale_grounding,
            "fallback": fallback,
            "model_call_count": sum(entry.event_type == "model_call_metrics" for entry in proposer_events),
            "rejected_model_outputs": [entry.details.get("reason", "") for entry in proposer_events if entry.event_type == "model_output_rejected"],
            "guard_allowed": queued.decision.allowed if queued else False,
            "queue_status": queued.status if queued else "no result",
            "model_metrics": model.last_metrics,
        } if proposal else None,
        "note": "The local responder produces no vulnerability findings; none were fabricated.",
    }, indent=2))
    if (
        proposal is None
        or queued is None
        or queued.status != "planned"
        or fallback
        or rationale_grounding is None
        or not rationale_grounding["accepted"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

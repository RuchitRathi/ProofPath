"""Local bypass checks. These call the scope guard. They do not send packets."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import ValidationError

from proofpath.schemas import Action, ActionName
from proofpath.scope_guard import ScopeGuard

BYPASS_CASES: list[dict[str, object]] = [
    {"name": "public ipv4", "target": "8.8.8.8", "ports": [80], "arguments": {}, "allowed": False, "reason": "outside"},
    {"name": "excluded host", "target": "10.10.0.1", "ports": [80], "arguments": {}, "allowed": False, "reason": "excluded"},
    {"name": "hostname out of scope", "target": "evil.lab", "ports": [80], "arguments": {}, "allowed": False, "reason": "outside"},
    {"name": "split resolution", "target": "split.lab", "ports": [80], "arguments": {}, "allowed": False, "reason": "outside"},
    {"name": "loopback name", "target": "localhost", "ports": [80], "arguments": {}, "allowed": False, "reason": "localhost"},
    {"name": "loopback address", "target": "127.0.0.1", "ports": [80], "arguments": {}, "allowed": False, "reason": "loopback"},
    {"name": "hostname to loopback", "target": "loopback.lab", "ports": [80], "arguments": {}, "allowed": False, "reason": "loopback"},
    {"name": "unspecified ipv4", "target": "0.0.0.0", "ports": [80], "arguments": {}, "allowed": False, "reason": "unspecified"},
    {"name": "unspecified ipv6", "target": "::", "ports": [80], "arguments": {}, "allowed": False, "reason": "unspecified"},
    {"name": "ipv6 out of scope", "target": "2001:db8::1", "ports": [80], "arguments": {}, "allowed": False, "reason": "outside"},
    {"name": "mapped public", "target": "::ffff:8.8.8.8", "ports": [80], "arguments": {}, "allowed": False, "reason": "outside"},
    {"name": "link local", "target": "169.254.1.1", "ports": [80], "arguments": {}, "allowed": False, "reason": "link-local"},
    {"name": "multicast", "target": "224.0.0.1", "ports": [80], "arguments": {}, "allowed": False, "reason": "multicast"},
    {"name": "decimal ip", "target": "2130706433", "ports": [80], "arguments": {}, "allowed": False, "reason": "malformed"},
    {"name": "short ip", "target": "127.1", "ports": [80], "arguments": {}, "allowed": False, "reason": "malformed"},
    {"name": "hex ip", "target": "0x7f000001", "ports": [80], "arguments": {}, "allowed": False, "reason": "malformed"},
    {"name": "script argument", "target": "10.10.1.5", "ports": [80], "arguments": {"script": "vuln"}, "allowed": False, "reason": "allowlist"},
    {"name": "flag argument", "target": "10.10.1.5", "ports": [80], "arguments": {"-oX": "out.xml"}, "allowed": False, "reason": "allowlist"},
    {"name": "string timing", "target": "10.10.1.5", "ports": [80], "arguments": {"timing": "2;id"}, "allowed": False, "reason": "integer"},
    {"name": "timing above cap", "target": "10.10.1.5", "ports": [80], "arguments": {"timing": 5}, "allowed": False, "reason": "timing"},
    {"name": "port outside policy", "target": "10.10.1.5", "ports": [4444], "arguments": {}, "allowed": False, "reason": "port"},
    {"name": "active validation", "target": "10.10.1.5", "ports": [80], "arguments": {"method": "GET", "path": "/", "finding_id": "F-REDTEAM-1"}, "allowed": False, "reason": "approval", "action": "active_validate"},
    {"name": "in scope address", "target": "10.10.1.5", "ports": [80, 443], "arguments": {"timing": 2}, "allowed": True, "reason": "inside", "expect_ips": ["10.10.1.5"]},
    {"name": "in scope hostname", "target": "in-scope.lab", "ports": [22], "arguments": {}, "allowed": True, "reason": "inside", "expect_ips": ["10.10.1.5"]},
    {"name": "localhost uppercase", "target": "LOCALHOST", "ports": [80], "arguments": {}, "allowed": False, "reason": "localhost"},
    {"name": "localhost trailing dot", "target": "localhost.", "ports": [80], "arguments": {}, "allowed": False, "reason": "localhost"},
    {"name": "localhost localdomain", "target": "Localhost.localdomain", "ports": [80], "arguments": {}, "allowed": False, "reason": "localhost"},
    {"name": "ipv6 zone id", "target": "fe80::1%eth0", "ports": [80], "arguments": {}, "allowed": False, "reason": "zone"},
    {"name": "ipv6 loopback", "target": "::1", "ports": [80], "arguments": {}, "allowed": False, "reason": "loopback"},
    {"name": "mapped loopback", "target": "::ffff:127.0.0.1", "ports": [80], "arguments": {}, "allowed": False, "reason": "loopback"},
    {"name": "legacy short loopback", "target": "127.1", "ports": [80], "arguments": {}, "allowed": False, "reason": "malformed"},
    {"name": "decimal loopback", "target": "2130706433", "ports": [80], "arguments": {}, "allowed": False, "reason": "malformed"},
    {"name": "hex loopback", "target": "0x7f000001", "ports": [80], "arguments": {}, "allowed": False, "reason": "malformed"},
    {"name": "octal decimal loopback", "target": "017700000001", "ports": [80], "arguments": {}, "allowed": False, "reason": "malformed"},
    {"name": "zero shorthand", "target": "0", "ports": [80], "arguments": {}, "allowed": False, "reason": "malformed"},
    {"name": "cidr target", "target": "10.10.1.0/24", "ports": [80], "arguments": {}, "allowed": False, "reason": "characters"},
    {"name": "range target", "target": "10.10.1.1-20", "ports": [80], "arguments": {}, "allowed": False, "reason": "target is not an IP address or hostname"},
    {"name": "wildcard target", "target": "10.10.1.*", "ports": [80], "arguments": {}, "allowed": False, "reason": "target is not an IP address or hostname"},
    {"name": "comma-list target", "target": "10.10.1.5,10.10.1.6", "ports": [80], "arguments": {}, "allowed": False, "reason": "target is not an IP address or hostname"},
    {"name": "excluded host trailing dot", "target": "10.10.0.1.", "ports": [80], "arguments": {}, "allowed": False, "reason": "excluded"},
    {"name": "excluded hostname uppercase", "target": "BLOCKED.LAB", "ports": [80], "arguments": {}, "allowed": False, "reason": "excluded"},
    {"name": "excluded hostname trailing dot", "target": "blocked.lab.", "ports": [80], "arguments": {}, "allowed": False, "reason": "excluded"},
    {"name": "unicode hostname", "target": "bücher.example", "ports": [80], "arguments": {}, "allowed": False, "reason": "hostname"},
    {"name": "empty target", "target": "", "ports": [80], "arguments": {}, "allowed": False, "reason": "target"},
    {"name": "whitespace target", "target": " 10.10.1.5", "ports": [80], "arguments": {}, "allowed": False, "reason": "whitespace"},
    {"name": "flag-like argument", "target": "10.10.1.5", "ports": [80], "arguments": {"timing": "-1"}, "allowed": False, "reason": "integer"},
    {"name": "empty ports", "target": "10.10.1.5", "ports": [], "arguments": {}, "allowed": False, "reason": "ports are required"},
    {"name": "zero port", "target": "10.10.1.5", "ports": [0], "arguments": {}, "allowed": False, "reason": "port"},
    {"name": "negative port", "target": "10.10.1.5", "ports": [-1], "arguments": {}, "allowed": False, "reason": "port"},
    {"name": "oversize port", "target": "10.10.1.5", "ports": [65536], "arguments": {}, "allowed": False, "reason": "port"},
    {"name": "mapped in scope", "target": "::ffff:10.10.1.5", "ports": [80], "arguments": {}, "allowed": True, "reason": "inside", "expect_ips": ["10.10.1.5"]},
]


def demo_resolver(hostname: str) -> list[str]:
    """Fixed resolver used by tests and `proofpath redteam`. It does not use DNS."""
    table = {
        "in-scope.lab": ["10.10.1.5"],
        "evil.lab": ["8.8.8.8"],
        "split.lab": ["10.10.1.5", "8.8.8.8"],
        "loopback.lab": ["127.0.0.1"],
        "localhost": ["127.0.0.1"],
        "blocked.lab": ["10.10.0.2"],
    }
    return list(table.get(hostname.lower(), []))


def run_cases(scope_path: str | Path) -> list[tuple[str, bool, str]]:
    """Evaluate every bypass case. Each item is name, passed, decision reason."""
    guard = ScopeGuard.from_yaml(scope_path, resolver=demo_resolver)
    # Add a deterministic excluded hostname specifically to exercise case/dot variants.
    policy = guard.policy.model_copy(update={"excluded_hosts": [*guard.policy.excluded_hosts, "blocked.lab"]})
    guard = ScopeGuard(policy, resolver=demo_resolver)
    results: list[tuple[str, bool, str]] = []
    for case in BYPASS_CASES:
        action_name = ActionName(str(case.get("action", ActionName.NMAP_SCAN.value)))
        try:
            action = Action(
            id="selftest",
            name=action_name,
            target=str(case["target"]),
            ports=list(case["ports"]),  # type: ignore[arg-type]
            arguments=dict(case["arguments"]),  # type: ignore[arg-type]
            engagement_id=guard.policy.engagement,
            )
        except ValidationError as exc:
            passed = case["allowed"] is False and any(term in str(exc).lower() for term in ("ports", "target"))
            results.append((str(case["name"]), passed, "rejected by typed Action validation"))
            continue
        decision = guard.check(action)
        passed = decision.allowed is case["allowed"] and str(case["reason"]) in decision.reason
        if case["allowed"]:
            passed = passed and guard.verify_decision(decision)
            passed = passed and bool(decision.resolved_ips)
            for ip_text in decision.resolved_ips:
                ipaddress.ip_address(ip_text)
            expect = case.get("expect_ips")
            if expect is not None:
                passed = passed and list(expect) == decision.resolved_ips
        results.append((str(case["name"]), passed, decision.reason))
    return results


def run_injection_redteam(scope_path: str | Path) -> tuple[bool, str]:
    """Run the model-injection scenario with a malicious stub; no network or Ollama."""
    import tempfile

    from proofpath.adapters.nmap import parse_nmap_xml
    from proofpath.audit import AuditLog
    from proofpath.ledger import Ledger
    from proofpath.schemas import ServiceObservation
    from proofpath.proposer import CandidateSelection, Rationale, RulePlanner, propose_and_gate

    root = Path(scope_path).resolve().parent
    fixture = root / "tests" / "fixtures" / "injection" / "nmap.xml"
    try:
        observations = parse_nmap_xml(fixture.read_bytes(), "EV-0001")
        guard = ScopeGuard.from_yaml(scope_path, resolver=demo_resolver)
        candidates = RulePlanner().candidates(observations, guard.policy.engagement)

        class MaliciousStub:
            def complete(self, _messages: list[dict[str, str]], _schema: dict[str, object]) -> str:
                return CandidateSelection(
                    candidate_id="C1",
                    rationale=Rationale(observed=["EV-0001 reports the synthetic service."], inferred="Inference: test payload.", why="Redteam stub."),
                ).model_dump_json()

        temp_root = root / ".pytest-tmp"
        temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temp_root) as tmp:
            audit = AuditLog(Path(tmp) / "audit.jsonl")
            ledger = Ledger(Path(tmp) / "evidence")
            evidence = ledger.store(content=fixture.read_bytes(), tool="nmap", command=["synthetic_fixture"], status="ok", summary="redteam fixture", source_mode="imported")
            observations = [item.model_copy(update={"evidence_id": evidence.id}) for item in observations]
            candidates = RulePlanner().candidates(observations, guard.policy.engagement)
            proposal, result, _fallback = propose_and_gate(observations, candidates, MaliciousStub(), guard, audit, ledger)
            entries = audit.read_entries()
            blocked = any(entry.event_type == "model_action_blocked" for entry in entries)
            scope_denied = any(entry.event_type == "scope_decision" and entry.details.get("allowed") is False for entry in entries)
            passed = proposal is not None and result is not None and result.status == "planned" and result.decision.allowed and proposal.action.target != "8.8.8.8"
            return passed, "model selected C1; built action remained scoped and allowed" if passed else "candidate selection did not preserve scoped action"
    except Exception as exc:
        return False, f"injection redteam error: {type(exc).__name__}: {exc}"


def run_approval_redteam(scope_path: str | Path) -> list[tuple[str, bool, str]]:
    """Exercise approval, exact binding, replay denial, and loopback-only HTTP."""
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from proofpath.adapters.active_validate import ActiveValidationAdapter
    from proofpath.adapters.base import execute_action
    from proofpath.approval import decide_approval, request_approval
    from proofpath.audit import AuditLog
    from proofpath.ledger import Ledger
    from proofpath.schemas import ServiceObservation

    class Handler(BaseHTTPRequestHandler):
        secret_hits = 0

        def do_GET(self) -> None:
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/secret")
                self.end_headers()
                return
            if self.path == "/secret":
                type(self).secret_hits += 1
            body = b"redteam local response"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    outcomes: list[tuple[str, bool, str]] = []
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = ScopeGuard.from_yaml(scope_path, resolver=demo_resolver).policy
        policy = base.model_copy(update={"allowed_cidrs": ["127.0.0.1/32"], "excluded_cidrs": [], "excluded_hosts": [], "allowed_ports": [str(server.server_port)], "allow_loopback": True, "enabled_actions": [ActionName.ACTIVE_VALIDATE], "allowed_validation_paths": ["/", "/redirect", "/secret"]})
        guard = ScopeGuard(policy, resolver=demo_resolver)
        action = Action(id="redteam-active", name=ActionName.ACTIVE_VALIDATE, target="127.0.0.1", ports=[server.server_port], arguments={"method": "GET", "path": "/", "finding_id": "F-REDTEAM-1"}, engagement_id=policy.engagement, requested_by="requester")
        outcomes.append(("unapproved active validation denied", not guard.check(action).allowed, guard.check(action).reason))
        approval = request_approval(action, "requester", "redteam local server")
        audit = AuditLog(Path(tempfile.gettempdir()) / "proofpath-approval-redteam.jsonl")
        audit.path.write_text("", encoding="utf-8")
        audit.append("approval_requested", "requester", {"approval_id": approval.id, "action_id": action.id, "action_hash": approval.action_hash, "requested_by": approval.requested_by, "action": action.model_dump(mode="json")})
        approval = decide_approval(approval, "approver", approved=True)
        audit.append("approval_decision", "approver", {"approval_id": approval.id, "action_id": action.id, "action_hash": approval.action_hash, "state": approval.state.value})
        ledger = Ledger(Path(tempfile.gettempdir()) / "proofpath-approval-redteam-evidence")
        ledger.root.mkdir(parents=True, exist_ok=True)
        result = execute_action(action, guard, audit, ledger, {ActionName.ACTIVE_VALIDATE: ActiveValidationAdapter(action, approval)}, approval=approval)
        entries = audit.read_entries()
        success = result.status == "ok" and entries[-1].event_type == "active_validation_outcome" and entries[-1].details.get("approved_by") == "approver"
        outcomes.append(("approval request-decision-execute-outcome", success, "loopback action ran once with four chained lifecycle events" if success else result.message))
        replay = execute_action(action, guard, audit, ledger, {ActionName.ACTIVE_VALIDATE: ActiveValidationAdapter(action, approval)}, approval=approval)
        outcomes.append(("approval replay denied", replay.status == "denied", replay.message))
        tampered = action.model_copy(update={"arguments": {"method": "GET", "path": "/changed", "finding_id": "F-REDTEAM-1"}})
        outcomes.append(("approval tamper denied", not guard.check(tampered, approval).allowed, "changed path invalidates the approval hash"))
        out_of_scope = action.model_copy(update={"target": "8.8.8.8"})
        outcomes.append(("approved out-of-scope host denied", not guard.check(out_of_scope, approval).allowed, guard.check(out_of_scope, approval).reason))
        excluded_policy = policy.model_copy(update={"excluded_hosts": ["127.0.0.1"]})
        excluded_guard = ScopeGuard(excluded_policy, resolver=demo_resolver)
        outcomes.append(("approved excluded host denied", not excluded_guard.check(action, approval).allowed, excluded_guard.check(action, approval).reason))
        try:
            request_approval(action.model_copy(update={"arguments": {"method": "POST", "path": "/", "finding_id": "F-REDTEAM-1"}}), "requester", "bad method")
            method_denied = False
            method_message = "invalid method received approval"
        except ValueError as exc:
            method_denied = True
            method_message = str(exc)
        outcomes.append(("non-GET/HEAD active request denied", method_denied, method_message))
        self_request = request_approval(Action.model_copy(action, update={"id": "self-approve"}), "requester", "self approval")
        try:
            decide_approval(self_request, "requester", approved=True)
            self_denied = False
        except ValueError:
            self_denied = True
        outcomes.append(("self-approval denied", self_denied, "requester cannot decide own request"))
        expired_request = request_approval(Action.model_copy(action, update={"id": "expired"}), "requester", "expiry")
        expired_request = expired_request.model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
        expired_decision = decide_approval(expired_request, "approver", approved=True)
        outcomes.append(("expired approval denied", expired_decision.state.value == "expired" and not guard.check(Action.model_copy(action, update={"id": "expired"}), expired_decision).allowed, expired_decision.state.value))
        denied_request = request_approval(action.model_copy(update={"id": "human-denied"}), "requester", "human denial")
        denied_decision = decide_approval(denied_request, "approver", approved=False)
        outcomes.append(("human-denied action cannot execute", not guard.check(action.model_copy(update={"id": "human-denied"}), denied_decision).allowed, denied_decision.state.value))

        # A local stub may propose an active action, but it cannot manufacture the human approval.
        from proofpath.proposer import PlannerCandidate, ProposedAction, Rationale, propose_and_gate
        synthetic = ledger.store(content=b"<fixture>localhost test server</fixture>", tool="fixture", command=["synthetic"], status="ok", summary="synthetic approval redteam fixture", source_mode="imported")
        candidate_action = Action(id="candidate", name=ActionName.IMPORT_BURP, target="127.0.0.1", ports=[server.server_port], engagement_id=policy.engagement)
        observation = ServiceObservation(evidence_id=synthetic.id, ip="127.0.0.1", port=server.server_port, protocol="tcp", state="open", service="http")
        candidate = PlannerCandidate(action=candidate_action, observed_evidence_ids=[synthetic.id], planner_reason="test candidate")
        class ActiveStub:
            def complete(self, _messages: list[dict[str, str]], _schema: dict[str, object]) -> str:
                active = action.model_copy(update={"id": "model-active", "requested_by": "model-proposer"})
                return ProposedAction(action=active, rationale=Rationale(observed=[f"Observed EV-{synthetic.id[3:]}."], inferred="Inference: review the approved finding.", why="test stub")).model_dump_json()
        _proposal, model_result, _fallback = propose_and_gate([observation], [candidate], ActiveStub(), guard, audit, ledger)
        outcomes.append(("action-shaped model output rejected; fixed candidate scope-checked", model_result is not None and model_result.status == "denied" and model_result.decision.allowed is False, model_result.message if model_result else "no result"))

        redirect_action = Action(id="redteam-redirect", name=ActionName.ACTIVE_VALIDATE, target="127.0.0.1", ports=[server.server_port], arguments={"method": "GET", "path": "/redirect", "finding_id": "F-REDTEAM-2"}, engagement_id=policy.engagement, requested_by="requester")
        redirect_approval = decide_approval(request_approval(redirect_action, "requester", "redirect case"), "approver", approved=True)
        redirect_result = execute_action(redirect_action, guard, audit, ledger, {ActionName.ACTIVE_VALIDATE: ActiveValidationAdapter(redirect_action, redirect_approval)}, approval=redirect_approval)
        outcomes.append(("HTTP redirect not followed", redirect_result.status == "ok" and Handler.secret_hits == 0, "received 302; /secret was not requested" if Handler.secret_hits == 0 else "redirect target was followed"))
        ok, reason = audit.verify()
        outcomes.append(("approval audit chain", ok, reason))
    except Exception as exc:
        outcomes.append(("approval redteam", False, f"{type(exc).__name__}: {exc}"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    return outcomes


def run_grounding_redteam() -> list[tuple[str, bool, str]]:
    """Reject invented identifiers and confirm rejection is hash-chain audited."""
    import tempfile

    from proofpath.audit import AuditLog
    from proofpath.grounding import verify_text
    from proofpath.ledger import Ledger

    temp = Path(tempfile.mkdtemp(prefix="proofpath-ground-redteam-"))
    audit = AuditLog(temp / "audit.jsonl")
    ledger = Ledger(temp / "evidence")
    evidence = ledger.store(content=b"<finding port=\"80\">Observed 10.10.1.5</finding>", tool="fixture", command=["synthetic"], status="ok", summary="synthetic grounding fixture", source_mode="imported")
    result = verify_text("CVE-2026-99999 CWE-999 10.10.1.5 port 443 EV-9999", [evidence.id], ledger)
    audit.append("grounding_rejected", "grounding-verifier", {"evidence_ids": [evidence.id], "violations": list(result.violations), "fallback": "tool-reported template"})
    ok, _ = audit.verify()
    checks = [
        ("grounding invented CVE rejected", any("unsupported CVE" in item for item in result.violations), str(result.violations)),
        ("grounding invented CWE rejected", any("unsupported CWE" in item for item in result.violations), str(result.violations)),
        ("grounding invented port and evidence ID rejected", any("unsupported port" in item for item in result.violations) and any("uncited evidence ID" in item for item in result.violations), str(result.violations)),
        ("grounding rejection audited", not result.accepted and any(entry.event_type == "grounding_rejected" for entry in audit.read_entries()) and ok, "rejection stored in a valid audit chain"),
    ]
    return checks

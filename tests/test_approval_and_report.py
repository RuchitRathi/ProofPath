from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from pathlib import Path

from pypdf import PdfReader

from proofpath.adapters.active_validate import ActiveValidationAdapter
from proofpath.adapters.base import execute_action
from proofpath.approval import decide_approval, request_approval
from proofpath.audit import AuditLog
from proofpath.grounding import verify_text
from proofpath.ledger import Ledger
from proofpath.report.generator import generate_pdf
from proofpath.schemas import Action, ActionName, EvidenceRef, Finding, FindingAsset
from proofpath.scope_guard import ScopeGuard
from proofpath.verification import verify_report_and_approvals
from proofpath.cli import main

ROOT = Path(__file__).resolve().parents[1]


class _Handler(BaseHTTPRequestHandler):
    secret_hits = 0

    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/secret")
            self.end_headers()
            return
        if self.path == "/secret":
            type(self).secret_hits += 1
        body = b"local lab response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def _guard(port: int, paths: list[str] | None = None) -> ScopeGuard:
    base = ScopeGuard.from_yaml(ROOT / "scope.yaml").policy
    policy = base.model_copy(update={
        "allowed_cidrs": ["127.0.0.1/32"], "excluded_cidrs": [], "excluded_hosts": [],
        "allowed_ports": [str(port)], "allow_loopback": True,
        "enabled_actions": [ActionName.NMAP_SCAN, ActionName.ACTIVE_VALIDATE],
        "allowed_validation_paths": paths or ["/", "/redirect"],
    })
    return ScopeGuard(policy)


def _action(port: int, *, method: str = "GET", path: str = "/", finding_id: str = "F-TEST-001") -> Action:
    return Action(id="active-action", name=ActionName.ACTIVE_VALIDATE, target="127.0.0.1", ports=[port], arguments={"method": method, "path": path, "finding_id": finding_id}, engagement_id="lab-01", requested_by="alice")


def test_approval_http_request_single_use_audit_chain_and_no_redirect_follow(tmp_path: Path) -> None:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        guard = _guard(server.server_port)
        action = _action(server.server_port, path="/redirect")
        approval = request_approval(action, "alice", "Confirm reported web service")
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.append("approval_requested", "alice", {"approval": approval.model_dump(mode="json"), "action": action.model_dump(mode="json")})
        approval = decide_approval(approval, "bob", approved=True)
        audit.append("approval_decision", "bob", {"approval_id": approval.id, "action_id": action.id, "state": approval.state.value, "action_hash": approval.action_hash})
        ledger = Ledger(tmp_path / "evidence")
        adapter = ActiveValidationAdapter(action, approval)
        result = execute_action(action, guard, audit, ledger, {ActionName.ACTIVE_VALIDATE: adapter}, approval=approval)
        assert result.status == "ok" and result.evidence_id, result.message
        assert _Handler.secret_hits == 0
        outcome = audit.read_entries()[-1]
        assert outcome.event_type == "active_validation_outcome"
        assert outcome.details["status_code"] == 302
        assert outcome.details["approved_by"] == "bob"
        second = execute_action(action, guard, audit, ledger, {ActionName.ACTIVE_VALIDATE: adapter}, approval=approval)
        assert second.status == "denied"
        event_types = [entry.event_type for entry in audit.read_entries()]
        assert event_types.index("approval_requested") < event_types.index("approval_decision") < event_types.index("active_validation_execution") < event_types.index("active_validation_outcome")
        ok, _ = audit.verify()
        assert ok
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_approval_denial_expiry_self_approval_and_tampering(tmp_path: Path) -> None:
    guard = _guard(443)
    action = _action(443)
    request = request_approval(action, "alice", "test", now=datetime.now(timezone.utc))
    try:
        decide_approval(request, "alice", approved=True)
    except ValueError as exc:
        assert "requester" in str(exc)
    else:
        raise AssertionError("self-approval was accepted")
    expired = request.model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    assert decide_approval(expired, "bob", approved=True).state.value == "expired"
    denied = decide_approval(request, "bob", approved=False)
    assert denied.state.value == "denied"
    approved = decide_approval(request, "bob", approved=True)
    forged = request.model_copy(update={"state": approved.state, "decided_by": "mallory", "decided_at": approved.decided_at})
    assert not guard.check(action, forged).allowed
    tampered = action.model_copy(update={"arguments": {"method": "GET", "path": "/other", "finding_id": "F-TEST-001"}})
    assert not guard.check(tampered, approved).allowed
    assert not guard.check(action).allowed
    non_get = _action(443, method="POST")
    try:
        request_approval(non_get, "alice", "bad method")
    except ValueError as exc:
        assert "GET or HEAD" in str(exc)
    else:
        raise AssertionError("non-GET method received an approval request")
    out_scope = action.model_copy(update={"target": "8.8.8.8"})
    assert not guard.check(out_scope, approved).allowed


def _finding(evidence_id: str, excerpt: str) -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(id="F-REPORT-001", title="Reported service issue", asset=FindingAsset(ip="10.10.1.5"), port=80, protocol="tcp", service="http", source_tools=["nessus"], evidence=[EvidenceRef(evidence_id=evidence_id, locator="/ReportItem[1]", excerpt=excerpt[:300])], observed="Nessus reports port 80/tcp; " + excerpt, severity="high", cvss=None, confidence="low", status="suspected", first_seen=now, last_seen=now)


def test_grounding_rejects_invented_cve_port_and_evidence_id(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "evidence")
    ev = ledger.store(content=b"<ReportItem port=\"80\"><description>Reported service issue on 10.10.1.5</description><product>OpenSSH</product><version>9.6</version><address>2001:db8::1</address><banner>Apache/2.4.49</banner></ReportItem>", tool="nessus", command=["import"], status="ok", summary="synthetic fixture", source_mode="imported")
    result = verify_text("CVE-2026-99999 at 10.10.1.5 port 443 EV-9999", [ev.id], ledger)
    assert not result.accepted
    assert any("unsupported CVE" in item for item in result.violations)
    assert any("unsupported port: 443" in item for item in result.violations)
    assert any("uncited evidence ID" in item for item in result.violations)
    grounded = verify_text("10.10.1.5 port 80", [ev.id], ledger)
    assert grounded.accepted
    grounded_version = verify_text("OpenSSH 9.6 Apache/2.4.49 2001:db8::1", [ev.id], ledger)
    assert grounded_version.accepted
    invented_version = verify_text("OpenSSH 9.9", [ev.id], ledger)
    assert not invented_version.accepted and any("product/version" in item for item in invented_version.violations)


def test_report_sections_evidence_trace_import_label_and_hash(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "evidence")
    raw = b"<ReportItem port=\"80\"><description>Reported service issue on 10.10.1.5</description></ReportItem>"
    ev = ledger.store(content=raw, tool="nessus", command=["import"], status="ok", summary="synthetic fixture", source_mode="imported")
    finding = _finding(ev.id, raw.decode())
    audit = AuditLog(tmp_path / "audit.jsonl")
    pdf = tmp_path / "report.pdf"
    result = generate_pdf([finding], [], ledger, audit, pdf, engagement="test", scope_cidrs=["10.10.1.0/24"])
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(pdf)).pages)
    section_titles = ["7.1 Executive Summary", "7.2 Assessment Methodology", "7.3 Severity Distribution & Risk Prioritization", "7.4 Detailed Vulnerability Findings", "7.5 Impact & Actionable Remediation", "7.6 Standards & Reference Frameworks", "7.7 Assessment Limitations", "Appendix A: Evidence Index", "Appendix B: Integration Status Matrix", "Appendix C: Audit & Report Hashes"]
    positions = [text.index(title) for title in section_titles]
    assert positions == sorted(positions)
    assert ev.id in text and "/ReportItem[1]" in text and "port=\"80\"" in text
    assert "imported, not live-executed" in text
    assert "This report uses synthetic data." in text
    assert "not provided" in text
    assert "compliant with" not in text.casefold()
    entry = next(item for item in audit.read_entries() if item.event_type == "report_generated")
    assert entry.details["report_sha256"] == result["sha256"]
    assert entry.details["evidence_hashes"][ev.id] == ev.sha256
    assert result["severity_counts"]["high"] == 1
    known = {ev.id}
    assert verify_report_and_approvals(audit.read_entries(), known, ledger)[0]
    assert main(["verify", "--audit", str(audit.path), "--ledger", str(ledger.root)]) == 0
    assert main(["ground-check", "--findings", str(tmp_path / "current-findings.json"), "--ledger", str(ledger.root), "--audit", str(audit.path)]) == 0
    clean = pdf.read_bytes()
    pdf.write_bytes(clean[:-1] + bytes([clean[-1] ^ 1]))
    ok, message = verify_report_and_approvals(audit.read_entries(), known, ledger)
    assert not ok and "report hash mismatch" in message
    assert main(["verify", "--audit", str(audit.path), "--ledger", str(ledger.root)]) == 1
    pdf.write_bytes(clean)


def test_verify_detects_deleted_approval_audit_entry(tmp_path: Path, capsys) -> None:
    action = _action(443)
    approval = request_approval(action, "alice", "test action")
    audit = AuditLog(tmp_path / "audit.jsonl")
    request_event = audit.append("approval_requested", "alice", {"approval_id": approval.id, "action_id": action.id, "action_hash": approval.action_hash, "requested_by": approval.requested_by, "action": action.model_dump(mode="json")})
    decision = decide_approval(approval, "bob", approved=True)
    audit.append("approval_decision", "bob", {"approval_id": decision.id, "action_id": action.id, "action_hash": decision.action_hash, "state": decision.state.value})
    audit.path.write_text(audit.path.read_text(encoding="utf-8").replace(request_event.model_dump_json() + "\n", ""), encoding="utf-8")
    assert main(["verify", "--audit", str(audit.path), "--ledger", str(tmp_path / "empty-ledger")]) == 1
    assert "sequence break" in capsys.readouterr().out


def test_grounding_rejection_is_audited_and_report_omits_unverified_inference(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "evidence")
    raw = b"<finding ip=\"10.10.1.5\" port=\"80\">Reported service issue</finding>"
    ev = ledger.store(content=raw, tool="nessus", command=["import"], status="ok", summary="synthetic fixture", source_mode="imported")
    finding = _finding(ev.id, raw.decode()).model_copy(update={"inference": "Inference: CVE-2026-99999 is present."})
    audit = AuditLog(tmp_path / "audit.jsonl")
    report = tmp_path / "report.pdf"
    generate_pdf([finding], [], ledger, audit, report, engagement="test", scope_cidrs=[])
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(report)).pages)
    assert "Inference: CVE-2026-99999" not in text
    assert "AI inference rejected" in text or "AI inference omitted" in text
    assert any(entry.event_type == "grounding_rejected" for entry in audit.read_entries())

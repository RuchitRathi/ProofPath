from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from pathlib import Path

import yaml
from streamlit.testing.v1 import AppTest

from proofpath.ledger import Ledger
from proofpath.schemas import EvidenceRef, Finding, FindingAsset

ROOT = Path(__file__).resolve().parents[1]


class _UIHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"local UI test server"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def _finding(data_root: Path, *, asset: str = "10.10.1.5", port: int = 80) -> Finding:
    raw = f"<finding ip=\"{asset}\" port=\"{port}\">Reported service issue</finding>".encode()
    evidence = Ledger(data_root / "evidence").store(content=raw, tool="nessus", command=["import"], status="ok", summary="synthetic UI fixture", source_mode="imported")
    now = datetime.now(timezone.utc)
    return Finding(id="F-UI-001", title="Reported service issue", asset=FindingAsset(ip=asset), port=port, protocol="tcp", service="http", source_tools=["nessus"], evidence=[EvidenceRef(evidence_id=evidence.id, locator="/finding", excerpt=raw.decode())], observed=f"Observed port {port}/tcp on {asset}", severity="high", cvss=None, confidence="low", status="suspected", first_seen=now, last_seen=now)


def _app(tmp_path: Path, monkeypatch, *, port: int | None = None) -> AppTest:
    monkeypatch.setenv("PROOFPATH_DATA_DIR", str(tmp_path / "data"))
    if port is not None:
        policy = yaml.safe_load((ROOT / "scope.yaml").read_text(encoding="utf-8"))
        policy["allowed_cidrs"] = ["127.0.0.1/32"]
        policy["allowed_ports"] = [str(port)]
        policy["allow_loopback"] = True
        policy["enabled_actions"] = list(dict.fromkeys([*policy["enabled_actions"], "active_validate"]))
        policy["allowed_validation_paths"] = ["/"]
        scope_path = tmp_path / "scope.yaml"
        scope_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        monkeypatch.setenv("PROOFPATH_SCOPE_CONFIG", str(scope_path))
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=20).run()
    return app


def _set_input(app: AppTest, label: str, value: str) -> None:
    next(widget for widget in app.text_input if widget.label == label).set_value(value)


def test_risk_table_renders_and_criticality_change_is_audited(tmp_path: Path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    app.session_state["raw_findings"] = [_finding(tmp_path / "data")]
    app.run()
    assert not app.exception
    assert any("Risk table rendered" in item.value for item in app.caption)
    assert any("Asset criticality" in widget.label for widget in app.selectbox), [(widget.label, widget.value) for widget in app.selectbox]
    next(widget for widget in app.selectbox if widget.label.startswith("Asset criticality")).set_value("high").run()
    assert any(entry.event_type == "asset_criticality_changed" for entry in __import__("proofpath.audit", fromlist=["AuditLog"]).AuditLog(tmp_path / "data" / "audit.jsonl").read_entries())


def test_approval_ui_request_approve_execute_and_single_use(tmp_path: Path, monkeypatch) -> None:
    server = HTTPServer(("127.0.0.1", 0), _UIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        app = _app(tmp_path, monkeypatch, port=server.server_port)
        app.session_state["raw_findings"] = [_finding(tmp_path / "data", asset="127.0.0.1", port=server.server_port)]
        app.run()
        _set_input(app, "Requester identity", "alice")
        _set_input(app, "Reason for this non-destructive check", "Confirm the local test service")
        next(button for button in app.button if button.label == "Request approval").click().run()
        _set_input(app, "Approver identity", "bob")
        next(button for button in app.button if button.label == "Approve").click().run()
        next(button for button in app.button if button.label == "Run approved request once").click().run()
        assert not app.exception
        audit = __import__("proofpath.audit", fromlist=["AuditLog"]).AuditLog(tmp_path / "data" / "audit.jsonl")
        events = [item.event_type for item in audit.read_entries()]
        assert "approval_requested" in events and "approval_decision" in events
        assert "active_validation_execution" in events and "active_validation_outcome" in events
        assert app.session_state["raw_findings"][0].validation_status == "validated_approved"
        assert not any(button.label == "Run approved request once" for button in app.button)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_approval_ui_deny_and_report_download_button(tmp_path: Path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    app.session_state["raw_findings"] = [_finding(tmp_path / "data")]
    app.run()
    _set_input(app, "Requester identity", "alice")
    _set_input(app, "Reason for this non-destructive check", "Test human denial")
    next(button for button in app.button if button.label == "Request approval").click().run()
    _set_input(app, "Approver identity", "bob")
    next(button for button in app.button if button.label == "Deny").click().run()
    assert app.session_state["raw_findings"][0].validation_status == "rejected_by_human"
    next(button for button in app.button if button.label == "Generate PDF report").click().run()
    assert any(item.label == "Download PDF report" for item in app.get("download_button"))
    assert not app.exception

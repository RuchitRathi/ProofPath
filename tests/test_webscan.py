"""The live web/TLS scanner: guard-first, evidence-backed, standard library only."""

from datetime import datetime, timezone
from pathlib import Path

from proofpath.adapters.base import execute_action
from proofpath.adapters.webscan import WebEndpoint, WebScanAdapter, analyze_endpoint, probe_endpoint
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName
from proofpath.scope_guard import ScopeGuard
from proofpath.selftest import demo_resolver

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "scope.yaml"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _guard() -> ScopeGuard:
    return ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)


def _action(target: str = "in-scope.lab", ports: list[int] | None = None) -> Action:
    return Action(
        id="act-web",
        name=ActionName.WEB_SCAN,
        target=target,
        ports=ports or [80, 443],
        arguments={},
        engagement_id="lab-01",
    )


def _fetcher(ip: str, port: int, scheme: str, timeout: float) -> WebEndpoint:
    """Deterministic stand-in for the network so tests never open a socket."""
    if port == 443:
        return WebEndpoint(
            ip=ip,
            port=port,
            scheme="https",
            status_code=200,
            headers={"server": "nginx/1.25.0"},
            set_cookies=("sid=abc123",),
            tls_version="TLSv1.1",
            cert_trusted=False,
        )
    return WebEndpoint(
        ip=ip,
        port=port,
        scheme="http",
        status_code=200,
        headers={
            "server": "nginx/1.25.0",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
        },
    )


def test_analyze_endpoint_reports_each_class_of_issue() -> None:
    findings = analyze_endpoint(_fetcher("10.10.1.5", 443, "https", 5.0), "EV-0001", NOW, 0)
    codes = {finding.id.rsplit("-", 1)[-1] for finding in findings}
    assert codes == {"HDR", "BANNER", "COOKIE", "TLS"}
    for finding in findings:
        assert finding.source_tools == ["webscan"]
        assert finding.asset.ip == "10.10.1.5"
        assert finding.port == 443
        assert finding.evidence[0].evidence_id == "EV-0001"
        assert finding.evidence[0].locator == "/endpoints/0"
        assert finding.confidence == "high"
        assert finding.status == "confirmed"
    tls = next(finding for finding in findings if finding.id.endswith("-TLS"))
    assert tls.severity == "high"
    assert tls.cwes == ["CWE-295"]


def test_analyze_endpoint_flags_only_missing_hsts_and_banner() -> None:
    findings = analyze_endpoint(_fetcher("10.10.1.5", 80, "http", 5.0), "EV-0001", NOW, 1)
    assert [finding.id for finding in findings] == [
        "F-WS-10-10-1-5-80-HDR",
        "F-WS-10-10-1-5-80-BANNER",
    ]
    hdr = findings[0]
    assert hdr.observed == "HTTP 200 response omitted: strict-transport-security"


def test_error_endpoint_produces_no_findings() -> None:
    endpoint = WebEndpoint(ip="10.10.1.5", port=80, scheme="http", error="ConnectionRefusedError: refused")
    assert analyze_endpoint(endpoint, "EV-0001", NOW, 0) == []


def test_probe_endpoint_retries_the_alternate_scheme() -> None:
    calls: list[str] = []

    def fetch(ip: str, port: int, scheme: str, timeout: float) -> WebEndpoint:
        calls.append(scheme)
        if scheme == "https":
            return WebEndpoint(ip=ip, port=port, scheme="https", error="ssl error")
        return WebEndpoint(ip=ip, port=port, scheme="http", status_code=200)

    endpoint = probe_endpoint("10.10.1.5", 443, fetch=fetch)
    assert calls == ["https", "http"]
    assert endpoint.scheme == "http"
    assert endpoint.status_code == 200


def test_allowed_run_stores_live_evidence_and_findings(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "evidence")
    result = execute_action(
        _action(),
        _guard(),
        AuditLog(tmp_path / "audit.jsonl"),
        ledger,
        {ActionName.WEB_SCAN: WebScanAdapter(fetcher=_fetcher)},
    )
    assert result.status == "ok"
    assert result.evidence_id == "EV-0001"
    assert ledger.load(result.evidence_id).source_mode == "live"
    assert ledger.verify_artifact(result.evidence_id) is True
    assert result.parsed_items == 2
    assert result.findings
    assert {finding.asset.ip for finding in result.findings} == {"10.10.1.5"}


def test_denied_target_never_probes(tmp_path: Path) -> None:
    def fetcher(*_args: object, **_kwargs: object) -> WebEndpoint:
        raise AssertionError("webscan opened a socket")

    result = execute_action(
        _action("evil.lab"),
        _guard(),
        AuditLog(tmp_path / "audit.jsonl"),
        Ledger(tmp_path / "evidence"),
        {ActionName.WEB_SCAN: WebScanAdapter(fetcher=fetcher)},
    )
    assert result.status == "denied"
    assert result.evidence_id is None
    assert result.findings == []


def test_forged_decision_never_probes(tmp_path: Path) -> None:
    def fetcher(*_args: object, **_kwargs: object) -> WebEndpoint:
        raise AssertionError("webscan opened a socket")

    guard = _guard()
    decision = guard.check(_action("evil.lab"))
    forged = decision.model_copy(
        update={
            "allowed": True,
            "tool": "webscan",
            "resolved_ips": ["10.10.1.5"],
            "ports": [80],
            "normalized_arguments": {},
        }
    )
    result = WebScanAdapter(fetcher=fetcher).run(
        forged,
        guard,
        AuditLog(tmp_path / "audit.jsonl"),
        Ledger(tmp_path / "evidence"),
        "analyst",
    )
    assert result.status == "denied"
    assert result.findings == []


def test_wrong_tool_decision_is_refused(tmp_path: Path) -> None:
    guard = _guard()
    decision = guard.check(
        Action(
            id="act-nmap",
            name=ActionName.NMAP_SCAN,
            target="in-scope.lab",
            ports=[80],
            arguments={"service_detection": True, "timing": 2, "host_timeout_seconds": 60},
            engagement_id="lab-01",
        )
    )
    result = WebScanAdapter(fetcher=_fetcher).run(
        decision,
        guard,
        AuditLog(tmp_path / "audit.jsonl"),
        Ledger(tmp_path / "evidence"),
        "analyst",
    )
    assert result.status == "denied"


def test_web_scan_action_is_in_the_closed_action_space() -> None:
    assert ActionName.WEB_SCAN.value == "web_scan"
    policy = _guard().policy
    assert "web_scan" in policy.enabled_actions
    assert "webscan" in policy.tool_arguments

"""Live web and transport security scanner.

A read-only GET probe that turns response headers and TLS negotiation into
evidence-backed findings. It runs only on a signed allow decision whose tool is
``webscan``, connects only to the guard's already-resolved IPs, sends no body or
caller-supplied headers, reads a bounded response, and never follows redirects.

Standard library only, so the live path has no external tool dependency. The
network fetcher is injectable so tests never open a socket.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from proofpath.adapters.base import ToolResult
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import EvidenceRef, Finding, FindingAsset, GuardDecision
from proofpath.scope_guard import ScopeGuard

MAX_PORTS = 8
MAX_BODY_BYTES = 4096
TIMEOUT_SECONDS = 5.0
_TLS_PORTS = {443, 8443, 9443}
_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)
_BANNER_HEADERS = ("server", "x-powered-by")
_WEAK_TLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
_VERSION_TOKEN = re.compile(r"\d+\.\d+")

Fetcher = Callable[[str, int, str, float], "WebEndpoint"]


@dataclass(frozen=True)
class WebEndpoint:
    """One probed endpoint and the raw facts it returned."""

    ip: str
    port: int
    scheme: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: tuple[str, ...] = ()
    tls_version: str | None = None
    cert_trusted: bool | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "port": self.port,
            "scheme": self.scheme,
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "set_cookies": list(self.set_cookies),
            "tls_version": self.tls_version,
            "cert_trusted": self.cert_trusted,
            "error": self.error,
        }


def _header_map(raw_headers: list[tuple[str, str]]) -> dict[str, str]:
    mapped: dict[str, str] = {}
    for name, value in raw_headers:
        key = name.lower()
        mapped.setdefault(key, value[:300])
    return mapped


def _set_cookies(raw_headers: list[tuple[str, str]]) -> tuple[str, ...]:
    return tuple(value[:300] for name, value in raw_headers if name.lower() == "set-cookie")


def _fetch_http(ip: str, port: int, timeout: float) -> WebEndpoint:
    connection = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        response.read(MAX_BODY_BYTES)
        raw = response.getheaders()
        return WebEndpoint(
            ip=ip,
            port=port,
            scheme="http",
            status_code=response.status,
            headers=_header_map(raw),
            set_cookies=_set_cookies(raw),
        )
    except (OSError, http.client.HTTPException) as exc:
        return WebEndpoint(ip=ip, port=port, scheme="http", error=f"{type(exc).__name__}: {exc}"[:300])
    finally:
        connection.close()


def _https_request(context: ssl.SSLContext, ip: str, port: int, timeout: float, *, trusted: bool) -> WebEndpoint:
    connection = http.client.HTTPSConnection(ip, port, timeout=timeout, context=context)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        response.read(MAX_BODY_BYTES)
        raw = response.getheaders()
        version = connection.sock.version() if connection.sock is not None else None
        return WebEndpoint(
            ip=ip,
            port=port,
            scheme="https",
            status_code=response.status,
            headers=_header_map(raw),
            set_cookies=_set_cookies(raw),
            tls_version=version,
            cert_trusted=trusted,
        )
    finally:
        connection.close()


def _fetch_https(ip: str, port: int, timeout: float) -> WebEndpoint:
    try:
        return _https_request(ssl.create_default_context(), ip, port, timeout, trusted=True)
    except ssl.SSLCertVerificationError as exc:
        # Retry without verification so the negotiated version is still captured.
        try:
            return _https_request(ssl._create_unverified_context(), ip, port, timeout, trusted=False)
        except (OSError, ssl.SSLError, http.client.HTTPException) as inner:
            return WebEndpoint(
                ip=ip, port=port, scheme="https", cert_trusted=False, error=f"{type(inner).__name__}: {inner}"[:300]
            )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return WebEndpoint(ip=ip, port=port, scheme="https", error=f"{type(exc).__name__}: {exc}"[:300])


def _default_fetch(ip: str, port: int, scheme: str, timeout: float) -> WebEndpoint:
    if scheme == "https":
        return _fetch_https(ip, port, timeout)
    return _fetch_http(ip, port, timeout)


def probe_endpoint(
    ip: str,
    port: int,
    *,
    fetch: Fetcher | None = None,
    timeout_seconds: float = TIMEOUT_SECONDS,
) -> WebEndpoint:
    """Probe one in-scope port, guessing the scheme from the port number."""
    fetch = fetch or _default_fetch
    scheme = "https" if port in _TLS_PORTS else "http"
    endpoint = fetch(ip, port, scheme, timeout_seconds)
    if endpoint.error:
        alternate = "http" if scheme == "https" else "https"
        retried = fetch(ip, port, alternate, timeout_seconds)
        if retried.error is None:
            return retried
    return endpoint


def _slug(ip: str, port: int, code: str) -> str:
    return f"F-WS-{ip.replace('.', '-').replace(':', '-')}-{port}-{code}"


def _finding(
    endpoint: WebEndpoint,
    *,
    evidence_id: str,
    index: int,
    captured_at: datetime,
    code: str,
    title: str,
    observed: str,
    severity: str,
    cwes: list[str],
    mapped_to: list[str],
) -> Finding:
    return Finding(
        id=_slug(endpoint.ip, endpoint.port, code),
        title=title,
        asset=FindingAsset(ip=endpoint.ip),
        port=endpoint.port,
        protocol="tcp",
        service="https" if endpoint.scheme == "https" else "http",
        source_tools=["webscan"],
        evidence=[EvidenceRef(evidence_id=evidence_id, locator=f"/endpoints/{index}", excerpt=observed[:300])],
        observed=observed[:500],
        inference="",
        severity=severity,
        cwes=cwes,
        mapped_to=mapped_to,
        confidence="high",
        status="confirmed",
        first_seen=captured_at,
        last_seen=captured_at,
    )


def analyze_endpoint(endpoint: WebEndpoint, evidence_id: str, captured_at: datetime, index: int) -> list[Finding]:
    """Turn one endpoint's raw headers and TLS facts into evidence-backed findings."""
    if endpoint.error or endpoint.status_code is None:
        return []
    findings: list[Finding] = []

    missing = [header for header in _SECURITY_HEADERS if header not in endpoint.headers]
    if missing:
        findings.append(
            _finding(
                endpoint,
                evidence_id=evidence_id,
                index=index,
                captured_at=captured_at,
                code="HDR",
                title="Missing HTTP security header(s)",
                observed=f"HTTP {endpoint.status_code} response omitted: {', '.join(missing)}",
                severity="low",
                cwes=["CWE-693"],
                mapped_to=["mapped to OWASP Top 10:2021-A05", "mapped to CWE"],
            )
        )

    banners = {name: endpoint.headers[name] for name in _BANNER_HEADERS if name in endpoint.headers}
    disclosed = {name: value for name, value in banners.items() if _VERSION_TOKEN.search(value)}
    if disclosed:
        observed = "; ".join(f"{name}: {value}" for name, value in disclosed.items())
        findings.append(
            _finding(
                endpoint,
                evidence_id=evidence_id,
                index=index,
                captured_at=captured_at,
                code="BANNER",
                title="Server banner discloses software version",
                observed=observed,
                severity="low",
                cwes=["CWE-200"],
                mapped_to=["mapped to OWASP Top 10:2021-A05", "mapped to CWE"],
            )
        )

    insecure = [cookie for cookie in endpoint.set_cookies if _cookie_is_insecure(cookie, endpoint.scheme)]
    if insecure:
        findings.append(
            _finding(
                endpoint,
                evidence_id=evidence_id,
                index=index,
                captured_at=captured_at,
                code="COOKIE",
                title="Cookie set without security flags",
                observed="Set-Cookie: " + " | ".join(insecure),
                severity="medium",
                cwes=["CWE-1004"],
                mapped_to=["mapped to OWASP Top 10:2021-A05", "mapped to CWE"],
            )
        )

    if endpoint.scheme == "https":
        problems: list[str] = []
        if endpoint.cert_trusted is False:
            problems.append("certificate is not trusted")
        if endpoint.tls_version in _WEAK_TLS:
            problems.append(f"negotiated {endpoint.tls_version}")
        if problems:
            observed = f"TLS {endpoint.tls_version or 'unknown'}; " + "; ".join(problems)
            findings.append(
                _finding(
                    endpoint,
                    evidence_id=evidence_id,
                    index=index,
                    captured_at=captured_at,
                    code="TLS",
                    title="Weak or untrusted TLS configuration",
                    observed=observed,
                    severity="high" if endpoint.cert_trusted is False else "medium",
                    cwes=["CWE-295"],
                    mapped_to=["mapped to OWASP Top 10:2021-A02", "mapped to CWE"],
                )
            )

    return findings


def _cookie_is_insecure(cookie: str, scheme: str) -> bool:
    lower = cookie.lower()
    if "httponly" not in lower:
        return True
    if scheme == "https" and "secure" not in lower:
        return True
    if "samesite" not in lower:
        return True
    return False


class WebScanAdapter:
    """Live web/TLS posture scan. Must run only on a signed ``webscan`` allow."""

    mode = "Live"

    def __init__(self, fetcher: Fetcher | None = None, *, timeout_seconds: float = TIMEOUT_SECONDS) -> None:
        self._fetcher = fetcher
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        decision: GuardDecision,
        guard: ScopeGuard,
        audit: AuditLog,
        ledger: Ledger,
        actor: str,
    ) -> ToolResult:
        if (
            not decision.allowed
            or decision.tool != "webscan"
            or not decision.resolved_ips
            or not decision.ports
            or not guard.verify_decision(decision)
        ):
            audit.append(
                "execution_blocked",
                actor,
                {"action_id": decision.action_id, "reason": "decision was not a signed webscan allow"},
            )
            return ToolResult(status="denied", decision=decision, message="webscan execution blocked")

        ip = decision.resolved_ips[0]
        ports = list(dict.fromkeys(decision.ports))[:MAX_PORTS]
        endpoints = [
            probe_endpoint(ip, port, fetch=self._fetcher, timeout_seconds=self.timeout_seconds) for port in ports
        ]
        artifact = json.dumps(
            {"tool": "webscan", "target": ip, "endpoints": [endpoint.as_dict() for endpoint in endpoints]},
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        responded = any(endpoint.status_code is not None for endpoint in endpoints)
        evidence = ledger.store(
            content=artifact,
            tool="webscan",
            command=["webscan", "GET", "/", ip, ",".join(str(port) for port in ports)],
            status="ok" if responded else "error",
            summary=f"webscan probed {len(endpoints)} port(s) on {ip}",
            source_mode="live",
        )
        findings: list[Finding] = []
        for index, endpoint in enumerate(endpoints):
            findings.extend(analyze_endpoint(endpoint, evidence.id, evidence.captured_at, index))
        audit.append(
            "webscan_result",
            actor,
            {
                "action_id": decision.action_id,
                "status": "ok" if responded else "error",
                "evidence_id": evidence.id,
                "sha256": evidence.sha256,
                "resolved_ips": decision.resolved_ips,
                "ports": ports,
                "findings": [finding.id for finding in findings],
            },
        )
        return ToolResult(
            status="ok" if responded else "error",
            decision=decision,
            evidence_id=evidence.id,
            sha256=evidence.sha256,
            findings=findings,
            parsed_items=len(endpoints),
            message=evidence.summary,
        )

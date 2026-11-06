"""Check externally verifiable claims against evidence cited by each finding."""

from __future__ import annotations

import re
from dataclasses import dataclass
import ipaddress

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Finding

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_CWE = re.compile(r"\bCWE-\d+\b", re.I)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?![0-9A-Fa-f:])")
_EVIDENCE = re.compile(r"\bEV-\d+\b")
_PORT = re.compile(r"\bport\s+(\d{1,5})\b|(?<!:):(\d{1,5})(?:\b|/)" , re.I)
_VERSION = re.compile(r"\b([A-Za-z][A-Za-z0-9.+-]{1,40})(?:/|[ _])v?(\d+(?:\.\d+){1,4}(?:p\d+|[-+][A-Za-z0-9_.-]+)?)\b")


@dataclass(frozen=True)
class GroundingResult:
    accepted: bool
    violations: tuple[str, ...]


def verify_text(text: str, cited_evidence_ids: list[str], ledger: Ledger) -> GroundingResult:
    """Reject identifiers and concrete endpoint/version claims absent from cited bytes."""
    violations: list[str] = []
    refs = list(dict.fromkeys(cited_evidence_ids))
    if not refs:
        return GroundingResult(False, ("no evidence IDs were cited",))
    corpus: list[str] = []
    for evidence_id in refs:
        try:
            evidence = ledger.load(evidence_id)
            raw = ledger.read_bytes(evidence_id)
        except (OSError, ValueError) as exc:
            violations.append(f"{evidence_id}: unavailable ledger evidence ({type(exc).__name__})")
            continue
        import hashlib
        if hashlib.sha256(raw).hexdigest() != evidence.sha256:
            violations.append(f"{evidence_id}: ledger hash mismatch")
            continue
        corpus.append(raw.decode("utf-8", errors="replace").casefold())
    evidence_text = "\n".join(corpus)
    for identifier in _CVE.findall(text):
        if identifier.casefold() not in evidence_text:
            violations.append(f"unsupported CVE: {identifier}")
    for identifier in _CWE.findall(text):
        if identifier.casefold() not in evidence_text:
            violations.append(f"unsupported CWE: {identifier}")
    evidence_addresses = _addresses(evidence_text)
    for address in _addresses(text):
        if address not in evidence_addresses:
            violations.append(f"unsupported IP address: {address}")
    for match in _PORT.findall(text):
        port = next(value for value in match if value)
        if not re.search(rf"(?:port\s*=\s*['\"]?{port}\b|\b{port}/(?:tcp|udp)\b|\bport\s+{port}\b)", evidence_text, re.I):
            violations.append(f"unsupported port: {port}")
    for product, version in _VERSION.findall(text):
        if product.casefold() not in evidence_text or version.casefold() not in evidence_text:
            violations.append(f"unsupported product/version: {product} {version}")
    for evidence_id in _EVIDENCE.findall(text):
        if evidence_id not in refs:
            violations.append(f"uncited evidence ID: {evidence_id}")
    return GroundingResult(not violations, tuple(dict.fromkeys(violations)))


def verify_finding(finding: Finding, ledger: Ledger, audit: AuditLog | None = None) -> GroundingResult:
    cited = list(dict.fromkeys(ref.evidence_id for ref in finding.evidence))
    claim_text = " ".join((finding.title, finding.observed, finding.inference, finding.asset.ip, str(finding.port), *finding.cves, *finding.cwes))
    result = verify_text(claim_text, cited, ledger)
    if not result.accepted and audit is not None:
        audit.append("grounding_rejected", "grounding-verifier", {"finding_id": finding.id, "evidence_ids": cited, "violations": list(result.violations), "fallback": "tool-reported template"})
    return result


def _addresses(text: str) -> set[str]:
    found: set[str] = set()
    candidates = [*_IPV4.findall(text), *_IPV6_CANDIDATE.findall(text)]
    for candidate in candidates:
        try:
            found.add(ipaddress.ip_address(candidate).compressed.casefold())
        except ValueError:
            continue
    return found

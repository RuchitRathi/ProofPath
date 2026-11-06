"""Deterministic mappings from tool-reported fields to Finding records."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

from proofpath.schemas import EvidenceRef, Finding, FindingAsset, ServiceObservation

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)


def normalize_nmap_observations(observations: list[ServiceObservation]) -> list[ServiceObservation]:
    """Preserve nmap service facts as observations; banners never become findings."""
    return [observation.model_copy(deep=True) for observation in observations]


def normalize_nessus(item: Any, evidence_id: str, captured_at: datetime) -> Finding | None:
    """Create a finding only from a Nessus ReportItem with an explicit host IP."""
    if item.asset_ip is None or item.port is None:
        return None
    reference = EvidenceRef(evidence_id=evidence_id, locator=item.locator, excerpt=item.excerpt)
    observed = [f"Nessus plugin {item.plugin_id}: {item.plugin_name}", f"Port {item.port}/{item.protocol}"]
    if item.description:
        observed.append("Description: " + item.description)
    if item.plugin_output:
        observed.append("Plugin output: " + item.plugin_output)
    timestamp = captured_at.astimezone(timezone.utc)
    return Finding(
        id=f"F-{evidence_id[3:]}-{item.host_index:03d}-{item.item_index:03d}",
        title=item.plugin_name or "Nessus report item",
        asset=FindingAsset(ip=item.asset_ip, hostname=item.hostname),
        port=item.port,
        protocol=item.protocol,
        service=item.service,
        source_tools=["nessus"],
        evidence=[reference],
        observed="; ".join(observed),
        inference="",
        severity=item.severity,
        cvss=item.cvss,
        cvss_vector=item.cvss_vector,
        exploit_available=getattr(item, "exploit_available", None),
        cves=item.cves,
        cwes=item.cwes,
        confidence="low",  # Nessus XML does not supply a confidence field in this mapping.
        status="suspected",
        first_seen=timestamp,
        last_seen=timestamp,
    )


def normalize_burp(issue: Any, evidence_id: str, captured_at: datetime, resolved_ips: list[str]) -> list[Finding]:
    """Create one finding per verified address represented by a Burp host URL."""
    addresses = [issue.asset_ip] if issue.asset_ip else list(resolved_ips)
    observed = [f"Burp issue: {issue.title}", f"Host: {issue.host_text}", f"Path: {issue.path}", f"Location: {issue.location}"]
    if issue.issue_background:
        observed.append("Issue background: " + issue.issue_background)
    if issue.issue_detail:
        observed.append("Issue detail: " + issue.issue_detail)
    if issue.remediation:
        observed.append("Remediation: " + issue.remediation)
    if issue.requestresponse_count:
        observed.append(f"Request/response records preserved in raw artifact: {issue.requestresponse_count}")
    # CVE/CWE values are extracted only when those identifiers literally occur in the issue detail.
    cves = list(dict.fromkeys(match.upper() for match in _CVE.findall(issue.issue_detail)))
    cwes = list(dict.fromkeys(match.upper() for match in _CWE.findall(issue.issue_detail)))
    reference = EvidenceRef(evidence_id=evidence_id, locator=issue.locator, excerpt=issue.excerpt)
    timestamp = captured_at.astimezone(timezone.utc)
    return [
        Finding(
            id=f"F-{evidence_id[3:]}-B{issue.index:03d}-{addr.replace(':', '_').replace('.', '_')}",
            title=issue.title,
            asset=FindingAsset(ip=addr, hostname=issue.hostname),
            port=issue.port,
            protocol=issue.protocol,
            service=issue.service,
            source_tools=["burp"],
            evidence=[reference],
            observed="; ".join(observed),
            inference="",
            severity=issue.severity,
            confidence=issue.confidence,
            status="suspected",
            first_seen=timestamp,
            last_seen=timestamp,
            cves=cves,
            cwes=cwes,
        )
        for addr in addresses
    ]

"""Deterministic mappings from tool-reported fields to Finding records."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

from proofpath.schemas import EvidenceRef, Finding, FindingAsset, ServiceObservation

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)


def map_standards(cwes: list[str], cves: list[str] | None = None) -> list[str]:
    """Map observed CWEs/CVEs to standard security frameworks with 'mapped to' wording."""
    standards: list[str] = ["mapped to NIST SP 800-115"]
    cwe_set = {cwe.upper() for cwe in cwes}
    
    # OWASP Top 10:2021, MITRE ATT&CK, NIST CSF 2.0 mapping by CWE
    if "CWE-79" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A03 (Injection)")
        standards.append("mapped to MITRE ATT&CK:T1189 (Drive-by Compromise)")
        standards.append("mapped to NIST CSF 2.0:PR.DS-01")
    elif "CWE-89" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A03 (Injection)")
        standards.append("mapped to MITRE ATT&CK:T1190 (Exploit Public-Facing Application)")
        standards.append("mapped to NIST CSF 2.0:PR.DS-01")
    elif "CWE-22" in cwe_set or "CWE-23" in cwe_set or "CWE-35" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A01 (Broken Access Control)")
        standards.append("mapped to MITRE ATT&CK:T1083 (File and Directory Discovery)")
        standards.append("mapped to NIST CSF 2.0:PR.AC-04")
    elif "CWE-200" in cwe_set or "CWE-209" in cwe_set or "CWE-538" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A05 (Security Misconfiguration)")
        standards.append("mapped to MITRE ATT&CK:T1592 (Gather Victim Host Information)")
        standards.append("mapped to NIST CSF 2.0:PR.DS-05")
    elif "CWE-287" in cwe_set or "CWE-384" in cwe_set or "CWE-306" in cwe_set or "CWE-798" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A07 (Identification and Authentication Failures)")
        standards.append("mapped to MITRE ATT&CK:T1078 (Valid Accounts)")
        standards.append("mapped to NIST CSF 2.0:PR.AC-01")
    elif "CWE-352" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A01 (Broken Access Control)")
        standards.append("mapped to MITRE ATT&CK:T1189 (Drive-by Compromise)")
        standards.append("mapped to NIST CSF 2.0:PR.AC-04")
    elif "CWE-502" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A08 (Software and Data Integrity Failures)")
        standards.append("mapped to MITRE ATT&CK:T1190 (Exploit Public-Facing Application)")
        standards.append("mapped to NIST CSF 2.0:PR.DS-06")
    elif "CWE-918" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A10 (Server-Side Request Forgery)")
        standards.append("mapped to MITRE ATT&CK:T1190 (Exploit Public-Facing Application)")
        standards.append("mapped to NIST CSF 2.0:PR.PT-04")
    elif "CWE-94" in cwe_set or "CWE-78" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A03 (Injection)")
        standards.append("mapped to MITRE ATT&CK:T1059 (Command and Scripting Interpreter)")
        standards.append("mapped to NIST CSF 2.0:PR.DS-01")
    elif "CWE-319" in cwe_set or "CWE-326" in cwe_set or "CWE-327" in cwe_set:
        standards.append("mapped to OWASP Top 10:2021-A02 (Cryptographic Failures)")
        standards.append("mapped to MITRE ATT&CK:T1573 (Encrypted Channel)")
        standards.append("mapped to NIST CSF 2.0:PR.DS-02")
    elif cwes:
        standards.append("mapped to OWASP Top 10:2021")
        standards.append("mapped to MITRE ATT&CK Enterprise")
        standards.append("mapped to NIST CSF 2.0:PR.IP")
    if cves:
        standards.append("mapped to Common Vulnerabilities and Exposures (CVE)")
    return list(dict.fromkeys(standards))


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
        mapped_to=map_standards(item.cwes, item.cves),
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
            mapped_to=map_standards(cwes, cves),
        )
        for addr in addresses
    ]


def normalize_openvas(item: Any, evidence_id: str, captured_at: datetime) -> Finding | None:
    """Create a finding from an OpenVAS / Greenbone result record."""
    if item.asset_ip is None or item.port is None:
        return None
    reference = EvidenceRef(evidence_id=evidence_id, locator=item.locator, excerpt=item.excerpt)
    observed = [f"OpenVAS result: {item.name}", f"Port: {item.port}/{item.protocol}"]
    if item.description:
        observed.append("Description: " + item.description)
    if item.nvt_name:
        observed.append("NVT: " + item.nvt_name)
    if item.solution:
        observed.append("Solution: " + item.solution)
    timestamp = captured_at.astimezone(timezone.utc)
    return Finding(
        id=f"F-{evidence_id[3:]}-OV{item.index:03d}",
        title=item.name or "OpenVAS finding",
        asset=FindingAsset(ip=item.asset_ip, hostname=item.hostname),
        port=item.port,
        protocol=item.protocol,
        service=item.service,
        source_tools=["openvas"],
        evidence=[reference],
        observed="; ".join(observed),
        inference="",
        severity=item.severity,
        cvss=item.cvss,
        cvss_vector=item.cvss_vector,
        cves=item.cves,
        cwes=item.cwes,
        mapped_to=map_standards(item.cwes, item.cves),
        confidence="medium",
        status="suspected",
        first_seen=timestamp,
        last_seen=timestamp,
    )


def normalize_nikto(item: Any, evidence_id: str, captured_at: datetime) -> Finding | None:
    """Create a finding from a Nikto web security observation."""
    if item.asset_ip is None or item.port is None:
        return None
    reference = EvidenceRef(evidence_id=evidence_id, locator=item.locator, excerpt=item.excerpt)
    observed = [f"Nikto finding: {item.title}", f"Target: {item.asset_ip}:{item.port}", f"URI: {item.uri}"]
    if item.message:
        observed.append("Details: " + item.message)
    if item.osvdb:
        observed.append(f"OSVDB: {item.osvdb}")
    timestamp = captured_at.astimezone(timezone.utc)
    return Finding(
        id=f"F-{evidence_id[3:]}-NK{item.index:03d}",
        title=item.title or "Nikto web configuration finding",
        asset=FindingAsset(ip=item.asset_ip, hostname=item.hostname),
        port=item.port,
        protocol=item.protocol or "tcp",
        service=item.service or "http",
        source_tools=["nikto"],
        evidence=[reference],
        observed="; ".join(observed),
        inference="",
        severity=item.severity,
        cvss=item.cvss,
        cves=item.cves,
        cwes=item.cwes,
        mapped_to=map_standards(item.cwes, item.cves),
        confidence="medium",
        status="suspected",
        first_seen=timestamp,
        last_seen=timestamp,
    )


def normalize_zap(item: Any, evidence_id: str, captured_at: datetime) -> Finding | None:
    """Create a finding from an OWASP ZAP alert record."""
    if item.asset_ip is None or item.port is None:
        return None
    reference = EvidenceRef(evidence_id=evidence_id, locator=item.locator, excerpt=item.excerpt)
    observed = [f"OWASP ZAP alert: {item.alert}", f"Port: {item.port}/{item.protocol}", f"URI: {item.uri}"]
    if item.description:
        observed.append("Description: " + item.description)
    if item.param:
        observed.append("Parameter: " + item.param)
    if item.solution:
        observed.append("Solution: " + item.solution)
    timestamp = captured_at.astimezone(timezone.utc)
    return Finding(
        id=f"F-{evidence_id[3:]}-ZP{item.index:03d}",
        title=item.alert or "OWASP ZAP vulnerability alert",
        asset=FindingAsset(ip=item.asset_ip, hostname=item.hostname),
        port=item.port,
        protocol=item.protocol or "tcp",
        service=item.service or "http",
        source_tools=["zap"],
        evidence=[reference],
        observed="; ".join(observed),
        inference="",
        severity=item.severity,
        cvss=item.cvss,
        cves=item.cves,
        cwes=item.cwes,
        mapped_to=map_standards(item.cwes, item.cves),
        confidence=item.confidence or "medium",
        status="suspected",
        first_seen=timestamp,
        last_seen=timestamp,
    )


def normalize_metasploit(item: Any, evidence_id: str, captured_at: datetime) -> Finding | None:
    """Create a finding from a Metasploit finding/validation record."""
    if item.asset_ip is None or item.port is None:
        return None
    reference = EvidenceRef(evidence_id=evidence_id, locator=item.locator, excerpt=item.excerpt)
    observed = [f"Metasploit finding: {item.title}", f"Port: {item.port}/{item.protocol}"]
    if item.info:
        observed.append("Details: " + item.info)
    timestamp = captured_at.astimezone(timezone.utc)
    val_status = "validated_approved" if item.validated else "not_validated"
    return Finding(
        id=f"F-{evidence_id[3:]}-MS{item.index:03d}",
        title=item.title or "Metasploit vulnerability record",
        asset=FindingAsset(ip=item.asset_ip, hostname=item.hostname),
        port=item.port,
        protocol=item.protocol or "tcp",
        service=item.service or "unknown",
        source_tools=["metasploit"],
        evidence=[reference],
        observed="; ".join(observed),
        inference="",
        severity=item.severity or "high",
        cvss=item.cvss,
        cves=item.cves,
        cwes=item.cwes,
        mapped_to=map_standards(item.cwes, item.cves),
        confidence="high" if item.validated else "medium",
        status="confirmed" if item.validated else "suspected",
        validation_status=val_status,
        first_seen=timestamp,
        last_seen=timestamp,
    )

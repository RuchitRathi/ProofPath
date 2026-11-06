"""Deterministic, evidence-preserving finding correlation."""

from __future__ import annotations

import re

from proofpath.schemas import EvidenceRef, Finding, ServiceObservation


def correlate_findings(findings: list[Finding], services: list[ServiceObservation] | None = None) -> list[Finding]:
    """Merge exact asset/port/protocol identities and attach nmap contradictions."""
    merged_by_key: dict[tuple[object, ...], Finding] = {}
    for source in findings:
        current = source.model_copy(deep=True)
        key = _dedup_key(current)
        prior = merged_by_key.get(key)
        if prior is None:
            merged_by_key[key] = current
            continue
        merged_by_key[key] = _merge(prior, current)

    merged = list(merged_by_key.values())
    for finding in merged:
        matching = [row for row in services or [] if _same_endpoint(finding, row)]
        for row in matching:
            if row.state.lower() != "closed":
                continue
            ref = EvidenceRef(evidence_id=row.evidence_id, locator=row.locator, excerpt=row.excerpt)
            _append_evidence(finding, ref)
            if "nmap" not in finding.source_tools:
                finding.source_tools.append("nmap")
            note = f"Conflict: {','.join(tool for tool in finding.source_tools if tool != 'nmap')} reports a finding; nmap reports {row.port}/{row.protocol} state=closed."
            _append_note(finding, note)
            vuln_sources = [tool for tool in finding.source_tools if tool != "nmap"]
            finding.status = "false_positive_candidate" if len(vuln_sources) == 1 and finding.confidence == "low" else "suspected"
    return merged


def _dedup_key(finding: Finding) -> tuple[object, ...]:
    asset = finding.asset.ip
    port = finding.port
    protocol = finding.protocol.casefold()
    if finding.cves:
        identifier: tuple[object, ...] = ("CVE", *sorted(set(value.upper() for value in finding.cves)))
    elif finding.cwes:
        identifier = ("CWE", *sorted(set(value.upper() for value in finding.cwes)))
    else:
        title = re.sub(r"[^a-z0-9]+", " ", finding.title.casefold()).strip()
        identifier = ("TITLE", title)
    return asset, port, protocol, identifier


def _merge(left: Finding, right: Finding) -> Finding:
    sources_before = list(dict.fromkeys([*left.source_tools, *right.source_tools]))
    notes = list(left.conflict_notes)
    notes.extend(right.conflict_notes)
    severity_conflict = left.severity != "not_provided" and right.severity != "not_provided" and left.severity != right.severity
    if severity_conflict:
        _append_note_to(notes, f"Severity conflict: {left.source_tools[0]}={left.severity}; {right.source_tools[0]}={right.severity}.")
    cvss_conflict = left.cvss is not None and right.cvss is not None and left.cvss != right.cvss
    vector_conflict = bool(left.cvss_vector and right.cvss_vector and left.cvss_vector != right.cvss_vector)
    if cvss_conflict:
        _append_note_to(notes, f"CVSS score conflict: {left.source_tools[0]}={left.cvss}; {right.source_tools[0]}={right.cvss}.")
    if vector_conflict:
        _append_note_to(notes, f"CVSS vector conflict: {left.source_tools[0]} and {right.source_tools[0]} report different vectors.")
    service_conflict = bool(left.service and right.service and left.service.casefold() != right.service.casefold())
    if service_conflict:
        _append_note_to(notes, f"Service conflict: {left.source_tools[0]}={left.service}; {right.source_tools[0]}={right.service}.")

    evidence = list(left.evidence)
    for ref in right.evidence:
        _append_evidence_to(evidence, ref)
    cves = list(dict.fromkeys([*left.cves, *right.cves]))
    cwes = list(dict.fromkeys([*left.cwes, *right.cwes]))
    severity = "not_provided" if severity_conflict else (left.severity if left.severity != "not_provided" else right.severity)
    cvss = None if cvss_conflict else (left.cvss if left.cvss is not None else right.cvss)
    vector = None if vector_conflict else (left.cvss_vector or right.cvss_vector)
    conflicts = severity_conflict or cvss_conflict or vector_conflict or service_conflict
    independent_sources = len(set(sources_before)) >= 2
    confidence = "high" if independent_sources and not conflicts else _lower_confidence(left.confidence, right.confidence)
    status = "suspected" if conflicts else ("confirmed" if independent_sources else left.status)
    return left.model_copy(
        update={
            "source_tools": sources_before,
            "evidence": evidence,
            "observed": _merge_observed(left, right),
            "severity": severity,
            "cvss": cvss,
            "cvss_vector": vector,
            "cves": cves,
            "cwes": cwes,
            "service": None if service_conflict else (left.service or right.service),
            "confidence": confidence,
            "status": status,
            "first_seen": min(left.first_seen, right.first_seen),
            "last_seen": max(left.last_seen, right.last_seen),
            "conflict_notes": notes,
        }
    )


def _merge_observed(left: Finding, right: Finding) -> str:
    rows: list[str] = []
    for finding in (left, right):
        segment = f"{finding.source_tools[0]}: {finding.observed}"
        if segment not in rows:
            rows.append(segment)
    return " | ".join(rows)


def _lower_confidence(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return left if order[left] <= order[right] else right


def _same_endpoint(finding: Finding, observation: ServiceObservation) -> bool:
    return (
        finding.asset.ip == observation.ip
        and finding.port == observation.port
        and finding.protocol.casefold() == observation.protocol.casefold()
    )


def _append_evidence(finding: Finding, reference: EvidenceRef) -> None:
    _append_evidence_to(finding.evidence, reference)


def _append_evidence_to(evidence: list[EvidenceRef], reference: EvidenceRef) -> None:
    if not any((item.evidence_id, item.locator, item.excerpt) == (reference.evidence_id, reference.locator, reference.excerpt) for item in evidence):
        evidence.append(reference)


def _append_note(finding: Finding, note: str) -> None:
    _append_note_to(finding.conflict_notes, note)


def _append_note_to(notes: list[str], note: str) -> None:
    if note not in notes:
        notes.append(note)

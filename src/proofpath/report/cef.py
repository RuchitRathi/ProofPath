"""ArcSight CEF exporter so findings land directly in a SIEM.

Each correlated finding becomes one Common Event Format record. Records can be
written on their own or wrapped in an RFC 3164 syslog frame for collection by a
syslog relay. The mapping mirrors `report/sarif.py`: the same finding fields are
carried, just expressed as CEF keys a SIEM already understands.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from proofpath.schemas import Finding

_DEVICE_VENDOR = "ProofPath"
_DEVICE_PRODUCT = "ProofPath VAPT"

_SEVERITY_MAP = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 1,
    "not_provided": 0,
}


def _escape_header(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _escape_extension(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _signature_id(finding: Finding) -> str:
    if finding.cves:
        return finding.cves[0]
    if finding.cwes:
        return finding.cwes[0]
    return finding.id


def _severity(finding: Finding) -> int:
    if finding.cvss is not None:
        return max(0, min(10, int(round(finding.cvss))))
    return _SEVERITY_MAP.get(finding.severity, 0)


def finding_to_cef(finding: Finding, *, device_version: str = "0.1.0") -> str:
    """Render one finding as a single CEF:0 record."""
    header = "|".join(
        [
            "CEF:0",
            _escape_header(_DEVICE_VENDOR),
            _escape_header(_DEVICE_PRODUCT),
            _escape_header(device_version),
            _escape_header(_signature_id(finding)),
            _escape_header(finding.title),
            str(_severity(finding)),
        ]
    )
    ext: list[tuple[str, str]] = [
        ("src", finding.asset.ip),
        ("dpt", str(finding.port)),
        ("proto", finding.protocol),
        ("externalId", finding.id),
        ("cat", "Vulnerability"),
        ("rt", finding.last_seen.astimezone(timezone.utc).isoformat()),
    ]
    if finding.cvss is not None:
        ext.append(("cs1Label", "CVSS"))
        ext.append(("cs1", f"{finding.cvss:.1f}"))
    if finding.cves:
        ext.append(("cs2Label", "CVE"))
        ext.append(("cs2", ",".join(finding.cves)))
    if finding.cwes:
        ext.append(("cs3Label", "CWE"))
        ext.append(("cs3", ",".join(finding.cwes)))
    ext.extend(
        [
            ("cs4Label", "Tools"),
            ("cs4", ",".join(finding.source_tools)),
            ("cs5Label", "Confidence"),
            ("cs5", finding.confidence),
            ("cs6Label", "Evidence"),
            ("cs6", ",".join(ref.evidence_id for ref in finding.evidence)),
            ("msg", finding.observed),
        ]
    )
    body = " ".join(
        f"{key}={_escape_extension(value)}" for key, value in ext if value
    )
    return f"{header}|{body}"


def export_cef(findings: list[Finding], *, device_version: str = "0.1.0") -> list[str]:
    """Return one CEF record per finding."""
    return [finding_to_cef(finding, device_version=device_version) for finding in findings]


def write_cef(
    findings: list[Finding],
    output_path: str | Path,
    *,
    device_version: str = "0.1.0",
) -> list[str]:
    """Write newline-delimited CEF records to disk and return them."""
    records = export_cef(findings, device_version=device_version)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(records) + ("\n" if records else ""), encoding="utf-8")
    return records


def export_syslog(
    findings: list[Finding],
    *,
    host: str = "proofpath",
    facility: int = 13,
    severity: int = 5,
    device_version: str = "0.1.0",
) -> list[str]:
    """Wrap each CEF record in an RFC 3164 syslog frame for a syslog collector."""
    priority = facility * 8 + severity
    stamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return [
        f"<{priority}>{stamp} {host} {record}"
        for record in export_cef(findings, device_version=device_version)
    ]


def write_syslog(
    findings: list[Finding],
    output_path: str | Path,
    *,
    host: str = "proofpath",
    facility: int = 13,
    severity: int = 5,
    device_version: str = "0.1.0",
) -> list[str]:
    """Write newline-delimited syslog-framed CEF records to disk and return them."""
    records = export_syslog(
        findings, host=host, facility=facility, severity=severity, device_version=device_version
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(records) + ("\n" if records else ""), encoding="utf-8")
    return records

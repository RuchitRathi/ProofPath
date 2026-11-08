"""Deterministic priority scoring; reported and observed inputs stay traceable."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from proofpath.schemas import Finding, ServiceObservation
from proofpath.threat_intel import PublicThreatIntel

Criticality = Literal["low", "medium", "high"]

WEIGHTS: dict[str, float] = {
    "reported_severity": 0.16,
    "reported_cvss": 0.16,
    "observed_exposure": 0.12,
    "reported_exploitability": 0.12,
    "analyst_criticality": 0.12,
    "correlation_confidence": 0.12,
    "nvd_cvss_context": 0.08,
    "epss_probability": 0.08,
    "cisa_kev_listing": 0.04,
}
SEVERITY_VALUE = {"critical": 10.0, "high": 8.0, "medium": 6.0, "low": 3.0, "info": 1.0}
CRITICALITY_VALUE: dict[Criticality, float] = {"low": 2.0, "medium": 5.0, "high": 10.0}
STATUS_TIER = {"confirmed": 0, "suspected": 0, "false_positive_candidate": 1, "refuted": 2}


class RiskFactor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    value: str
    normalized: float | None
    source: str
    weight: float
    included: bool


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding: Finding
    rank: int
    priority_score: float | None
    status_label: str
    factors: list[RiskFactor]


def rank_findings(
    findings: list[Finding],
    observations: list[ServiceObservation],
    criticality: dict[str, Criticality] | None = None,
    public_intel: PublicThreatIntel | None = None,
) -> list[RiskAssessment]:
    """Rank on documented factors; unknowns are excluded and weights renormalized."""
    values = criticality or {}
    assessed: list[RiskAssessment] = []
    for finding in findings:
        factors = _factors(finding, observations, values.get(finding.asset.ip, "medium"), public_intel)
        included = [factor for factor in factors if factor.included and factor.normalized is not None]
        score = (
            round(sum(factor.normalized * factor.weight for factor in included) / sum(factor.weight for factor in included) * 10, 1)
            if included else None
        )
        label = finding.status.replace("_", " ")
        assessed.append(RiskAssessment(finding=finding, rank=0, priority_score=score, status_label=label, factors=factors))
    assessed.sort(key=lambda row: (STATUS_TIER[row.finding.status], -(row.priority_score if row.priority_score is not None else -1), row.finding.id))
    return [row.model_copy(update={"rank": index}) for index, row in enumerate(assessed, 1)]


def _factors(
    finding: Finding,
    observations: list[ServiceObservation],
    criticality: Criticality,
    public_intel: PublicThreatIntel | None = None,
) -> list[RiskFactor]:
    severity = finding.severity
    severity_value = SEVERITY_VALUE.get(severity)
    cvss = finding.cvss
    open_observation = next((row for row in observations if row.source_mode == "live" and row.ip == finding.asset.ip and row.port == finding.port and row.protocol.casefold() == finding.protocol.casefold() and row.state.casefold() == "open"), None)
    exposure_value = 10.0 if open_observation else None
    exploit = finding.exploit_available
    factors = [
        RiskFactor(name="reported_severity", value=severity if severity_value is not None else "not provided", normalized=severity_value, source=f"finding:{finding.id}.severity", weight=WEIGHTS["reported_severity"], included=severity_value is not None),
        RiskFactor(name="reported_cvss", value=f"{cvss:.1f}" if cvss is not None else "not provided", normalized=cvss, source=f"finding:{finding.id}.cvss", weight=WEIGHTS["reported_cvss"], included=cvss is not None),
        RiskFactor(name="observed_exposure", value="exposed" if open_observation else "unknown", normalized=exposure_value, source=f"nmap:{open_observation.evidence_id}" if open_observation else "no matching open nmap observation", weight=WEIGHTS["observed_exposure"], included=open_observation is not None),
        RiskFactor(name="reported_exploitability", value=str(exploit).lower() if exploit is not None else "not provided", normalized=10.0 if exploit else 0.0 if exploit is False else None, source=f"finding:{finding.id}.exploit_available", weight=WEIGHTS["reported_exploitability"], included=exploit is not None),
        RiskFactor(name="analyst_criticality", value=criticality, normalized=CRITICALITY_VALUE[criticality], source="analyst-set; default medium", weight=WEIGHTS["analyst_criticality"], included=True),
        RiskFactor(name="correlation_confidence", value=finding.confidence, normalized={"low": 3.0, "medium": 6.0, "high": 9.0}[finding.confidence], source=f"correlator:{finding.id}.confidence", weight=WEIGHTS["correlation_confidence"], included=True),
    ]
    kev_cve = next((cve for cve in finding.cves if public_intel and cve in public_intel.kev), None)
    kev_match = public_intel.kev[kev_cve] if public_intel and kev_cve else None
    epss_matches = [(cve, public_intel.epss[cve]) for cve in finding.cves if public_intel and cve in public_intel.epss]
    nvd_matches = [(cve, public_intel.nvd[cve]) for cve in finding.cves if public_intel and cve in public_intel.nvd]
    best_epss = max(epss_matches, key=lambda item: item[1].probability) if epss_matches else None
    best_nvd = max((item for item in nvd_matches if item[1].cvss is not None), key=lambda item: item[1].cvss or -1, default=None)
    kev_source = f"CISA KEV:{public_intel.kev_evidence_id}" if public_intel else "CISA KEV unavailable"
    epss_source = f"FIRST EPSS:{public_intel.epss_evidence_id}" if public_intel else "FIRST EPSS unavailable"
    if public_intel:
        factors.extend([
            RiskFactor(
                name="nvd_cvss_context",
                value=(f"{best_nvd[1].cvss:.1f} ({best_nvd[1].version or 'NVD CVSS'})" if best_nvd else "not available in NVD snapshot"),
                normalized=best_nvd[1].cvss if best_nvd and cvss is None else None,
                source=(f"NVD:{best_nvd[1].evidence_id}:{best_nvd[0]}" if best_nvd else "NVD CVE lookup not available"),
                weight=WEIGHTS["nvd_cvss_context"],
                included=bool(best_nvd and cvss is None),
            ),
            RiskFactor(
                name="epss_probability",
                value=(f"{best_epss[1].probability:.4f} probability ({best_epss[1].percentile:.1%} percentile)" if best_epss else "not scored by EPSS"),
                normalized=(best_epss[1].probability * 10 if best_epss else None),
                source=(f"{epss_source}:{best_epss[0]}" if best_epss else epss_source),
                weight=WEIGHTS["epss_probability"],
                included=best_epss is not None,
            ),
            RiskFactor(
                name="cisa_kev_listing",
                value=(f"listed {kev_match.date_added}" if kev_match else "not listed in current KEV snapshot"),
                normalized=10.0 if kev_match else None,
                source=(f"{kev_source}:{kev_cve}" if kev_match and kev_cve else kev_source),
                weight=WEIGHTS["cisa_kev_listing"],
                included=kev_match is not None,
            ),
        ])
    return factors

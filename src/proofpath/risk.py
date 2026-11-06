"""Deterministic priority scoring; reported and observed inputs stay traceable."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from proofpath.schemas import Finding, ServiceObservation

Criticality = Literal["low", "medium", "high"]

WEIGHTS: dict[str, float] = {
    "reported_severity": 0.20,
    "reported_cvss": 0.20,
    "observed_exposure": 0.15,
    "reported_exploitability": 0.15,
    "analyst_criticality": 0.15,
    "correlation_confidence": 0.15,
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
) -> list[RiskAssessment]:
    """Rank on documented factors; unknowns are excluded and weights renormalized."""
    values = criticality or {}
    assessed: list[RiskAssessment] = []
    for finding in findings:
        factors = _factors(finding, observations, values.get(finding.asset.ip, "medium"))
        included = [factor for factor in factors if factor.included and factor.normalized is not None]
        score = (
            round(sum(factor.normalized * factor.weight for factor in included) / sum(factor.weight for factor in included) * 10, 1)
            if included else None
        )
        label = finding.status.replace("_", " ")
        assessed.append(RiskAssessment(finding=finding, rank=0, priority_score=score, status_label=label, factors=factors))
    assessed.sort(key=lambda row: (STATUS_TIER[row.finding.status], -(row.priority_score if row.priority_score is not None else -1), row.finding.id))
    return [row.model_copy(update={"rank": index}) for index, row in enumerate(assessed, 1)]


def _factors(finding: Finding, observations: list[ServiceObservation], criticality: Criticality) -> list[RiskFactor]:
    severity = finding.severity
    severity_value = SEVERITY_VALUE.get(severity)
    cvss = finding.cvss
    open_observation = next((row for row in observations if row.source_mode == "live" and row.ip == finding.asset.ip and row.port == finding.port and row.protocol.casefold() == finding.protocol.casefold() and row.state.casefold() == "open"), None)
    exposure_value = 10.0 if open_observation else None
    exploit = finding.exploit_available
    return [
        RiskFactor(name="reported_severity", value=severity if severity_value is not None else "not provided", normalized=severity_value, source=f"finding:{finding.id}.severity", weight=WEIGHTS["reported_severity"], included=severity_value is not None),
        RiskFactor(name="reported_cvss", value=f"{cvss:.1f}" if cvss is not None else "not provided", normalized=cvss, source=f"finding:{finding.id}.cvss", weight=WEIGHTS["reported_cvss"], included=cvss is not None),
        RiskFactor(name="observed_exposure", value="exposed" if open_observation else "unknown", normalized=exposure_value, source=f"nmap:{open_observation.evidence_id}" if open_observation else "no matching open nmap observation", weight=WEIGHTS["observed_exposure"], included=open_observation is not None),
        RiskFactor(name="reported_exploitability", value=str(exploit).lower() if exploit is not None else "not provided", normalized=10.0 if exploit else 0.0 if exploit is False else None, source=f"finding:{finding.id}.exploit_available", weight=WEIGHTS["reported_exploitability"], included=exploit is not None),
        RiskFactor(name="analyst_criticality", value=criticality, normalized=CRITICALITY_VALUE[criticality], source="analyst-set; default medium", weight=WEIGHTS["analyst_criticality"], included=True),
        RiskFactor(name="correlation_confidence", value=finding.confidence, normalized={"low": 3.0, "medium": 6.0, "high": 9.0}[finding.confidence], source=f"correlator:{finding.id}.confidence", weight=WEIGHTS["correlation_confidence"], included=True),
    ]

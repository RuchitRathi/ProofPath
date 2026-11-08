"""Retesting and change comparison diff engine for VAPT workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from proofpath.correlator import _dedup_key
from proofpath.schemas import Finding


@dataclass(frozen=True)
class FindingDelta:
    finding_id: str
    title: str
    asset_ip: str
    port: int
    protocol: str
    severity: str
    status: str
    change_type: str  # "new", "persisting", "remediated"
    note: str = ""


@dataclass(frozen=True)
class AssessmentDiff:
    new_findings: list[Finding] = field(default_factory=list)
    persisting_findings: list[tuple[Finding, Finding]] = field(default_factory=list)  # (baseline, current)
    remediated_findings: list[Finding] = field(default_factory=list)

    @property
    def total_new(self) -> int:
        return len(self.new_findings)

    @property
    def total_persisting(self) -> int:
        return len(self.persisting_findings)

    @property
    def total_remediated(self) -> int:
        return len(self.remediated_findings)

    def summary(self) -> dict[str, int]:
        return {
            "new": self.total_new,
            "persisting": self.total_persisting,
            "remediated": self.total_remediated,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "new": [f.model_dump(mode="json") for f in self.new_findings],
            "persisting": [
                {
                    "baseline": base.model_dump(mode="json"),
                    "current": curr.model_dump(mode="json"),
                }
                for base, curr in self.persisting_findings
            ],
            "remediated": [f.model_dump(mode="json") for f in self.remediated_findings],
        }


def compare_assessments(
    baseline_findings: list[Finding],
    current_findings: list[Finding],
) -> AssessmentDiff:
    """Compare a previous baseline assessment against current findings."""
    baseline_map = {_dedup_key(f): f for f in baseline_findings}
    current_map = {_dedup_key(f): f for f in current_findings}

    new_list: list[Finding] = []
    persisting_list: list[tuple[Finding, Finding]] = []
    remediated_list: list[Finding] = []

    # Check findings in current run
    for key, curr_f in current_map.items():
        if key not in baseline_map:
            new_list.append(curr_f)
        else:
            base_f = baseline_map[key]
            if curr_f.status == "refuted":
                remediated_list.append(base_f)
            else:
                persisting_list.append((base_f, curr_f))

    # Check baseline findings missing from current run
    for key, base_f in baseline_map.items():
        if key not in current_map:
            remediated_list.append(base_f)

    return AssessmentDiff(
        new_findings=new_list,
        persisting_findings=persisting_list,
        remediated_findings=remediated_list,
    )


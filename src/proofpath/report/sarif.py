"""SARIF v2.1.0 exporter for industry-standard vulnerability reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from proofpath.schemas import Finding

_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "not_provided": "none",
}


def export_sarif(
    findings: list[Finding],
    output_path: str | Path | None = None,
    *,
    tool_name: str = "ProofPath",
    tool_version: str = "0.1.0",
) -> dict[str, Any]:
    """Generate an OASIS SARIF v2.1.0 JSON document from correlated findings."""
    rules_dict: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = finding.cves[0] if finding.cves else (finding.cwes[0] if finding.cwes else finding.title[:40].replace(" ", "-"))
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.observed[:500]},
                "defaultConfiguration": {
                    "level": _LEVEL_MAP.get(finding.severity, "warning")
                },
                "properties": {
                    "severity": finding.severity,
                    "cvss": finding.cvss,
                    "cves": finding.cves,
                    "cwes": finding.cwes,
                    "standards_mapped_to": finding.mapped_to,
                },
            }

        rule_index = list(rules_dict.keys()).index(rule_id)
        evidence_excerpts = [f"{ref.evidence_id}: {ref.excerpt}" for ref in finding.evidence]

        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": _LEVEL_MAP.get(finding.severity, "warning"),
            "message": {
                "text": f"{finding.title} on {finding.asset.ip}:{finding.port}/{finding.protocol}. {finding.observed}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"{finding.protocol}://{finding.asset.ip}:{finding.port}/",
                        },
                        "region": {
                            "snippet": {"text": "; ".join(evidence_excerpts)[:300]}
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": finding.service or f"port-{finding.port}",
                            "kind": "service",
                        }
                    ],
                }
            ],
            "properties": {
                "finding_id": finding.id,
                "asset_ip": finding.asset.ip,
                "port": finding.port,
                "protocol": finding.protocol,
                "source_tools": finding.source_tools,
                "evidence_ids": [ref.evidence_id for ref in finding.evidence],
                "confidence": finding.confidence,
                "status": finding.status,
                "validation_status": finding.validation_status,
                "cvss": finding.cvss,
                "cvss_vector": finding.cvss_vector,
            },
        })

    sarif_doc: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/proofpath/proofpath",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    if output_path is not None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    return sarif_doc


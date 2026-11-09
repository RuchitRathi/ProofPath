"""Grounded question answering over the current assessment findings.

Every concrete claim in an answer must cite an evidence ID present in the
findings, and the cited bytes must still hash-match in the ledger. A model
answer that fails either check is rejected and replaced with a deterministic,
evidence-only answer. This mirrors the proposer's "model output is verified,
never trusted" contract.
"""

from __future__ import annotations

import json
import re
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from proofpath.audit import AuditLog
from proofpath.grounding import verify_text
from proofpath.ledger import Ledger
from proofpath.schemas import Finding, ServiceObservation

_EVIDENCE_ID = re.compile(r"\bEV-\d{4,}\b")
_SEVERITIES = ("critical", "high", "medium", "low", "info", "not_provided")
_SEV_RANK = {severity: index for index, severity in enumerate(_SEVERITIES)}
_MAX_CONTEXT_BYTES = 16_000
_MAX_FINDINGS = 12
_COMPLIANCE_WORDS = re.compile(r"\b(?:compliant|compliance|certified|certification|passes|accredited)\b", re.IGNORECASE)


class ModelClient(Protocol):
    def complete(self, messages: list[dict[str, str]], schema: dict) -> str: ...


class ReportAnswer(BaseModel):
    """One grounded answer with the evidence it relies on."""

    model_config = ConfigDict(extra="forbid")

    question: str
    answer: str
    cited_evidence_ids: list[str] = Field(default_factory=list)
    model_used: bool = False
    grounded: bool = True
    critique: list[str] = Field(default_factory=list)


def _select_findings(question: str, findings: list[Finding], limit: int = _MAX_FINDINGS) -> list[Finding]:
    """Rank findings by keyword relevance to the question, breaking ties by severity."""
    lowered = question.casefold()
    tokens = {token for token in re.split(r"[^a-z0-9.:-]+", lowered) if len(token) >= 3}
    severity_hits = {severity for severity in _SEVERITIES if severity in lowered}
    scored: list[tuple[int, Finding]] = []
    for finding in findings:
        haystack = " ".join([
            finding.id, finding.title, finding.asset.ip, finding.severity,
            finding.service or "", *finding.cves, *finding.cwes, *finding.source_tools, *finding.mapped_to,
        ]).casefold()
        score = sum(2 for token in tokens if token in haystack)
        if finding.severity in severity_hits:
            score += 3
        scored.append((score, finding))
    scored.sort(key=lambda item: (-item[0], _SEV_RANK.get(item[1].severity, 9), item[1].id))
    return [finding for _score, finding in scored[:limit]]


def build_context(findings: list[Finding]) -> str:
    """Bounded, escaped JSON view of the selected findings handed to the model."""
    rows = [
        {
            "id": finding.id,
            "title": finding.title,
            "asset": finding.asset.ip,
            "port": finding.port,
            "service": finding.service or "",
            "severity": finding.severity,
            "cvss": finding.cvss,
            "cves": finding.cves,
            "cwes": finding.cwes,
            "status": finding.status,
            "confidence": finding.confidence,
            "source_tools": finding.source_tools,
            "observed": finding.observed[:200],
            "mapped_to": finding.mapped_to,
            "evidence_ids": [ref.evidence_id for ref in finding.evidence],
        }
        for finding in findings
    ]
    text = json.dumps({"findings": rows}, ensure_ascii=True, separators=(",", ":"))
    if len(text.encode("utf-8")) > _MAX_CONTEXT_BYTES:
        text = text.encode("utf-8")[:_MAX_CONTEXT_BYTES].decode("utf-8", "ignore")
    return text


def _deterministic_answer(findings: list[Finding]) -> tuple[str, list[str]]:
    """Compose an answer directly from finding fields; every line cites its evidence."""
    if not findings:
        return ("No findings are recorded yet. Run a scan or import a tool report, then ask again.", [])
    counts = {severity: sum(1 for finding in findings if finding.severity == severity) for severity in _SEVERITIES}
    summary = ", ".join(f"{count} {severity}" for severity, count in counts.items() if count)
    ordered = sorted(findings, key=lambda finding: (_SEV_RANK.get(finding.severity, 9), finding.id))
    lines = [f"The assessment holds {len(findings)} correlated finding(s): {summary}."]
    for finding in ordered[:3]:
        cited = ", ".join(ref.evidence_id for ref in finding.evidence[:2]) or "no evidence refs"
        lines.append(f"- [{finding.severity.upper()}] {finding.id} {finding.title} on {finding.asset.ip}:{finding.port} (evidence {cited}).")
    cited_ids = list(dict.fromkeys(ref.evidence_id for finding in ordered[:3] for ref in finding.evidence))
    return "\n".join(lines), cited_ids


def _model_answer(question: str, findings: list[Finding], client: ModelClient) -> tuple[str, list[str]]:
    system = (
        "You are the ProofPath report Q&A. Answer only from the provided findings JSON. "
        "Never invent CVEs, CWEs, IP addresses, ports, products, versions, or evidence IDs. "
        "Cite the evidence IDs you rely on. If the data does not support an answer, say so plainly."
    )
    user = (
        f"Question: {question}\n"
        "Ground every concrete claim in the findings JSON and cite its evidence IDs. "
        "Return a JSON object with an 'answer' string and an 'evidence_ids' array.\n"
        "FINDINGS_JSON:\n" + build_context(findings)
    )
    schema = {
        "type": "object",
        "properties": {
            "answer": {"type": "string"},
            "evidence_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["answer", "evidence_ids"],
        "additionalProperties": False,
    }
    raw = client.complete(
        [{"role": "system", "content": system}, {"role": "user", "content": user}], schema
    )
    parsed = json.loads(raw)
    answer = str(parsed.get("answer", "")).strip()
    cited = [str(item) for item in parsed.get("evidence_ids", [])]
    return answer, cited


def critique_answer(
    answer: str,
    cited: list[str],
    allowed_evidence: set[str],
    findings: list[Finding],
    observations: list[ServiceObservation],
) -> list[str]:
    """Deterministic self-critique: flag uncited claims, unknown IDs, and provenance conflicts."""
    issues: list[str] = []
    cited_in_text = set(_EVIDENCE_ID.findall(answer))
    if findings and not cited_in_text:
        issues.append("answer cites no evidence IDs")
    unknown = cited_in_text - allowed_evidence
    if unknown:
        issues.append("answer cites evidence absent from the findings: " + ", ".join(sorted(unknown)))
    if cited:
        uncited = set(cited) - allowed_evidence
        if uncited:
            issues.append("declared evidence IDs are absent from the findings: " + ", ".join(sorted(uncited)))
    if _COMPLIANCE_WORDS.search(answer):
        issues.append("answer uses compliance/certification wording that is not supported by the evidence")
    lowered = answer.casefold()
    has_live = any(observation.source_mode == "live" for observation in observations)
    if not has_live and re.search(r"\blive\b|\bcurrently open\b", lowered):
        issues.append("answer describes live exposure but only imported evidence is present")
    refuted = {finding.id for finding in findings if finding.status in {"refuted", "false_positive_candidate"}}
    for finding_id in refuted:
        if finding_id.casefold() in lowered and re.search(r"\bconfirmed\b", lowered):
            issues.append(f"answer calls {finding_id} confirmed but its status is not confirmed")
    return issues


def answer_report_question(
    question: str,
    findings: list[Finding],
    observations: list[ServiceObservation],
    ledger: Ledger,
    audit: AuditLog,
    *,
    model_client: ModelClient | None = None,
    actor: str = "report-qa",
) -> ReportAnswer:
    """Answer a question about the report, refusing any uncited or unverifiable claim."""
    selected = _select_findings(question, findings)
    allowed = {ref.evidence_id for finding in selected for ref in finding.evidence}

    answer = ""
    cited: list[str] = []
    model_used = False
    if model_client is not None and selected:
        try:
            answer, cited = _model_answer(question, selected, model_client)
            if not answer.strip():
                raise ValueError("model returned an empty answer")
            if not set(cited).issubset(allowed):
                raise ValueError("model cited evidence IDs not present in the findings")
            result = verify_text(answer, cited, ledger)
            if not result.accepted:
                raise ValueError("grounding failed: " + "; ".join(result.violations))
            model_used = True
        except Exception as exc:
            audit.append("qa_model_rejected", actor, {"question": question[:200], "reason": str(exc)[:300]})
            answer, cited = _deterministic_answer(selected)
    else:
        answer, cited = _deterministic_answer(selected)

    issues = critique_answer(answer, cited, allowed, selected, observations)
    if issues and model_used:
        audit.append("qa_critique_downgrade", actor, {"issues": issues, "question": question[:200]})
        answer, cited = _deterministic_answer(selected)
        model_used = False
        issues = critique_answer(answer, cited, allowed, selected, observations)

    audit.append(
        "qa_answered",
        actor,
        {"question": question[:200], "model_used": model_used, "cited": cited, "grounded": not issues},
    )
    return ReportAnswer(
        question=question,
        answer=answer,
        cited_evidence_ids=cited,
        model_used=model_used,
        grounded=not issues,
        critique=issues,
    )

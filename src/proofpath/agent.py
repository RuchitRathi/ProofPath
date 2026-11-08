"""Agentic VAPT orchestrator — autonomous multi-step security assessment.

The agent uses the local Qwen model (via Ollama) to reason about the
current assessment state, select the next tool to run, and iteratively
build a complete vulnerability picture. Every tool invocation goes through
``scope_guard.check(action)`` (Hard Rule #1). The agent selects from
typed candidates only (Hard Rule #3). All steps are hash-chain audited
(Hard Rule #7).

The agent implements a ReAct-style loop:
  1. Observe  — gather current service observations and findings
  2. Think    — ask Qwen to select the best next step from rule-generated
               candidates, with evidence-backed reasoning
  3. Act      — execute the selected action through the scope guard
  4. Reflect  — evaluate results, update state, decide whether to continue

The agent stops when:
  - No more candidates remain (full coverage achieved)
  - A configured step limit is reached
  - The human analyst intervenes
  - A critical error occurs
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from proofpath.adapters.base import ToolResult, execute_action
from proofpath.audit import AuditLog
from proofpath.correlator import correlate_findings
from proofpath.ledger import Ledger
from proofpath.normalizer import map_standards
from proofpath.proposer import (
    ModelClient,
    OllamaClient,
    OllamaConfig,
    PlannerCandidate,
    ProposedAction,
    RulePlanner,
    build_untrusted_summary,
    executed_fingerprints,
    propose_and_gate,
)
from proofpath.risk import rank_findings
from proofpath.schemas import Action, ActionName, Finding, ServiceObservation
from proofpath.scope_guard import ScopeGuard
from proofpath.threat_intel import PublicThreatIntel


# ---------------------------------------------------------------------------
# Agent step models
# ---------------------------------------------------------------------------

class StepType(str, Enum):
    """Classification of each agent step."""
    OBSERVE = "observe"
    THINK = "think"
    ACT = "act"
    REFLECT = "reflect"
    IMPORT_REQUEST = "import_request"
    COMPLETE = "complete"
    ERROR = "error"


class AgentStep(BaseModel):
    """One atomic step in the agent's execution trace."""
    model_config = ConfigDict(extra="forbid")

    step_number: int
    step_type: StepType
    timestamp: str
    action_name: str | None = None
    target: str | None = None
    ports: list[int] = Field(default_factory=list)
    candidate_id: str | None = None
    decision_allowed: bool | None = None
    decision_reason: str | None = None
    evidence_id: str | None = None
    tool_status: str | None = None
    reasoning: str = ""
    findings_added: int = 0
    observations_added: int = 0
    duration_ms: float = 0.0


class AgentPlan(BaseModel):
    """The agent's assessment plan — an ordered list of intended steps."""
    model_config = ConfigDict(extra="forbid")

    engagement_id: str
    targets: list[str] = Field(default_factory=list)
    planned_actions: list[str] = Field(default_factory=list)
    reasoning: str = ""
    created_at: str = ""


class ImportRequest(BaseModel):
    """Request for the analyst to supply an external tool report."""
    model_config = ConfigDict(extra="forbid")

    tool: str
    action_name: str
    target: str
    ports: list[int]
    reason: str
    expected_result: str
    candidate_id: str


class AgentResult(BaseModel):
    """Final result of an agent run."""
    model_config = ConfigDict(extra="forbid")

    run_id: str
    engagement_id: str
    status: str  # "complete", "paused_for_imports", "step_limit", "error"
    steps: list[AgentStep] = Field(default_factory=list)
    plan: AgentPlan | None = None
    total_observations: int = 0
    total_findings: int = 0
    total_candidates_evaluated: int = 0
    import_requests: list[ImportRequest] = Field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None


# ---------------------------------------------------------------------------
# Tool wrappers — each goes through scope_guard.check
# ---------------------------------------------------------------------------

@dataclass
class AgentToolbox:
    """Typed tool wrappers that enforce scope guard on every call."""

    guard: ScopeGuard
    audit: AuditLog
    ledger: Ledger
    adapters: dict[ActionName, Any]

    def execute(self, action: Action) -> ToolResult:
        """Execute an action through the scope guard choke point."""
        return execute_action(action, self.guard, self.audit, self.ledger, self.adapters)


# ---------------------------------------------------------------------------
# Agent configuration
# ---------------------------------------------------------------------------

class AgentConfig(BaseModel):
    """Configuration for the agentic orchestrator."""
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    max_steps: int = Field(default=20, ge=1, le=100)
    auto_execute_nmap: bool = True
    pause_for_imports: bool = True
    model_client: Any = None  # ModelClient | None
    public_intel: PublicThreatIntel | None = None
    criticality: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# ReAct agent
# ---------------------------------------------------------------------------

class VAPTAgent:
    """Autonomous VAPT assessment agent with ReAct reasoning loop.

    The agent operates within strict security boundaries:
    - Every tool call passes through ``scope_guard.check(action)``
    - Only typed ``ActionName`` candidates are considered
    - Tool output is untrusted data — stored and displayed, never interpreted
      as instructions
    - All steps are hash-chain audited
    - Import-only tools pause and request analyst-supplied files
    """

    def __init__(
        self,
        guard: ScopeGuard,
        audit: AuditLog,
        ledger: Ledger,
        adapters: dict[ActionName, Any],
        config: AgentConfig | None = None,
    ) -> None:
        self.guard = guard
        self.audit = audit
        self.ledger = ledger
        self.toolbox = AgentToolbox(guard, audit, ledger, adapters)
        self.config = config or AgentConfig()
        self.planner = RulePlanner()

        self._observations: list[ServiceObservation] = []
        self._raw_findings: list[Finding] = []
        self._steps: list[AgentStep] = []
        self._import_requests: list[ImportRequest] = []
        self._executed: set[tuple[str, str, tuple[int, ...]]] = set()
        self._run_id = uuid.uuid4().hex[:16]
        self._step_counter = 0
        self._total_candidates = 0

    # --- Public API ---

    def load_state(
        self,
        observations: list[ServiceObservation] | None = None,
        findings: list[Finding] | None = None,
    ) -> None:
        """Load existing assessment state for continuation."""
        if observations:
            self._observations.extend(observations)
        if findings:
            self._raw_findings.extend(findings)
        self._executed = executed_fingerprints(self.audit)

    def run(self) -> AgentResult:
        """Execute the full agentic assessment loop.

        Returns an AgentResult with all steps, findings, and any
        pending import requests for the analyst.
        """
        start_time = time.monotonic()
        self.audit.append(
            "agent_run_started",
            "vapt-agent",
            {
                "run_id": self._run_id,
                "engagement_id": self.guard.policy.engagement,
                "max_steps": self.config.max_steps,
                "auto_execute_nmap": self.config.auto_execute_nmap,
                "pause_for_imports": self.config.pause_for_imports,
                "initial_observations": len(self._observations),
                "initial_findings": len(self._raw_findings),
            },
        )

        status = "complete"
        error_msg: str | None = None

        try:
            # Phase 1: Generate assessment plan
            plan = self._generate_plan()

            # Phase 2: ReAct loop
            while self._step_counter < self.config.max_steps:
                # Observe
                observe_step = self._observe()
                self._steps.append(observe_step)

                # Think — evaluate candidates
                candidates, skipped = self._think()
                if not candidates:
                    self._steps.append(self._make_step(
                        StepType.COMPLETE,
                        reasoning="No more actionable candidates remain. Full coverage achieved for current observations.",
                    ))
                    break

                self._total_candidates += len(candidates)

                # Act — select and execute next step
                act_step = self._act(candidates)
                self._steps.append(act_step)

                # Reflect — evaluate results
                reflect_step = self._reflect(act_step)
                self._steps.append(reflect_step)

            else:
                status = "step_limit"
                self._steps.append(self._make_step(
                    StepType.COMPLETE,
                    reasoning=f"Reached the configured step limit of {self.config.max_steps}.",
                ))

            if self._import_requests:
                status = "paused_for_imports"

        except Exception as exc:
            status = "error"
            error_msg = f"{type(exc).__name__}: {exc}"[:500]
            self._steps.append(self._make_step(
                StepType.ERROR,
                reasoning=f"Agent error: {error_msg}",
            ))

        duration = time.monotonic() - start_time
        merged = correlate_findings(self._raw_findings, self._observations)

        result = AgentResult(
            run_id=self._run_id,
            engagement_id=self.guard.policy.engagement,
            status=status,
            steps=self._steps,
            plan=plan,
            total_observations=len(self._observations),
            total_findings=len(merged),
            total_candidates_evaluated=self._total_candidates,
            import_requests=self._import_requests,
            duration_seconds=round(duration, 3),
            error=error_msg,
        )

        self.audit.append(
            "agent_run_completed",
            "vapt-agent",
            {
                "run_id": self._run_id,
                "status": status,
                "steps_taken": len(self._steps),
                "total_observations": result.total_observations,
                "total_findings": result.total_findings,
                "total_candidates_evaluated": self._total_candidates,
                "import_requests_pending": len(self._import_requests),
                "duration_seconds": result.duration_seconds,
                "error": error_msg,
            },
        )

        return result

    def supply_import(
        self,
        action_name: ActionName,
        target: str,
        ports: list[int],
        import_func: Any,
        raw_data: bytes,
    ) -> tuple[list[Finding], str]:
        """Supply an analyst-provided import file and process it.

        Returns the resulting findings and a status message.
        """
        result = import_func(raw_data, self.guard, self.audit, self.ledger)
        self._raw_findings.extend(result.findings)
        self._import_requests = [
            req for req in self._import_requests
            if not (req.action_name == action_name.value and req.target == target)
        ]
        return result.findings, f"Imported {result.parsed_items} items via {action_name.value}"

    # --- Internal phases ---

    def _generate_plan(self) -> AgentPlan:
        """Ask Qwen to generate an assessment plan overview."""
        targets = sorted({obs.ip for obs in self._observations})
        engagement = self.guard.policy.engagement
        enabled = [a.value for a in self.guard.policy.enabled_actions]

        reasoning = (
            f"Assessment plan for engagement '{engagement}'. "
            f"Targets observed: {', '.join(targets) or 'none yet — reconnaissance needed'}. "
            f"Enabled tools: {', '.join(enabled)}. "
            f"Strategy: systematic reconnaissance → vulnerability import → correlation → risk ranking."
        )

        # Use Qwen for richer planning if available
        if self.config.model_client is not None:
            try:
                schema = {
                    "type": "object",
                    "properties": {
                        "strategy": {"type": "string"},
                        "priority_order": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["strategy", "priority_order"],
                    "additionalProperties": False,
                }
                messages = [
                    {"role": "system", "content": (
                        "You are a VAPT assessment planner. Given the engagement context, "
                        "produce a concise strategy and priority order for the assessment tools. "
                        "Never invent targets, vulnerabilities, or evidence. Return JSON only."
                    )},
                    {"role": "user", "content": (
                        f"Engagement: {engagement}. Enabled actions: {', '.join(enabled)}. "
                        f"Known targets: {', '.join(targets) or 'none yet'}. "
                        f"Current observations: {len(self._observations)}. "
                        f"Current findings: {len(self._raw_findings)}. "
                        f"Generate a concise VAPT assessment strategy."
                    )},
                ]
                raw = self.config.model_client.complete(messages, schema)
                parsed = json.loads(raw)
                ai_strategy = parsed.get("strategy", "")
                ai_priorities = parsed.get("priority_order", [])
                if ai_strategy:
                    reasoning = f"AI Strategy: {ai_strategy}"
                if ai_priorities:
                    enabled = [p for p in ai_priorities if isinstance(p, str)][:10]
            except Exception:
                pass  # Fall back to deterministic plan

        plan = AgentPlan(
            engagement_id=engagement,
            targets=targets,
            planned_actions=enabled,
            reasoning=reasoning,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        self.audit.append(
            "agent_plan_generated",
            "vapt-agent",
            {
                "run_id": self._run_id,
                "targets": plan.targets,
                "planned_actions": plan.planned_actions,
                "reasoning": plan.reasoning[:500],
            },
        )

        return plan

    def _observe(self) -> AgentStep:
        """Observe the current state of the assessment."""
        start = time.monotonic()
        merged = correlate_findings(self._raw_findings, self._observations)
        ranked = rank_findings(
            merged,
            self._observations,
            self.config.criticality,
            self.config.public_intel,
        ) if merged else []

        obs_count = len(self._observations)
        find_count = len(merged)
        critical = sum(1 for f in merged if f.severity == "critical")
        high = sum(1 for f in merged if f.severity == "high")

        reasoning = (
            f"Current state: {obs_count} service observations, {find_count} correlated findings "
            f"(critical: {critical}, high: {high}). "
            f"Executed action fingerprints: {len(self._executed)}. "
            f"Pending import requests: {len(self._import_requests)}."
        )

        return self._make_step(
            StepType.OBSERVE,
            reasoning=reasoning,
            duration_ms=round((time.monotonic() - start) * 1000, 1),
        )

    def _think(self) -> tuple[list[PlannerCandidate], list[tuple[PlannerCandidate, str]]]:
        """Generate and evaluate candidates for the next action."""
        merged = correlate_findings(self._raw_findings, self._observations)
        candidates, skipped = self.planner.evaluate(
            self._observations,
            self.guard.policy.engagement,
            executed=self._executed,
            findings=merged,
            criticality=self.config.criticality,
            enabled_actions=set(self.guard.policy.enabled_actions),
            public_intel=self.config.public_intel,
        )
        return candidates, skipped

    def _act(self, candidates: list[PlannerCandidate]) -> AgentStep:
        """Select the best candidate and execute or request import."""
        start = time.monotonic()
        merged = correlate_findings(self._raw_findings, self._observations)

        # Use propose_and_gate to select best candidate (uses Qwen if available)
        proposal, result, used_fallback = propose_and_gate(
            self._observations,
            candidates,
            self.config.model_client,
            self.guard,
            self.audit,
            self.ledger,
            findings=merged,
            actor="vapt-agent",
        )

        if proposal is None:
            return self._make_step(
                StepType.ACT,
                reasoning="No proposal could be generated from candidates.",
                duration_ms=round((time.monotonic() - start) * 1000, 1),
            )

        action = proposal.action
        action_name = action.name

        # Import-only actions: request analyst file supply
        import_actions = {
            ActionName.IMPORT_BURP,
            ActionName.IMPORT_NESSUS,
            ActionName.IMPORT_OPENVAS,
            ActionName.IMPORT_NIKTO,
            ActionName.IMPORT_ZAP,
            ActionName.IMPORT_METASPLOIT,
        }

        if action_name in import_actions and self.config.pause_for_imports:
            candidate = next(
                (c for c in candidates if c.candidate_id == proposal.candidate_id),
                candidates[0],
            )
            tool_name = {
                ActionName.IMPORT_BURP: "Burp Suite",
                ActionName.IMPORT_NESSUS: "Nessus",
                ActionName.IMPORT_OPENVAS: "OpenVAS / Greenbone",
                ActionName.IMPORT_NIKTO: "Nikto",
                ActionName.IMPORT_ZAP: "OWASP ZAP",
                ActionName.IMPORT_METASPLOIT: "Metasploit",
            }.get(action_name, action_name.value)

            # Don't duplicate import requests
            existing = {(r.action_name, r.target) for r in self._import_requests}
            if (action_name.value, action.target) not in existing:
                self._import_requests.append(ImportRequest(
                    tool=tool_name,
                    action_name=action_name.value,
                    target=action.target,
                    ports=action.ports,
                    reason=candidate.planner_reason,
                    expected_result=candidate.expected_result,
                    candidate_id=proposal.candidate_id,
                ))

            # Mark as executed to avoid re-proposing
            from proofpath.proposer import action_fingerprint
            self._executed.add(action_fingerprint(action))

            return self._make_step(
                StepType.IMPORT_REQUEST,
                action_name=action_name.value,
                target=action.target,
                ports=action.ports,
                candidate_id=proposal.candidate_id,
                reasoning=(
                    f"Import requested: {tool_name} report for {action.target}. "
                    f"Reason: {candidate.planner_reason}. "
                    f"The agent needs an analyst-supplied {tool_name} export to continue this branch."
                ),
                duration_ms=round((time.monotonic() - start) * 1000, 1),
            )

        # Live scan actions (e.g., nmap_scan) — execute through scope guard
        if action_name == ActionName.NMAP_SCAN and self.config.auto_execute_nmap:
            analyst_action = action.model_copy(update={"requested_by": "vapt-agent"})
            exec_result = self.toolbox.execute(analyst_action)

            # Update state
            if exec_result.services:
                self._observations.extend(exec_result.services)

            from proofpath.proposer import action_fingerprint
            self._executed.add(action_fingerprint(action))

            return self._make_step(
                StepType.ACT,
                action_name=action_name.value,
                target=action.target,
                ports=action.ports,
                candidate_id=proposal.candidate_id,
                decision_allowed=exec_result.decision.allowed,
                decision_reason=exec_result.decision.reason,
                evidence_id=exec_result.evidence_id,
                tool_status=exec_result.status,
                reasoning=(
                    f"Executed {action_name.value} on {action.target}:{','.join(str(p) for p in action.ports)}. "
                    f"Status: {exec_result.status}. "
                    f"New service observations: {len(exec_result.services or [])}."
                ),
                observations_added=len(exec_result.services or []),
                duration_ms=round((time.monotonic() - start) * 1000, 1),
            )

        # Queued but not auto-executed
        from proofpath.proposer import action_fingerprint
        self._executed.add(action_fingerprint(action))

        return self._make_step(
            StepType.ACT,
            action_name=action_name.value,
            target=action.target,
            ports=action.ports,
            candidate_id=proposal.candidate_id,
            reasoning=(
                f"Action {action_name.value} queued for {action.target}. "
                f"Auto-execution not enabled for this action type."
            ),
            duration_ms=round((time.monotonic() - start) * 1000, 1),
        )

    def _reflect(self, act_step: AgentStep) -> AgentStep:
        """Reflect on the last action's results and decide next direction."""
        start = time.monotonic()
        merged = correlate_findings(self._raw_findings, self._observations)

        reflection_parts = [
            f"After step {act_step.step_number}: ",
            f"{len(self._observations)} total observations, ",
            f"{len(merged)} correlated findings. ",
        ]

        if act_step.tool_status == "ok" and act_step.observations_added > 0:
            reflection_parts.append(
                f"Scan successful: {act_step.observations_added} new observations. "
                "Will evaluate for follow-up vulnerability imports."
            )
        elif act_step.step_type == StepType.IMPORT_REQUEST:
            reflection_parts.append(
                f"Awaiting analyst-supplied {act_step.action_name} report. "
                "Continuing with other available candidates."
            )
        elif act_step.tool_status in {"denied", "error"}:
            reflection_parts.append(
                f"Action was {act_step.tool_status}: {act_step.decision_reason or 'unknown reason'}. "
                "Will skip and try next candidate."
            )
        else:
            reflection_parts.append("Evaluating remaining assessment coverage gaps.")

        # AI-enhanced reflection if model is available
        if self.config.model_client is not None:
            try:
                schema = {
                    "type": "object",
                    "properties": {"assessment": {"type": "string"}},
                    "required": ["assessment"],
                    "additionalProperties": False,
                }
                raw = self.config.model_client.complete(
                    [
                        {"role": "system", "content": (
                            "You are a VAPT agent reflecting on the latest action. "
                            "Summarize what was learned and what to investigate next. "
                            "Never invent evidence, CVEs, or vulnerabilities. One sentence."
                        )},
                        {"role": "user", "content": (
                            f"Last action: {act_step.action_name or 'none'} on {act_step.target or 'none'}. "
                            f"Status: {act_step.tool_status or act_step.step_type.value}. "
                            f"Total observations: {len(self._observations)}. "
                            f"Total findings: {len(merged)}. "
                            f"What should the agent focus on next?"
                        )},
                    ],
                    schema,
                )
                ai_assessment = json.loads(raw).get("assessment", "")
                if ai_assessment:
                    reflection_parts.append(f"AI assessment: {ai_assessment}")
            except Exception:
                pass

        return self._make_step(
            StepType.REFLECT,
            reasoning="".join(reflection_parts),
            duration_ms=round((time.monotonic() - start) * 1000, 1),
        )

    def _make_step(self, step_type: StepType, **kwargs: Any) -> AgentStep:
        """Create a new step with auto-incrementing counter."""
        self._step_counter += 1
        return AgentStep(
            step_number=self._step_counter,
            step_type=step_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            **kwargs,
        )

    # --- State accessors ---

    @property
    def observations(self) -> list[ServiceObservation]:
        return list(self._observations)

    @property
    def findings(self) -> list[Finding]:
        return correlate_findings(self._raw_findings, self._observations)

    @property
    def raw_findings(self) -> list[Finding]:
        return list(self._raw_findings)

    @property
    def import_requests(self) -> list[ImportRequest]:
        return list(self._import_requests)

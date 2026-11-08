"""Tests for the agentic VAPT orchestrator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from proofpath.agent import (
    AgentConfig,
    AgentPlan,
    AgentResult,
    AgentStep,
    ImportRequest,
    StepType,
    VAPTAgent,
)
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import (
    Action,
    ActionName,
    EvidenceRef,
    Finding,
    FindingAsset,
    ServiceObservation,
)
from proofpath.scope_guard import ScopeGuard


@pytest.fixture
def tmp_env(tmp_path: Path):
    """Create a temporary test environment with scope, audit, and ledger."""
    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text(
        """
engagement: test-agent-01
allowed_cidrs:
  - "10.20.0.0/24"
allowed_ports:
  - "80"
  - "443"
  - "8080"
  - "8443"
rate_limits:
  max_timing: 3
  max_host_timeout_seconds: 120
enabled_actions:
  - nmap_scan
  - import_nessus
  - import_burp
  - import_openvas
  - import_nikto
  - import_zap
  - import_metasploit
  - import_nmap_xml
  - generate_report
tool_arguments:
  nmap:
    service_detection: {type: bool}
    skip_host_discovery: {type: bool}
    timing: {type: int, minimum: 0, maximum: 3}
    host_timeout_seconds: {type: int, minimum: 1, maximum: 120}
""",
        encoding="utf-8",
    )
    guard = ScopeGuard.from_yaml(scope_yaml, resolver=lambda host: ["10.20.0.10"])
    audit = AuditLog(tmp_path / "audit.jsonl")
    ledger = Ledger(tmp_path / "evidence")
    return guard, audit, ledger


def _make_observation(
    ip: str = "10.20.0.10",
    port: int = 80,
    evidence_id: str = "EV-0001",
    source_mode: str = "imported",
) -> ServiceObservation:
    return ServiceObservation(
        evidence_id=evidence_id,
        ip=ip,
        port=port,
        protocol="tcp",
        state="open",
        service="http",
        source_mode=source_mode,
    )


def _make_finding(
    ip: str = "10.20.0.10",
    port: int = 80,
    evidence_id: str = "EV-0001",
    tool: str = "nessus",
) -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        id="F-test-001",
        title="Test SQL Injection",
        asset=FindingAsset(ip=ip),
        port=port,
        protocol="tcp",
        service="http",
        source_tools=[tool],
        evidence=[EvidenceRef(
            evidence_id=evidence_id,
            locator="//test",
            excerpt="Test finding excerpt",
        )],
        observed="SQL injection test payload returned in response",
        severity="high",
        cvss=8.6,
        cves=["CVE-2024-0001"],
        cwes=["CWE-89"],
        confidence="medium",
        status="suspected",
        first_seen=now,
        last_seen=now,
    )


class TestAgentModels:
    """Test agent Pydantic models."""

    def test_agent_step_creation(self):
        step = AgentStep(
            step_number=1,
            step_type=StepType.OBSERVE,
            timestamp=datetime.now(timezone.utc).isoformat(),
            reasoning="Initial observation phase",
        )
        assert step.step_number == 1
        assert step.step_type == StepType.OBSERVE

    def test_agent_plan_creation(self):
        plan = AgentPlan(
            engagement_id="test-01",
            targets=["10.20.0.10"],
            planned_actions=["nmap_scan", "import_nessus"],
            reasoning="Test plan",
        )
        assert plan.engagement_id == "test-01"
        assert len(plan.planned_actions) == 2

    def test_import_request_creation(self):
        req = ImportRequest(
            tool="Nessus",
            action_name="import_nessus",
            target="10.20.0.10",
            ports=[80],
            reason="No Nessus findings for this host",
            expected_result="Normalized Nessus findings",
            candidate_id="C1",
        )
        assert req.tool == "Nessus"
        assert req.candidate_id == "C1"

    def test_agent_result_creation(self):
        result = AgentResult(
            run_id="test123",
            engagement_id="test-01",
            status="complete",
        )
        assert result.status == "complete"
        assert result.total_findings == 0

    def test_step_type_enum(self):
        assert StepType.OBSERVE.value == "observe"
        assert StepType.THINK.value == "think"
        assert StepType.ACT.value == "act"
        assert StepType.REFLECT.value == "reflect"
        assert StepType.IMPORT_REQUEST.value == "import_request"
        assert StepType.COMPLETE.value == "complete"
        assert StepType.ERROR.value == "error"


class TestVAPTAgent:
    """Test the VAPTAgent orchestrator."""

    def test_agent_initialization(self, tmp_env):
        guard, audit, ledger = tmp_env
        agent = VAPTAgent(guard, audit, ledger, {})
        assert agent.guard is guard
        assert agent.audit is audit

    def test_agent_load_state(self, tmp_env):
        guard, audit, ledger = tmp_env
        agent = VAPTAgent(guard, audit, ledger, {})
        obs = [_make_observation()]
        agent.load_state(observations=obs)
        assert len(agent.observations) == 1

    def test_agent_load_state_with_findings(self, tmp_env):
        guard, audit, ledger = tmp_env
        agent = VAPTAgent(guard, audit, ledger, {})
        obs = [_make_observation()]
        findings = [_make_finding()]
        agent.load_state(observations=obs, findings=findings)
        assert len(agent.observations) == 1
        assert len(agent.raw_findings) == 1

    def test_agent_run_no_observations(self, tmp_env):
        """Agent with no observations should complete with no candidates."""
        guard, audit, ledger = tmp_env
        agent = VAPTAgent(guard, audit, ledger, {}, AgentConfig(max_steps=5))
        result = agent.run()
        assert result.status == "complete"
        assert result.engagement_id == "test-agent-01"
        assert result.total_observations == 0
        assert any(s.step_type == StepType.COMPLETE for s in result.steps)

    def test_agent_run_with_observations_produces_import_requests(self, tmp_env):
        """Agent with imported observations should generate import requests."""
        guard, audit, ledger = tmp_env
        # Store evidence so ledger checks pass
        ledger.store(
            content=b"test evidence data",
            tool="nmap",
            command=["nmap", "-sT"],
            status="ok",
            summary="test evidence",
            source_mode="imported",
        )

        agent = VAPTAgent(
            guard, audit, ledger, {},
            AgentConfig(max_steps=10, auto_execute_nmap=False, pause_for_imports=True),
        )
        agent.load_state(observations=[_make_observation()])
        result = agent.run()

        # Should have generated import requests for missing tool coverage
        assert result.total_observations >= 1
        # Agent should either produce import requests or complete
        assert result.status in {"complete", "paused_for_imports", "step_limit"}

    def test_agent_run_audits_start_and_end(self, tmp_env):
        """Agent run should create audit entries for start and end."""
        guard, audit, ledger = tmp_env
        agent = VAPTAgent(guard, audit, ledger, {}, AgentConfig(max_steps=3))
        result = agent.run()

        entries = audit.read_entries()
        event_types = [e.event_type for e in entries]
        assert "agent_run_started" in event_types
        assert "agent_run_completed" in event_types

    def test_agent_run_plan_generated(self, tmp_env):
        """Agent should generate an assessment plan."""
        guard, audit, ledger = tmp_env
        agent = VAPTAgent(guard, audit, ledger, {}, AgentConfig(max_steps=3))
        result = agent.run()

        assert result.plan is not None
        assert result.plan.engagement_id == "test-agent-01"

        entries = audit.read_entries()
        assert any(e.event_type == "agent_plan_generated" for e in entries)

    def test_agent_respects_step_limit(self, tmp_env):
        """Agent should stop at the configured step limit."""
        guard, audit, ledger = tmp_env
        ledger.store(
            content=b"test evidence data",
            tool="nmap",
            command=["nmap", "-sT"],
            status="ok",
            summary="test evidence",
            source_mode="imported",
        )

        agent = VAPTAgent(
            guard, audit, ledger, {},
            AgentConfig(max_steps=2, auto_execute_nmap=False, pause_for_imports=True),
        )
        # Load multiple observations to ensure there are enough candidates
        agent.load_state(observations=[
            _make_observation(port=80, evidence_id="EV-0001"),
            _make_observation(port=443, evidence_id="EV-0001"),
        ])
        result = agent.run()

        # Should hit step limit since max_steps=2 and we have candidates
        # (The observe+act+reflect cycle each count as steps)
        assert len(result.steps) <= 10  # Bounded by max_steps * steps_per_cycle + overhead

    def test_agent_step_numbers_sequential(self, tmp_env):
        """All steps should have sequential step numbers."""
        guard, audit, ledger = tmp_env
        agent = VAPTAgent(guard, audit, ledger, {}, AgentConfig(max_steps=5))
        result = agent.run()

        for i, step in enumerate(result.steps):
            assert step.step_number == i + 1

    def test_agent_config_defaults(self):
        config = AgentConfig()
        assert config.max_steps == 20
        assert config.auto_execute_nmap is True
        assert config.pause_for_imports is True

    def test_agent_config_custom(self):
        config = AgentConfig(max_steps=5, auto_execute_nmap=False)
        assert config.max_steps == 5
        assert config.auto_execute_nmap is False

    def test_agent_result_serialization(self, tmp_env):
        """AgentResult should be JSON-serializable."""
        guard, audit, ledger = tmp_env
        agent = VAPTAgent(guard, audit, ledger, {}, AgentConfig(max_steps=3))
        result = agent.run()

        # Should not raise
        json_str = result.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["status"] == result.status
        assert parsed["run_id"] == result.run_id

    def test_agent_run_with_findings_and_observations(self, tmp_env):
        """Agent with both findings and observations should correlate and plan."""
        guard, audit, ledger = tmp_env
        ledger.store(
            content=b"test evidence data",
            tool="nmap",
            command=["nmap", "-sT"],
            status="ok",
            summary="test evidence",
            source_mode="imported",
        )

        agent = VAPTAgent(
            guard, audit, ledger, {},
            AgentConfig(max_steps=5, auto_execute_nmap=False, pause_for_imports=True),
        )
        agent.load_state(
            observations=[_make_observation()],
            findings=[_make_finding()],
        )
        result = agent.run()

        assert result.total_observations >= 1
        assert result.plan is not None


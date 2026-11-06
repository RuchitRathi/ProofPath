"""Scope guard bypasses and policy limits."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from proofpath.schemas import Action, ActionName
from proofpath.scope_guard import ScopeGuard, ScopePolicy
from proofpath.selftest import demo_resolver, run_cases

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "scope.yaml"


def test_shipped_bypass_cases() -> None:
    failed = [f"{name}: {reason}" for name, passed, reason in run_cases(SCOPE) if not passed]
    assert failed == []


def _guard_with(updates: dict) -> ScopeGuard:
    raw = yaml.safe_load(SCOPE.read_text(encoding="utf-8"))
    raw.update(updates)
    return ScopeGuard(ScopePolicy.model_validate(raw), resolver=demo_resolver)


def test_active_validation_stays_blocked_if_enabled_in_yaml() -> None:
    guard = _guard_with({"enabled_actions": ["nmap_scan", "active_validate"]})
    decision = guard.check(
        Action(
            id="act",
            name=ActionName.ACTIVE_VALIDATE,
            target="10.10.1.5",
            ports=[80],
                arguments={"method": "GET", "path": "/", "finding_id": "F-TEST-1"},
            engagement_id="lab-01",
        )
    )
    assert decision.allowed is False
    assert "approval" in decision.reason
    assert guard.verify_decision(decision) is True


def test_forged_allow_fails_verification() -> None:
    guard = ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)
    decision = guard.check(
        Action(id="act", name=ActionName.NMAP_SCAN, target="8.8.8.8", ports=[80], engagement_id="lab-01")
    )
    forged = decision.model_copy(update={"allowed": True, "resolved_ips": ["8.8.8.8"], "ports": [80], "tool": "nmap"})
    assert forged.allowed is True
    assert guard.verify_decision(forged) is False


def test_default_route_is_rejected() -> None:
    raw = yaml.safe_load(SCOPE.read_text(encoding="utf-8"))
    raw["allowed_cidrs"] = ["0.0.0.0/0"]
    with pytest.raises(ValidationError):
        ScopePolicy.model_validate(raw)


def test_unspecified_denied_even_if_listed() -> None:
    guard = _guard_with({"allowed_cidrs": ["0.0.0.0/32", "10.10.0.0/16"]})
    decision = guard.check(
        Action(id="act", name=ActionName.NMAP_SCAN, target="0.0.0.0", ports=[80], engagement_id="lab-01")
    )
    assert decision.allowed is False
    assert "unspecified" in decision.reason


def test_loopback_can_be_enabled_explicitly() -> None:
    guard = _guard_with({"allow_loopback": True, "allowed_cidrs": ["127.0.0.0/8"]})
    decision = guard.check(
        Action(id="act", name=ActionName.NMAP_SCAN, target="127.0.0.1", ports=[80], engagement_id="lab-01")
    )
    assert decision.allowed is True
    assert decision.resolved_ips == ["127.0.0.1"]


def test_boolean_timing_is_rejected() -> None:
    guard = ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)
    decision = guard.check(
        Action(
            id="act",
            name=ActionName.NMAP_SCAN,
            target="10.10.1.5",
            ports=[80],
            arguments={"timing": True},
            engagement_id="lab-01",
        )
    )
    assert decision.allowed is False
    assert "integer" in decision.reason


def test_skip_host_discovery_is_boolean_and_defaults_off() -> None:
    guard = ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)
    action = Action(id="pn-off", name=ActionName.NMAP_SCAN, target="10.10.1.5", ports=[80], engagement_id="lab-01")
    decision = guard.check(action)
    assert decision.allowed and decision.normalized_arguments["skip_host_discovery"] is False
    bad = action.model_copy(update={"arguments": {"skip_host_discovery": "yes"}})
    assert not guard.check(bad).allowed


@pytest.mark.parametrize("target", ["LOCALHOST", "localhost.", "Localhost.localdomain", "::1", "::ffff:127.0.0.1", "127.1", "2130706433", "0x7f000001", "017700000001", "0", "0.0.0.0", "fe80::1%eth0", "10.10.0.0/24", "", "bücher.example"])
def test_hostile_target_variants_are_denied(target: str) -> None:
    guard = ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)
    if target == "":
        with pytest.raises(ValidationError):
            Action(id="bad", name=ActionName.NMAP_SCAN, target=target, ports=[80], engagement_id="lab-01")
        return
    decision = guard.check(Action(id="bad", name=ActionName.NMAP_SCAN, target=target, ports=[80], engagement_id="lab-01"))
    assert decision.allowed is False


@pytest.mark.parametrize("port", [True, 0, -1, 65536, 999999, 80.5])
def test_ports_reject_bool_invalid_and_float_values(port: object) -> None:
    with pytest.raises(ValidationError):
        Action(id="bad", name=ActionName.NMAP_SCAN, target="10.10.1.5", ports=[port], engagement_id="lab-01")


def test_empty_ports_are_denied_and_decision_bound_to_guard() -> None:
    guard = ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)
    action = Action(id="empty", name=ActionName.NMAP_SCAN, target="10.10.1.5", ports=[], engagement_id="lab-01")
    decision = guard.check(action)
    assert not decision.allowed and "ports are required" in decision.reason
    assert ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver).verify_decision(decision) is False


def test_excluded_hostname_ips_are_excluded_and_unresolvable_is_rejected() -> None:
    guard = _guard_with({"excluded_hosts": ["in-scope.lab"]})
    decision = guard.check(Action(id="blocked", name=ActionName.NMAP_SCAN, target="10.10.1.5", ports=[80], engagement_id="lab-01"))
    assert not decision.allowed and "excluded" in decision.reason
    # Resolver used by the test maps only known lab names; an unmapped exclusion is a policy error.
    with pytest.raises(ValueError, match="excluded hostname could not be resolved"):
        _guard_with({"excluded_hosts": ["unresolved.lab"]})


def test_decision_mutation_of_non_allowed_field_invalidates_signature() -> None:
    guard = ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)
    decision = guard.check(Action(id="ok", name=ActionName.NMAP_SCAN, target="10.10.1.5", ports=[80], engagement_id="lab-01"))
    assert decision.allowed
    assert not guard.verify_decision(decision.model_copy(update={"reason": "forged"}))


@pytest.mark.parametrize("target", ["BLOCKED.LAB", "blocked.lab."])
def test_case_and_trailing_dot_excluded_names_are_denied(target: str) -> None:
    guard = _guard_with({"excluded_hosts": ["blocked.lab"]})
    decision = guard.check(Action(id="excluded-name", name=ActionName.NMAP_SCAN, target=target, ports=[80], engagement_id="lab-01"))
    assert not decision.allowed and "excluded" in decision.reason


@pytest.mark.parametrize("value", [True, -1, 10**100, 2.5, float("nan"), "-T4"])
def test_argument_values_reject_bool_negative_huge_float_nan_and_flags(value: object) -> None:
    guard = ScopeGuard.from_yaml(SCOPE, resolver=demo_resolver)
    action = Action(id="bad-arg", name=ActionName.NMAP_SCAN, target="10.10.1.5", ports=[80], arguments={"timing": value}, engagement_id="lab-01")
    assert not guard.check(action).allowed

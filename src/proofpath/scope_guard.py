"""Single choke point for tool authorization.

`ScopeGuard.check` accepts a typed Action and returns a signed decision.
Callers execute a tool only when `allowed` is true and `verify_decision` matches.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import socket
import threading
from pathlib import Path
from typing import Any, Callable
from datetime import datetime

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from proofpath.canonical import canonical_json
from proofpath.schemas import Action, ActionName, ApprovalRequest, GuardDecision

Resolver = Callable[[str], list[str]]

_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_IPV4_ATTEMPT = re.compile(r"^(?:\d{1,3}\.){1,3}\d{1,3}$")
_DECIMAL_IP = re.compile(r"^\d+$")
_HEX_IP = re.compile(r"(?i)^0x[0-9a-f.]+$")
_ARG_NAME = re.compile(r"[A-Za-z0-9_-]{1,32}")
_LOCAL_NAMES = {"localhost", "localhost.localdomain"}

# Active validation cannot run until approval.py records a human approval.
_BLOCKED_UNTIL_APPROVAL = {ActionName.ACTIVE_VALIDATE}

_TOOL_FOR_ACTION = {
    ActionName.NMAP_SCAN: "nmap",
    ActionName.IMPORT_NMAP_XML: "nmap",
    ActionName.WEB_SCAN: "webscan",
    ActionName.NIKTO_SCAN: "nikto",
    ActionName.ZAP_SCAN: "zap",
    ActionName.IMPORT_NESSUS: "nessus",
    ActionName.IMPORT_BURP: "burp",
    ActionName.ACTIVE_VALIDATE: "active_validate",
    ActionName.IMPORT_OPENVAS: "openvas",
    ActionName.IMPORT_NIKTO: "nikto",
    ActionName.IMPORT_ZAP: "zap",
    ActionName.IMPORT_METASPLOIT: "metasploit",
}


class RateLimits(BaseModel):
    """Upper bounds copied into argument checks."""

    model_config = ConfigDict(extra="forbid")

    max_timing: int = Field(ge=0, le=5)
    max_host_timeout_seconds: int = Field(ge=1, le=600)


class ArgSpec(BaseModel):
    """One allowlisted argument. String arguments are not accepted."""

    model_config = ConfigDict(extra="forbid")

    type: str
    minimum: int | None = None
    maximum: int | None = None

    @model_validator(mode="after")
    def bounds_match_type(self) -> ArgSpec:
        if self.type not in {"bool", "int"}:
            raise ValueError("argument type must be bool or int")
        if self.type == "bool" and (self.minimum is not None or self.maximum is not None):
            raise ValueError("boolean arguments do not take bounds")
        if self.type == "int" and (self.minimum is None or self.maximum is None):
            raise ValueError("integer arguments require minimum and maximum")
        return self


class ScopePolicy(BaseModel):
    """The engagement authorization file."""

    model_config = ConfigDict(extra="forbid")

    engagement: str = Field(min_length=1, max_length=64)
    allowed_cidrs: list[str] = Field(min_length=1)
    excluded_cidrs: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)
    allowed_ports: list[str] = Field(min_length=1)
    allow_loopback: bool = False
    allow_all_ips: bool = False
    rate_limits: RateLimits
    enabled_actions: list[ActionName] = Field(default_factory=lambda: [ActionName.NMAP_SCAN])
    allowed_validation_paths: list[str] = Field(default_factory=list)
    tool_arguments: dict[str, dict[str, ArgSpec]]

    @field_validator("allowed_ports", mode="before")
    @classmethod
    def ports_as_text(cls, value: list[Any]) -> list[str]:
        return [str(item) for item in value]

    @model_validator(mode="after")
    def networks_are_bounded(self) -> ScopePolicy:
        for cidr in [*self.allowed_cidrs, *self.excluded_cidrs]:
            _require_bounded_network(cidr)
        expand_ports(self.allowed_ports)
        for path in self.allowed_validation_paths:
            if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or any(char in path for char in "?#\\\r\n"):
                raise ValueError("active validation paths must be fixed relative paths")
        return self


def _require_bounded_network(cidr: str) -> ipaddress._BaseNetwork:
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR {cidr}") from exc
    too_wide = net.prefixlen == 0
    too_wide = too_wide or (net.version == 4 and net.prefixlen < 8)
    too_wide = too_wide or (net.version == 6 and net.prefixlen < 32)
    if too_wide:
        raise ValueError(f"CIDR {cidr} is wider than ProofPath accepts")
    return net


def expand_ports(specs: list[str]) -> set[int]:
    """Turn '80' and '8000-8002' into a set of ports. Port 0 is rejected."""
    ports: set[int] = set()
    for spec in specs:
        text = str(spec).strip()
        if text.isdigit():
            port = int(text)
            bounds = (port,)
        elif "-" in text:
            left, right = text.split("-", 1)
            if not left.isdigit() or not right.isdigit():
                raise ValueError(f"invalid port spec {spec}")
            bounds = tuple(range(int(left), int(right) + 1))
            if int(left) > int(right):
                raise ValueError(f"invalid port spec {spec}")
        else:
            raise ValueError(f"invalid port spec {spec}")
        for port in bounds:
            if not 1 <= port <= 65535:
                raise ValueError(f"port {port} is outside 1-65535")
            ports.add(port)
    return ports


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve A and AAAA records. Zone indexes are stripped."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    found: list[str] = []
    for info in infos:
        ip_text = str(info[4][0]).split("%", 1)[0]
        if ip_text not in found:
            found.append(ip_text)
    return found


def _is_hostname(value: str) -> bool:
    value = value[:-1] if value.endswith(".") else value
    if len(value) > 253 or ".." in value or value.startswith(".") or not value.isascii():
        return False
    labels = value.split(".")
    if not labels or not any(any(char.isalpha() for char in label) for label in labels):
        return False
    return all(_LABEL.fullmatch(label) for label in labels)


class ScopeGuard:
    """Checks structured actions against scope.yaml."""

    def __init__(self, policy: ScopePolicy, resolver: Resolver | None = None) -> None:
        self.policy = policy
        self._resolver = resolver or resolve_hostname
        self._secret = secrets.token_bytes(32)
        self._allowed_nets = [_require_bounded_network(item) for item in policy.allowed_cidrs]
        self._excluded_nets = [_require_bounded_network(item) for item in policy.excluded_cidrs]
        self._ports = expand_ports(policy.allowed_ports)
        self._excluded_ips = self._collect_excluded_ips()
        self._consumed_approvals: set[str] = set()
        self._approval_lock = threading.Lock()

    @classmethod
    def from_yaml(cls, path: str | Path, resolver: Resolver | None = None) -> ScopeGuard:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        policy = ScopePolicy.model_validate(raw)
        return cls(policy, resolver=resolver)

    def check(self, action: Action, approval: ApprovalRequest | None = None) -> GuardDecision:
        """Return a signed allow or deny. This is the only authorization decision."""
        if not isinstance(action, Action):
            raise TypeError("scope_guard.check requires an Action")

        tool = _TOOL_FOR_ACTION.get(action.name, "")
        if action.name not in self.policy.enabled_actions:
            return self._deny(action, tool, f"{action.name.value} is not enabled for this engagement")
        if action.engagement_id != self.policy.engagement:
            return self._deny(action, tool, "engagement_id does not match scope.yaml")

        target = action.target
        if not target or target != target.strip():
            return self._deny(action, tool, "target is empty or contains whitespace")
        if target.endswith("."):
            target = target[:-1]
        if target != target.strip() or any(char in target for char in " \t\r\n/\\@?#"):
            return self._deny(action, tool, "target contains characters that are not allowed")
        if target.lower() in _LOCAL_NAMES or target.lower() in {"localhost.localdomain", "localhost"}:
            return self._deny(action, tool, "localhost is denied")
        if target.lower() in {host.lower().rstrip(".") for host in self.policy.excluded_hosts}:
            return self._deny(action, tool, "target is an excluded host")

        resolved, error = self._resolve_target(target)
        if error or resolved is None:
            return self._deny(action, tool, error or "target could not be resolved")

        for ip_text in resolved:
            reason = self._ip_reason(ip_text)
            if reason:
                return self._deny(action, tool, reason, resolved_ips=resolved)

        if not action.ports:
            return self._deny(action, tool, "ports are required", resolved_ips=resolved)
        if not getattr(self.policy, "allow_all_ips", False):
            for port in action.ports:
                if port not in self._ports:
                    return self._deny(
                        action,
                        tool,
                        f"port {port} is outside the allowed port set",
                        resolved_ips=resolved,
                    )

        if action.name == ActionName.ACTIVE_VALIDATE:
            normalized, arg_error = self._validate_active_arguments(action)
        else:
            normalized, arg_error = self._normalize_arguments(tool, action.arguments)
        if arg_error or normalized is None:
            return self._deny(action, tool, arg_error or "arguments were rejected", resolved_ips=resolved)

        if action.name in _BLOCKED_UNTIL_APPROVAL:
            from proofpath.approval import approval_matches_action

            if approval is None or approval.id in self._consumed_approvals or not approval_matches_action(approval, action, datetime.now().astimezone()):
                return self._deny(action, tool, "active validation requires a valid, unused, unexpired approval bound to this action", resolved_ips=resolved)

        decision = GuardDecision(
            allowed=True,
            reason="target, ports, and arguments are inside the engagement scope",
            resolved_ips=resolved,
            ports=list(dict.fromkeys(action.ports)),
            tool=tool,
            normalized_arguments=normalized,
            action_id=action.id,
        )
        return self._sign(decision)

    def enumerate_hosts(self, cidr: str, *, max_hosts: int = 256) -> tuple[list[str], str | None]:
        """Turn one authorized CIDR into a concrete, bounded host list.

        A sweep still authorizes each host individually through `check`; this
        method only expands a range that is already inside the engagement. The
        range must be small enough to iterate and, unless universal scope is on,
        must sit inside an allowed range. Excluded hosts and ranges are removed
        and IPv4 network/broadcast addresses are dropped. Returns
        ``(hosts, None)`` or ``([], reason)`` when the sweep must not proceed.
        """
        try:
            net = _require_bounded_network(cidr)
        except ValueError as exc:
            return [], str(exc)

        contained = any(
            net.version == allowed.version and net.subnet_of(allowed)
            for allowed in self._allowed_nets
        )
        if not contained and not getattr(self.policy, "allow_all_ips", False):
            return [], f"CIDR {cidr} is not inside an allowed range"
        if net.num_addresses > max_hosts:
            return [], (
                f"CIDR {cidr} holds {net.num_addresses} addresses, "
                f"above the {max_hosts}-host sweep cap"
            )

        hosts: list[str] = []
        for ip in net:
            if net.version == 4 and net.prefixlen < 31 and ip in {net.network_address, net.broadcast_address}:
                continue
            text = self._canonical_ip(ip)
            if self._ip_reason(text) is None:
                hosts.append(text)
        return hosts, None

    def consume_approval(self, approval: ApprovalRequest, action: Action) -> bool:
        """Atomically consume a previously approved exact action once."""
        from proofpath.approval import approval_matches_action

        with self._approval_lock:
            if approval.id in self._consumed_approvals or not approval_matches_action(approval, action):
                return False
            self._consumed_approvals.add(approval.id)
            return True

    def _validate_active_arguments(self, action: Action) -> tuple[dict[str, Any] | None, str | None]:
        if len(action.ports) != 1:
            return None, "active validation requires exactly one allowed port"
        if set(action.arguments) != {"method", "path", "finding_id"}:
            return None, "active validation accepts only method, path, and finding_id"
        method, path, finding_id = action.arguments.get("method"), action.arguments.get("path"), action.arguments.get("finding_id")
        if method not in {"GET", "HEAD"}:
            return None, "active validation method must be GET or HEAD"
        if not isinstance(path, str) or path not in self.policy.allowed_validation_paths:
            return None, "active validation path is not allowlisted"
        if not isinstance(finding_id, str) or not re.fullmatch(r"F-[A-Za-z0-9_-]{1,64}", finding_id):
            return None, "active validation requires a valid finding ID"
        return {"method": method, "path": path, "finding_id": finding_id}, None

    def verify_decision(self, decision: GuardDecision) -> bool:
        """Confirm this guard instance signed the decision and it was not edited."""
        if not isinstance(decision, GuardDecision) or not decision.token:
            return False
        payload = decision.model_dump(mode="json", exclude={"token"})
        expected = self._token(payload)
        if len(decision.token) != len(expected):
            return False
        return hmac.compare_digest(expected, decision.token)

    def _deny(
        self,
        action: Action,
        tool: str,
        reason: str,
        resolved_ips: list[str] | None = None,
    ) -> GuardDecision:
        decision = GuardDecision(
            allowed=False,
            reason=reason,
            resolved_ips=list(resolved_ips or []),
            ports=[],
            tool=tool,
            normalized_arguments={},
            action_id=action.id,
        )
        return self._sign(decision)

    def _sign(self, decision: GuardDecision) -> GuardDecision:
        payload = decision.model_dump(mode="json", exclude={"token"})
        return decision.model_copy(update={"token": self._token(payload)})

    def _token(self, payload: dict[str, Any]) -> str:
        raw = canonical_json(payload).encode("utf-8")
        return hmac.new(self._secret, raw, hashlib.sha256).hexdigest()

    def _collect_excluded_ips(self) -> set[str]:
        found: set[str] = set()
        for host in self.policy.excluded_hosts:
            try:
                found.add(str(ipaddress.ip_address(host)))
            except ValueError:
                try:
                    resolved = self._resolver(host.rstrip("."))
                    for item in resolved:
                        found.add(self._canonical_ip(ipaddress.ip_address(str(item).split("%", 1)[0])))
                except (OSError, ValueError):
                    raise ValueError(f"excluded hostname could not be resolved: {host}")
                if not resolved:
                    raise ValueError(f"excluded hostname could not be resolved: {host}")
        return found

    def _resolve_target(self, target: str) -> tuple[list[str] | None, str | None]:
        if ":" in target or _DECIMAL_IP.fullmatch(target) or _HEX_IP.fullmatch(target) or _IPV4_ATTEMPT.fullmatch(target):
            try:
                if "%" in target:
                    return None, "IPv6 zone identifiers are denied"
                ip = ipaddress.ip_address(target)
            except ValueError:
                return None, "malformed IP address"
            return [self._canonical_ip(ip)], None
        if _is_hostname(target):
            try:
                resolved = self._resolver(target)
            except OSError:
                return None, "hostname did not resolve"
            if not resolved:
                return None, "hostname did not resolve"
            canon: list[str] = []
            for item in resolved:
                try:
                    ip = ipaddress.ip_address(str(item).split("%", 1)[0])
                except ValueError:
                    return None, "resolver returned a malformed address"
                text = self._canonical_ip(ip)
                if text not in canon:
                    canon.append(text)
            return canon, None
        return None, "target is not an IP address or hostname"

    @staticmethod
    def _canonical_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ip)

    def _ip_reason(self, ip_text: str) -> str | None:
        ip = ipaddress.ip_address(ip_text)
        if ip.is_unspecified:
            return "unspecified address is denied"
        if ip.is_multicast:
            return "multicast addresses are denied"
        if ip.is_link_local:
            return "link-local addresses are denied"
        if ip.is_loopback and not self.policy.allow_loopback:
            return "loopback is denied"
        if str(ip) in self._excluded_ips:
            return "target is an excluded host"
        for net in self._excluded_nets:
            if ip.version == net.version and ip in net:
                return "target is inside an excluded range"
        for net in self._allowed_nets:
            if ip.version == net.version and ip in net:
                return None
        if getattr(self.policy, "allow_all_ips", False):
            return None
        return "address is outside allowed ranges"

    def _normalize_arguments(
        self, tool: str, arguments: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str | None]:
        specs = self.policy.tool_arguments.get(tool)
        if specs is None:
            return None, "no argument allowlist for this tool"
        for key in arguments:
            if not isinstance(key, str) or not _ARG_NAME.fullmatch(key):
                return None, "argument name is not allowed"
            if key not in specs:
                return None, f"argument is not on the allowlist: {key}"
        normalized: dict[str, Any] = {}
        defaults: dict[str, Any] = {
            "service_detection": True,
            "skip_host_discovery": False,
            "timing": min(2, self.policy.rate_limits.max_timing),
            "host_timeout_seconds": min(60, self.policy.rate_limits.max_host_timeout_seconds),
        }
        for key, spec in specs.items():
            if key in arguments:
                value = arguments[key]
            elif key in defaults:
                value = defaults[key]
            else:
                return None, f"missing argument {key}"
            if spec.type == "bool":
                if type(value) is not bool:
                    return None, f"{key} must be a boolean"
                normalized[key] = value
                continue
            if type(value) is not int:
                return None, f"{key} must be an integer"
            assert spec.minimum is not None and spec.maximum is not None
            upper = spec.maximum
            if key == "timing":
                upper = min(upper, self.policy.rate_limits.max_timing)
            if key == "host_timeout_seconds":
                upper = min(upper, self.policy.rate_limits.max_host_timeout_seconds)
            if value < spec.minimum or value > upper:
                return None, f"{key} is outside the engagement rate limit"
            normalized[key] = value
        return normalized, None

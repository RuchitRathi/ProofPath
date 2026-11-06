"""Nmap adapter.

The process is started with an argument list. The scan targets are the
canonical IPs on a signed allow decision, never the raw request text.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from proofpath.adapters.base import ToolResult
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName, GuardDecision, ServiceObservation
from proofpath.scope_guard import ScopeGuard
from proofpath.xml_evidence import parse_xml_evidence

MAX_OUTPUT_BYTES = 8_000_000
_BINARY = re.compile(r"^[A-Za-z0-9._\-]+$")
_WSL_DISTRIBUTION = re.compile(r"^[A-Za-z0-9._-]+$")
Runner = Callable[..., subprocess.CompletedProcess[bytes]]


@dataclass(frozen=True)
class NmapExecutionConfig:
    runtime: str = "native"
    distribution: str | None = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> "NmapExecutionConfig":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict) or set(raw) - {"runtime", "distribution"}:
            raise ValueError("nmap.yaml must contain only runtime and distribution")
        config = cls(runtime=raw.get("runtime", "native"), distribution=raw.get("distribution"))
        if config.runtime not in {"native", "wsl"}:
            raise ValueError("nmap runtime must be native or wsl")
        if config.runtime == "wsl":
            if not isinstance(config.distribution, str) or not _WSL_DISTRIBUTION.fullmatch(config.distribution):
                raise ValueError("wsl runtime requires a valid WSL distribution name")
        elif config.distribution is not None:
            raise ValueError("distribution is valid only for wsl runtime")
        return config


def build_argv(binary: str, decision: GuardDecision, *, wsl_distribution: str | None = None) -> list[str]:
    """Build a fixed nmap argv from a signed decision. No script flags."""
    if not _BINARY.fullmatch(binary):
        raise ValueError("nmap binary name is not allowed")
    if wsl_distribution is not None and not _WSL_DISTRIBUTION.fullmatch(wsl_distribution):
        raise ValueError("WSL distribution name is not allowed")
    if not decision.resolved_ips or not decision.ports:
        raise ValueError("nmap requires resolved addresses and ports")
    ips: list[str] = []
    for ip_text in decision.resolved_ips:
        ip = ipaddress.ip_address(ip_text)
        if str(ip) != ip_text or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            raise ValueError("refusing a non-canonical target")
        ips.append(ip_text)
    timing = decision.normalized_arguments.get("timing")
    timeout = decision.normalized_arguments.get("host_timeout_seconds")
    if type(timing) is not int or not 0 <= timing <= 5:
        raise ValueError("timing is not allowed")
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise ValueError("timeout is not allowed")
    port_text: list[str] = []
    for port in decision.ports:
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("port is not allowed")
        port_text.append(str(port))
    argv = [binary, "-sT", "-oX", "-"]
    if decision.normalized_arguments.get("service_detection") is True:
        argv.append("-sV")
    if decision.normalized_arguments.get("skip_host_discovery") is True:
        argv.append("-Pn")
    argv.extend(["-T" + str(timing), "--host-timeout", f"{timeout}s", "-p", ",".join(port_text)])
    argv.extend(ips)
    if "--script" in argv or any(str(item).startswith("--script") for item in argv):
        raise ValueError("nmap scripts are not allowed")
    if wsl_distribution is not None:
        argv = ["wsl.exe", "--distribution", wsl_distribution, "--exec", *argv]
    return argv


def parse_nmap_xml(xml_bytes: bytes, evidence_id: str) -> list[ServiceObservation]:
    """Read port facts from nmap XML. Missing attributes stay null."""
    if len(xml_bytes) > MAX_OUTPUT_BYTES:
        raise ValueError("nmap output exceeds the capture limit")
    document = parse_xml_evidence(xml_bytes, label="nmap")
    root = document.root
    if root.tag != "nmaprun":
        raise ValueError("not an nmap xml document")
    observations: list[ServiceObservation] = []
    for host_index, host in enumerate(root.findall("host"), 1):
        ip = _host_ip(host)
        if ip is None:
            continue
        ports = host.find("ports")
        if ports is None:
            continue
        for port_index, port in enumerate(ports.findall("port"), 1):
            port_id = port.get("portid")
            if port_id is None or not port_id.isdigit():
                continue
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else None
            service_el = port.find("service")
            observations.append(
                ServiceObservation(
                    evidence_id=evidence_id,
                    ip=ip,
                    port=int(port_id),
                    protocol=port.get("protocol") or "tcp",
                    state=state or "unknown",
                    service=_attr(service_el, "name"),
                    product=_attr(service_el, "product"),
                    version=_attr(service_el, "version"),
                    locator=f"/nmaprun/host[{host_index}]/ports[1]/port[{port_index}]",
                    excerpt=document.excerpt(f"/nmaprun/host[{host_index}]/ports[1]/port[{port_index}]"),
                )
            )
    return observations


def _host_ip(host: ET.Element) -> str | None:
    for address in host.findall("address"):
        if address.get("addrtype") in {"ipv4", "ipv6"} and address.get("addr"):
            return address.get("addr")
    return None


def _attr(element: ET.Element | None, name: str) -> str | None:
    if element is None:
        return None
    value = element.get(name)
    if value is None or value == "":
        return None
    return value


class NmapAdapter:
    """Live nmap. Mode is Live only when this adapter is registered."""

    mode = "Live"

    def __init__(self, binary: str = "nmap", runner: Runner | None = None, *, wsl_distribution: str | None = None) -> None:
        self.binary = binary
        self._runner = runner or subprocess.run
        self.wsl_distribution = wsl_distribution

    def run(
        self,
        decision: GuardDecision,
        guard: ScopeGuard,
        audit: AuditLog,
        ledger: Ledger,
        actor: str,
    ) -> ToolResult:
        """Run nmap when the decision is a signed allow. Otherwise record a block."""
        if not decision.allowed or decision.tool != "nmap" or not guard.verify_decision(decision):
            audit.append(
                "execution_blocked",
                actor,
                {"action_id": decision.action_id, "reason": "decision was not a signed nmap allow"},
            )
            return ToolResult(
                status="denied",
                decision=decision,
                message="execution blocked because the decision was not a signed nmap allow",
            )
        argv = build_argv(self.binary, decision, wsl_distribution=self.wsl_distribution)
        timeout = int(decision.normalized_arguments["host_timeout_seconds"]) + 30
        try:
            completed = self._runner(
                argv,
                capture_output=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return self._timeout(exc, argv, decision, audit, ledger, actor)
        except FileNotFoundError:
            audit.append(
                "nmap_result",
                actor,
                {"action_id": decision.action_id, "status": "tool_not_found", "command": argv},
            )
            return ToolResult(
                status="tool_not_found",
                decision=decision,
                message="nmap binary was not found",
            )
        stdout = completed.stdout or b""
        stderr = completed.stderr or b""
        return self._from_output(
            stdout=stdout,
            stderr=stderr,
            returncode=completed.returncode,
            argv=argv,
            decision=decision,
            audit=audit,
            ledger=ledger,
            actor=actor,
        )

    def _timeout(
        self,
        exc: subprocess.TimeoutExpired,
        argv: list[str],
        decision: GuardDecision,
        audit: AuditLog,
        ledger: Ledger,
        actor: str,
    ) -> ToolResult:
        raw = exc.stdout or b""
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        if len(raw) > MAX_OUTPUT_BYTES:
            audit.append(
                "nmap_result",
                actor,
                {
                    "action_id": decision.action_id,
                    "status": "timeout",
                    "stdout_bytes": len(raw),
                    "stored": False,
                },
            )
            return ToolResult(
                status="timeout",
                decision=decision,
                message=f"nmap timed out and stdout was {len(raw)} bytes, above the capture cap",
            )
        evidence = ledger.store(
            content=raw,
            tool="nmap",
            command=argv,
            status="timeout",
            summary="nmap timed out; partial output was stored and was not parsed into services",
        )
        audit.append(
            "nmap_result",
            actor,
            _result_details(decision, evidence.id, evidence.sha256, "timeout"),
        )
        return ToolResult(
            status="timeout",
            decision=decision,
            evidence_id=evidence.id,
            sha256=evidence.sha256,
            message=evidence.summary,
        )


    def _from_output(
        self,
        *,
        stdout: bytes,
        stderr: bytes,
        returncode: int,
        argv: list[str],
        decision: GuardDecision,
        audit: AuditLog,
        ledger: Ledger,
        actor: str,
    ) -> ToolResult:
        if len(stdout) > MAX_OUTPUT_BYTES:
            audit.append(
                "nmap_result",
                actor,
                {
                    "action_id": decision.action_id,
                    "status": "error",
                    "stdout_bytes": len(stdout),
                    "stored": False,
                },
            )
            return ToolResult(
                status="error",
                decision=decision,
                message=f"nmap stdout was {len(stdout)} bytes, above the capture cap",
            )
        stored = stdout
        if stderr:
            stored = stdout + b"\n--- stderr ---\n" + stderr
        try:
            parsed = parse_nmap_xml(stdout, "pending")
        except ValueError as exc:
            evidence = ledger.store(
                content=stored,
                tool="nmap",
                command=argv,
                status="error",
                summary=f"nmap exit {returncode}; output was not usable scan xml ({exc})",
            )
            audit.append(
                "nmap_result",
                actor,
                _result_details(decision, evidence.id, evidence.sha256, "error"),
            )
            return ToolResult(
                status="error",
                decision=decision,
                evidence_id=evidence.id,
                sha256=evidence.sha256,
                message=evidence.summary,
            )
        # A parsed document is still shown when nmap exits non-zero.
        # The status stays "error" so the exit code is not hidden.
        result_status = "ok" if returncode == 0 else "error"
        evidence = ledger.store(
            content=stored,
            tool="nmap",
            command=argv,
            status=result_status,
            summary=f"nmap exit {returncode}; parsed {len(parsed)} port observations",
        )
        services = [item.model_copy(update={"evidence_id": evidence.id}) for item in parsed]
        audit.append(
            "nmap_result",
            actor,
            _result_details(decision, evidence.id, evidence.sha256, result_status),
        )
        return ToolResult(
            status=result_status,
            decision=decision,
            evidence_id=evidence.id,
            sha256=evidence.sha256,
            services=services,
            parsed_items=len(services),
            message=evidence.summary,
        )


def _result_details(decision: GuardDecision, evidence_id: str, digest: str, status: str) -> dict[str, Any]:
    return {
        "action_id": decision.action_id,
        "status": status,
        "evidence_id": evidence_id,
        "sha256": digest,
        "resolved_ips": decision.resolved_ips,
    }


class RecordedNmapXMLAdapter:
    """Parse an explicitly imported recorded XML artifact; never starts a process."""
    mode = "Import-only"

    def __init__(self, content: bytes) -> None:
        self.content = content

    def run(self, decision: GuardDecision, guard: ScopeGuard, audit: AuditLog, ledger: Ledger, actor: str) -> ToolResult:
        if not decision.allowed or decision.tool != "nmap" or not guard.verify_decision(decision):
            audit.append("execution_blocked", actor, {"action_id": decision.action_id, "reason": "decision was not a verified import allow"})
            return ToolResult(status="denied", decision=decision, message="recorded XML import denied")
        try:
            parsed = parse_nmap_xml(self.content, "pending")
        except ValueError as exc:
            return ToolResult(status="error", decision=decision, message=f"recorded XML rejected: {exc}")
        evidence = ledger.store(content=self.content, tool="nmap", command=["import_nmap_xml"], status="ok", summary=f"imported recorded nmap XML; parsed {len(parsed)} port observations", source_mode="imported")
        services: list[ServiceObservation] = []
        dropped = 0
        for item in parsed:
            item_action = Action(
                id=f"{decision.action_id}-import-{len(services) + dropped}",
                name=ActionName.IMPORT_NMAP_XML,
                target=item.ip,
                ports=[item.port],
                arguments={},
                engagement_id=guard.policy.engagement,
                requested_by=actor,
            )
            item_decision = guard.check(item_action)
            if not guard.verify_decision(item_decision):
                raise RuntimeError("scope guard returned an unsigned nmap import decision")
            if not item_decision.allowed:
                audit.append("out_of_scope", actor, {"evidence_id": evidence.id, "host": item.ip, "port": item.port, "reason": item_decision.reason})
                dropped += 1
                continue
            services.append(item.model_copy(update={"evidence_id": evidence.id, "source_mode": "imported"}))
        audit.append("nmap_import", actor, {"action_id": decision.action_id, "status": "ok", "source_mode": "imported", "evidence_id": evidence.id, "sha256": evidence.sha256, "parsed_items": len(parsed), "dropped_items": dropped})
        return ToolResult(status="ok", decision=decision, evidence_id=evidence.id, sha256=evidence.sha256, services=services, parsed_items=len(parsed), dropped_items=dropped, message=evidence.summary)

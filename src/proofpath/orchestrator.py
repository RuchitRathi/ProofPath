"""Bounded CIDR sweep across the existing single-host scan pipeline.

Enumeration lives on `ScopeGuard.enumerate_hosts` so one component decides what
is in scope. This module only iterates that approved host list and funnels every
host through the same `execute_action` choke point — no host reaches Nmap
without its own signed scope decision.
"""

from __future__ import annotations

import time
import uuid
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from proofpath.adapters.base import execute_action
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName, ServiceObservation
from proofpath.scope_guard import ScopeGuard


class HostScanResult(BaseModel):
    """Per-host outcome inside one sweep."""

    model_config = ConfigDict(extra="forbid")

    host: str
    allowed: bool
    status: str
    reason: str
    evidence_id: str | None = None
    service_count: int = 0


class SweepReport(BaseModel):
    """The plan, per-host results, and union of services for one CIDR."""

    model_config = ConfigDict(extra="forbid")

    cidr: str
    hosts: list[str]
    results: list[HostScanResult] = Field(default_factory=list)
    services: list[ServiceObservation] = Field(default_factory=list)

    @property
    def scanned(self) -> int:
        return sum(1 for row in self.results if row.allowed)

    @property
    def denied(self) -> int:
        return sum(1 for row in self.results if not row.allowed)


def sweep_cidr(
    guard: ScopeGuard,
    audit: AuditLog,
    ledger: Ledger,
    adapters: dict[ActionName, object],
    cidr: str,
    ports: list[int],
    hosts: list[str],
    *,
    delay_seconds: float = 0.0,
    requester: str = "cidr-orchestrator",
    progress: Callable[[HostScanResult], None] | None = None,
) -> SweepReport:
    """Scan each enumerated host, one at a time, with a signed decision per host."""
    report = SweepReport(cidr=cidr, hosts=list(hosts))
    audit.append(
        "cidr_sweep_planned",
        requester,
        {"cidr": cidr, "host_count": len(hosts), "ports": list(ports), "hosts": list(hosts)},
    )

    for index, host in enumerate(report.hosts):
        if index and delay_seconds > 0:
            time.sleep(delay_seconds)
        action = Action(
            id=uuid.uuid4().hex,
            name=ActionName.NMAP_SCAN,
            target=host,
            ports=list(ports),
            arguments={
                "service_detection": True,
                "skip_host_discovery": True,
                "timing": 2,
                "host_timeout_seconds": 60,
            },
            engagement_id=guard.policy.engagement,
            requested_by=requester,
        )
        result = execute_action(action, guard, audit, ledger, adapters)
        row = HostScanResult(
            host=host,
            allowed=result.decision.allowed,
            status=result.status,
            reason=result.decision.reason,
            evidence_id=result.evidence_id,
            service_count=len(result.services),
        )
        report.results.append(row)
        if result.decision.allowed:
            report.services.extend(result.services)
        if progress is not None:
            progress(row)

    audit.append(
        "cidr_sweep_completed",
        requester,
        {
            "cidr": cidr,
            "scanned": report.scanned,
            "denied": report.denied,
            "services": len(report.services),
        },
    )
    return report

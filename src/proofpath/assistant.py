"""Conversational security assistant guiding end-to-end VAPT assessments."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.proposer import ModelClient
from proofpath.schemas import Action, ActionName, Finding, ServiceObservation
from proofpath.scope_guard import ScopeGuard

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r"\b(?:port|ports)\s+([0-9,\s]+)\b", re.IGNORECASE)
_SINGLE_PORT_RE = re.compile(r"\b([0-9]{1,5})\b")

_TOOL_KEYWORDS = {
    "nmap": ActionName.NMAP_SCAN,
    "nessus": ActionName.IMPORT_NESSUS,
    "burp": ActionName.IMPORT_BURP,
    "openvas": ActionName.IMPORT_OPENVAS,
    "greenbone": ActionName.IMPORT_OPENVAS,
    "nikto": ActionName.IMPORT_NIKTO,
    "zap": ActionName.IMPORT_ZAP,
    "metasploit": ActionName.IMPORT_METASPLOIT,
}


class ParsedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw_text: str
    target: str | None = None
    ports: list[int] = Field(default_factory=list)
    tools_mentioned: list[str] = Field(default_factory=list)
    intent: str = "general"
    scope_allowed: bool | None = None
    scope_reason: str | None = None
    recommended_action: ActionName | None = None
    assistant_reply: str = ""
    staged_action: Action | None = None


class SecurityAssistant:
    """Conversational security guide that evaluates intent, enforces scope, and plans VAPT stages."""

    def __init__(
        self,
        guard: ScopeGuard,
        audit: AuditLog,
        ledger: Ledger,
        model_client: ModelClient | None = None,
    ) -> None:
        self.guard = guard
        self.audit = audit
        self.ledger = ledger
        self.model_client = model_client

    def parse_request(
        self,
        text: str,
        observations: list[ServiceObservation] | None = None,
        findings: list[Finding] | None = None,
    ) -> ParsedRequest:
        observations = observations or []
        findings = findings or []
        text_clean = text.strip()

        # 1. Target extraction
        target_match = _IPV4_RE.search(text_clean)
        target = target_match.group(0) if target_match else None
        if not target:
            # Check for domain / hostname tokens like example.lab or target.local
            domain_match = re.search(r"\b([a-zA-Z0-9.-]+\.(?:lab|local|test|corp|internal))\b", text_clean, re.IGNORECASE)
            if domain_match:
                target = domain_match.group(1)

        # 2. Port extraction
        ports: list[int] = []
        port_block = _PORT_RE.search(text_clean)
        if port_block:
            raw_ports = port_block.group(1)
            for part in re.split(r"[,\s]+", raw_ports):
                if part.isdigit() and 1 <= int(part) <= 65535:
                    ports.append(int(part))
        if not ports and target:
            # Common defaults based on request context
            if any(term in text_clean.casefold() for term in ["web", "http", "https", "url", "website"]):
                ports = [80, 443]
            elif any(term in text_clean.casefold() for term in ["all ports", "full scan", "range"]):
                ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
            else:
                ports = [80, 443]

        # 3. Mentioned tools
        tools_mentioned = [tool for tool in _TOOL_KEYWORDS if tool in text_clean.casefold()]

        # 4. Intent classification
        intent = "general"
        lower_text = text_clean.casefold()
        if any(w in lower_text for w in ["scan", "recon", "discover", "probe", "nmap", "ports"]):
            intent = "reconnaissance"
        elif any(w in lower_text for w in ["web", "nikto", "zap", "burp", "xss", "sqli", "injection"]):
            intent = "web_assessment"
        elif any(w in lower_text for w in ["vulnerability", "vuln", "nessus", "openvas", "cve"]):
            intent = "vulnerability_scan"
        elif any(w in lower_text for w in ["exploit", "metasploit", "validate", "active", "poc"]):
            intent = "validation_inquiry"
        elif any(w in lower_text for w in ["report", "sarif", "pdf", "export", "executive"]):
            intent = "reporting_inquiry"
        elif any(w in lower_text for w in ["status", "findings", "risk", "summary", "progress"]):
            intent = "status_inquiry"

        # 5. Scope validation if target is identified
        scope_allowed: bool | None = None
        scope_reason: str | None = None
        staged_action: Action | None = None
        recommended_action: ActionName | None = None

        if target:
            test_ports = ports or [80]
            probe_action = Action(
                id=uuid.uuid4().hex,
                name=ActionName.NMAP_SCAN,
                target=target,
                ports=test_ports,
                arguments={"service_detection": True, "skip_host_discovery": False, "timing": 2, "host_timeout_seconds": 60},
                engagement_id=self.guard.policy.engagement,
                requested_by="analyst-assistant",
            )
            decision = self.guard.check(probe_action)
            scope_allowed = decision.allowed
            scope_reason = decision.reason
            if scope_allowed:
                staged_action = probe_action

        # 6. Synthesize security rationale and conversational advice
        reply_lines: list[str] = []

        if target:
            if scope_allowed:
                reply_lines.append(f"**Target Scope Verified**: `{target}` is **authorized** in engagement `{self.guard.policy.engagement}` ({scope_reason}).")
            else:
                reply_lines.append(f"**Scope Warning**: `{target}` is **denied** by scope policy: *{scope_reason}*.")
                reply_lines.append("Testing outside authorized CIDR boundaries is strictly prevented by the Scope Guard.")

        # Context-aware lifecycle guidance
        open_web_ports = [obs for obs in observations if obs.port in {80, 443, 8080, 8443} and obs.state.casefold() == "open"]
        
        if intent == "reconnaissance" and target and scope_allowed:
            recommended_action = ActionName.NMAP_SCAN
            reply_lines.append(
                f"**Assessment Plan**: Step 1 — Reconnaissance. Run a service discovery scan using Nmap on `{target}` "
                f"for ports `{','.join(str(p) for p in ports)}` to identify active services, banners, and exposure states."
            )
        elif intent == "web_assessment" and target:
            if open_web_ports:
                recommended_action = ActionName.IMPORT_ZAP
                reply_lines.append(
                    f"**Assessment Plan**: Step 2 — Web Application Assessment. Open HTTP/HTTPS endpoints discovered "
                    f"({', '.join(f'{o.ip}:{o.port}' for o in open_web_ports)}). Recommended actions:\n"
                    f"- Import an **OWASP ZAP** or **Burp Suite** report for application-layer analysis (XSS, SQLi, CSRF, broken access control).\n"
                    f"- Import a **Nikto** scan for web server misconfiguration, exposed files, and outdated header checks."
                )
            else:
                reply_lines.append(
                    f"**Assessment Guidance**: Before web assessment, confirm web service exposure using Nmap reconnaissance on `{target}`."
                )
        elif intent == "vulnerability_scan" and target:
            recommended_action = ActionName.IMPORT_NESSUS
            reply_lines.append(
                f"**Assessment Plan**: Infrastructure Vulnerability Assessment. Import a **Nessus** or **OpenVAS / Greenbone** report "
                f"for host `{target}` to identify CVEs, unpatched services, and security flaws."
            )
        elif intent == "validation_inquiry":
            reply_lines.append(
                "**Security Boundary Notice**: Active validation or offensive proof-of-concept testing requires an "
                "explicit, independent human approval record before execution. Autonomous exploitation is strictly prohibited. "
                "Use the **Approvals** tab to submit and authorize non-destructive validation requests."
            )
        elif intent == "reporting_inquiry":
            reply_lines.append(
                f"**Reporting Status**: Current findings ({len(findings)}) can be exported in the **Report** tab as:\n"
                f"- Deterministic, client-ready **ReportLab PDF** with 8 standard sections and executive summary.\n"
                f"- Industry-standard **OASIS SARIF v2.1.0** export for integration with GitHub Advanced Security / CI/CD.\n"
                f"- Retesting change comparison diff against prior baselines."
            )
        elif intent == "status_inquiry":
            obs_count = len(observations)
            find_count = len(findings)
            reply_lines.append(
                f"**Current Engagement Status**:\n"
                f"- Engagement: `{self.guard.policy.engagement}`\n"
                f"- Service observations recorded: **{obs_count}**\n"
                f"- Correlated findings: **{find_count}**\n"
                f"- Active approval records: maintained in audit ledger"
            )
        else:
            reply_lines.append(
                "**ProofPath VAPT Assistant Active**: State an assessment objective (e.g., 'Assess host 10.10.1.5 for web vulnerabilities', "
                "'Check if 10.20.0.10 is in scope', or 'What should I investigate next?'). All actions are scope-guarded and hash-audited."
            )

        # Grounded Qwen model recommendation if client configured
        if self.model_client is not None:
            try:
                system_prompt = (
                    "You are the ProofPath AI VAPT assistant. Ground your response in the provided scope decision. "
                    "Never invent open ports, vulnerabilities, CVEs, or evidence. Respect scope boundaries strictly. "
                    "Return a JSON object with a single 'recommendation' string of 1-2 sentences."
                )
                user_msg = (
                    f"Analyst query: '{text_clean}'. "
                    f"Target: '{target or 'unspecified'}'. Scope status: {'ALLOWED' if scope_allowed else 'DENIED' if scope_allowed is False else 'NOT_CHECKED'}. "
                    f"Observations: {len(observations)}. Findings: {len(findings)}. "
                    f"Provide a concise security recommendation."
                )
                raw_resp = self.model_client.complete(
                    [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_msg}],
                    {"type": "object", "properties": {"recommendation": {"type": "string"}}, "required": ["recommendation"], "additionalProperties": False},
                )
                parsed_rec = json.loads(raw_resp).get("recommendation", "")
                if parsed_rec:
                    reply_lines.append(f"**Qwen AI Security Recommendation**: {parsed_rec}")
            except Exception:
                pass

        reply_text = "\n\n".join(reply_lines)

        parsed = ParsedRequest(
            raw_text=text_clean,
            target=target,
            ports=ports,
            tools_mentioned=tools_mentioned,
            intent=intent,
            scope_allowed=scope_allowed,
            scope_reason=scope_reason,
            recommended_action=recommended_action,
            assistant_reply=reply_text,
            staged_action=staged_action,
        )

        # Hash-chained audit event for conversational interaction
        self.audit.append(
            "analyst_conversation",
            "analyst-assistant",
            {
                "raw_text": text_clean[:500],
                "target": target,
                "ports": ports,
                "intent": intent,
                "scope_allowed": scope_allowed,
                "scope_reason": scope_reason,
                "recommended_action": recommended_action.value if recommended_action else None,
            },
        )

        return parsed


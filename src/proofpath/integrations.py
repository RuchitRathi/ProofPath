"""What each external tool can do in this build.

Status values are only Live, Import-only, Planned, or Unsupported.
A Planned tool has no working executor.
"""

from __future__ import annotations

INTEGRATIONS: list[dict[str, str]] = [
    {
        "tool": "Nmap",
        "mode": "Live",
        "limitation": "Live-capable; this workstation's WSL Ubuntu 7.98 run was verified only against 127.0.0.1 inside WSL and returned a closed port. The Windows in-process server was not reachable from WSL loopback. Recorded XML import remains labeled imported. Guarded skip_host_discovery maps to -Pn and defaults off.",
    },
    {
        "tool": "Nikto",
        "mode": "Planned",
        "limitation": "No executor is registered.",
    },
    {
        "tool": "OWASP ZAP",
        "mode": "Planned",
        "limitation": "The Docker daemon API is not wired.",
    },
    {
        "tool": "Nessus",
        "mode": "Import-only",
        "limitation": "Imports bounded NessusClientData_v2 XML. Synthetic fixture only; verify details against an export from the installed Nessus version.",
    },
    {
        "tool": "Burp Suite",
        "mode": "Import-only",
        "limitation": "Imports bounded issue XML; one validated internal ELEMENT/ATTLIST DTD subset is accepted after stripping. Entities, external identifiers, and other DTD forms are refused.",
    },
    {
        "tool": "OpenVAS",
        "mode": "Planned",
        "limitation": "The intended mode is report import. The parser is not built.",
    },
    {
        "tool": "Metasploit",
        "mode": "Planned",
        "limitation": "No Metasploit integration is built.",
    },
    {
        "tool": "ProofPath HTTP validation",
        "mode": "Live",
        "limitation": "One human-approved GET/HEAD to a configured path on one in-scope port; no body, custom headers, or redirect following.",
    },
    {
        "tool": "sqlmap",
        "mode": "Unsupported",
        "limitation": "No integration and no action name.",
    },
]

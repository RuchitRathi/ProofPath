"""What each external tool can do in this build.

Status values are only Live, Import-only, Planned, or Unsupported.
A Planned tool has no working executor.
"""

from __future__ import annotations

INTEGRATIONS: list[dict[str, str]] = [
    {
        "tool": "Nmap",
        "mode": "Live",
        "limitation": "Nmap: Live through configured native or WSL runtime; this workstation uses WSL Ubuntu. Recorded XML import remains labeled imported. Guarded skip_host_discovery maps to -Pn and defaults off.",
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
        "limitation": "Imports bounded DTD-free issue XML. Standard exports may include an internal DTD and are refused by the safe parser.",
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

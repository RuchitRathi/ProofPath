# Integration matrix

Statuses describe the code available in this build. **Live** means an executor exists; it does not imply every network topology has been verified.

| Tool | Status | Verified behavior and limit |
| --- | --- | --- |
| Nmap | Live | Ubuntu WSL 7.98, explicit TCP connect (`-sT`); the verified scan targeted WSL's own 127.0.0.1 and found a closed port. Windows host-only/Docker reachability is unverified. |
| Nikto | Planned | No executor. |
| OWASP ZAP | Planned | Docker daemon API is not connected. |
| Nessus | Import-only | Bounded `NessusClientData_v2` XML; only synthetic fixture tested. |
| Burp Suite | Import-only | Bounded issue XML; a validated internal ELEMENT/ATTLIST subset is accepted, entities and external identifiers are refused; only synthetic fixture tested. |
| OpenVAS | Planned | Import parser is not built. |
| Metasploit | Planned | No integration is built. |
| ProofPath HTTP validation | Live | Exact approved GET/HEAD to one scoped port and allowlisted path; no body, custom headers, or redirects. |
| sqlmap | Unsupported | No integration or action type. |

The same statuses are maintained in `src/proofpath/integrations.py` and the matrix in [PROJECT.md](PROJECT.md). Never infer compatibility with a real Nessus/Burp export from the synthetic fixtures.

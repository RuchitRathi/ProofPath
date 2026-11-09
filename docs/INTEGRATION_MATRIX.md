# Integration matrix

Statuses describe the code available in this build. **Live** means an executor exists; it does not imply every network topology has been verified.

| Tool | Status | Verified behavior and limit |
| --- | --- | --- |
| Nmap | Live | Ubuntu WSL 7.98, explicit TCP connect (`-sT`); the verified scan targeted WSL's own 127.0.0.1 and found a closed port. Windows host-only/Docker reachability is unverified. |
| ProofPath Web Scan | Live | Native standard-library GET probe on the guard's resolved IPs and allowlisted ports. Reads bounded response headers, cookie flags, and TLS negotiation into evidence-backed findings; no body, caller headers, or redirects. |
| Nikto | Import-only | Imports bounded Nikto JSON or XML reports. Web configuration issues, sensitive paths, and headers are normalized with source evidence references. |
| OWASP ZAP | Import-only | Imports bounded OWASP ZAP XML or JSON alert reports. Web application alerts, CWE/WASC classifications, and solutions are normalized with evidence references. |
| Nessus | Import-only | Bounded `NessusClientData_v2` XML; only synthetic fixture tested. |
| Burp Suite | Import-only | Bounded issue XML; a validated internal ELEMENT/ATTLIST subset is accepted, entities and external identifiers are refused; only synthetic fixture tested. |
| OpenVAS | Import-only | Imports bounded OpenVAS / Greenbone XML report exports. Vulnerability checks, CVSS, and CVE references are normalized with source evidence references. |
| Metasploit | Import-only | Imports human-approved, lab-controlled Metasploit findings and validation exports. Autonomous exploitation is strictly prohibited. |
| ProofPath HTTP validation | Live | Exact approved GET/HEAD to one scoped port and allowlisted path; no body, custom headers, or redirects. |
| sqlmap | Unsupported | No integration or action type. |

The same statuses are maintained in `src/proofpath/integrations.py` and the matrix in [PROJECT.md](PROJECT.md). Never infer compatibility with a real Nessus/Burp export from the synthetic fixtures.

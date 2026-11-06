"""Schema display rules."""

import pytest
from pydantic import ValidationError

from datetime import datetime, timezone

from proofpath.schemas import EvidenceRef, Finding, format_cvss


def test_missing_cvss_is_labeled_not_provided() -> None:
    assert format_cvss(None) == "not provided"
    assert format_cvss(7.5) == "7.5"


def test_finding_requires_evidence_and_rejects_out_of_range_cvss() -> None:
    with pytest.raises(ValidationError):
        _finding(evidence=[])
    with pytest.raises(ValidationError):
        _finding(cvss=11)


def _finding(**updates):
    now = datetime.now(timezone.utc)
    values = dict(id="F-0001", title="Example", asset={"ip": "10.10.1.5"}, port=443, protocol="tcp", service="https", source_tools=["nmap"], evidence=[EvidenceRef(evidence_id="EV-0001", locator="/nmaprun/host[1]", excerpt="<host/>")], observed="seen", inference="", confidence="medium", status="suspected", first_seen=now, last_seen=now)
    values.update(updates)
    return Finding(**values)


def test_finding_identifiers_validate_and_old_status_is_rejected() -> None:
    assert _finding(cves=["CVE-2024-1234"], cwes=["CWE-79"]).cves == ["CVE-2024-1234"]
    with pytest.raises(ValidationError):
        _finding(cves=["CVE-bad"])
    with pytest.raises(ValidationError):
        _finding(cwes=["CWE-no"])
    with pytest.raises(ValidationError):
        _finding(status="supported")

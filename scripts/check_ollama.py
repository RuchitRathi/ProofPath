"""Check local Ollama tags and exercise ProofPath's schema-constrained response."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

from proofpath.proposer import OllamaConfig, ProposedAction


def main() -> int:
    config = OllamaConfig.from_yaml("ollama.yaml")
    tags_url = config.base_url.rstrip("/") + "/api/tags"
    try:
        with urlopen(tags_url, timeout=3) as response:
            tags_result = json.loads(response.read(1_000_001))
    except Exception as exc:
        print("Ollama reachable: no")
        print(f"Ollama unavailable at {config.base_url}: {exc}")
        print("Schema-constrained test call skipped.")
        return 0

    print("Ollama reachable: yes")
    names = [row.get("name", "") for row in tags_result.get("models", []) if isinstance(row, dict)]
    print("ollama list tags (from /api/tags): " + (", ".join(names) if names else "(none)"))
    tag = config.model_tag.strip()
    if not tag:
        print("Configured tag: (blank); exists: n/a")
        print("No model_tag configured in ollama.yaml. Schema-constrained test call skipped.")
        return 0
    if tag not in names and not any(name.split(":", 1)[0] == tag for name in names):
        print(f"Configured tag {tag!r} exists: no. Schema-constrained test call skipped.")
        return 0
    print(f"Configured tag {tag!r} exists: yes")

    payload = {
        "model": tag,
        "stream": False,
        "format": ProposedAction.model_json_schema(),
        "messages": [{
            "role": "user",
            "content": (
                "Return a schema-valid synthetic proposer object only. Use action name import_burp, "
                "target 10.10.1.5, ports [80], engagement_id lab-01, requested_by planner. "
                "Use evidence ID EV-TEST in the observed rationale. This is a schema test fixture, "
                "not a real scan or evidence claim."
            ),
        }],
    }
    request = Request(
        config.base_url.rstrip("/") + "/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=config.timeout_seconds) as response:
            result = json.loads(response.read(1_000_001))
        content = result.get("message", {}).get("content")
        ProposedAction.model_validate_json(content)
    except Exception as exc:
        print(f"Schema-constrained test call FAILED: {exc}")
        return 1
    print(f"Schema-constrained test call PASS for {tag} (synthetic fixture only).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

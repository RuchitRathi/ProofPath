"""Check local Ollama tags and exercise ProofPath's schema-constrained response."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from proofpath.proposer import CandidateSelection, OllamaClient, OllamaConfig


def main() -> int:
    config = OllamaConfig.from_yaml(ROOT / "ollama.yaml")
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

    try:
        schema = CandidateSelection.model_json_schema()
        schema["properties"]["candidate_id"]["enum"] = ["C1"]
        content = OllamaClient(config).complete(
            [
                {"role": "system", "content": "Return candidate_id and rationale only. Never return action fields."},
                {"role": "user", "content": "Select C1. Cite EV-TEST in one observed item. This is synthetic schema-test text."},
            ],
            schema,
        )
        parsed = CandidateSelection.model_validate_json(content)
        if parsed.candidate_id != "C1":
            raise ValueError("model returned a candidate outside the test enum")
    except Exception as exc:
        print(f"Schema-constrained test call FAILED: {exc}")
        return 1
    print(f"Schema-constrained candidate-selection test PASS for {tag} (synthetic fixture only).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

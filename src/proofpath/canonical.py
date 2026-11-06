"""Stable JSON encoding for hashes and decision signatures."""

from __future__ import annotations

import json
from typing import Any


def canonical_json(data: Any) -> str:
    """Return a deterministic JSON string with sorted object keys."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )

"""Bounded XML parsing and exact source spans for evidence locators."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from xml.parsers import expat
import xml.etree.ElementTree as ET

MAX_IMPORT_BYTES = 25_000_000


@dataclass(frozen=True)
class XmlDocument:
    root: ET.Element
    raw: bytes
    spans: dict[str, tuple[int, int]]

    def excerpt(self, locator: str, max_chars: int = 300) -> str:
        span = self.spans.get(locator)
        if span is None:
            raise ValueError(f"XML locator does not exist: {locator}")
        fragment = self.raw[span[0]:span[1]]
        # Trim by bytes while preserving an exact, valid UTF-8 substring.
        while fragment:
            try:
                value = fragment.decode("utf-8")
                return value[:max_chars]
            except UnicodeDecodeError:
                fragment = fragment[:-1]
        return ""


def parse_xml_evidence(raw: bytes, *, label: str) -> XmlDocument:
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError(f"{label} XML exceeds the {MAX_IMPORT_BYTES}-byte import limit")
    lowered = raw.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ValueError(f"{label} XML with a DOCTYPE or entity declaration is refused")
    if not raw.strip():
        raise ValueError(f"empty {label} XML")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"invalid {label} XML") from exc
    spans = _source_spans(raw)
    return XmlDocument(root=root, raw=raw, spans=spans)


def _source_spans(raw: bytes) -> dict[str, tuple[int, int]]:
    parser = expat.ParserCreate()
    spans: dict[str, tuple[int, int]] = {}
    stack: list[tuple[str, str, int]] = []
    siblings: list[defaultdict[str, int]] = []

    def start(name: str, _attrs: dict[str, str]) -> None:
        if not stack:
            path = f"/{name}"
        else:
            siblings[-1][name] += 1
            path = f"{stack[-1][1]}/{name}[{siblings[-1][name]}]"
        stack.append((name, path, parser.CurrentByteIndex))
        siblings.append(defaultdict(int))

    def end(name: str) -> None:
        if not stack or stack[-1][0] != name:
            raise ValueError("XML element stack mismatch")
        _tag, path, start_index = stack.pop()
        siblings.pop()
        end_index = parser.CurrentByteIndex
        if raw[end_index:end_index + 2] == b"</":
            close = raw.find(b">", end_index)
            if close < 0:
                raise ValueError("truncated XML closing tag")
            end_index = close + 1
        spans[path] = (start_index, end_index)

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        parser.Parse(raw, True)
    except expat.ExpatError as exc:
        raise ValueError("invalid XML byte offsets") from exc
    return spans

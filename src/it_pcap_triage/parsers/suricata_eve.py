from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_eve(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise RuntimeError(f"Suricata output missing: {path}; check EVE logging configuration")

    events = []
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("expected JSON object")
            except ValueError as exc:
                raise RuntimeError(f"Invalid Suricata EVE record at line {number}: {path}") from exc
            events.append(event)
    return events


def split_eve(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_type: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        event_type = event.get("event_type", "unknown")
        by_type.setdefault(event_type, []).append(event)
    return by_type

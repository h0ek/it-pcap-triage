from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_eve(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []

    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def split_eve(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_type: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        event_type = event.get("event_type", "unknown")
        by_type.setdefault(event_type, []).append(event)
    return by_type

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from ..utils import safe_int


def _num(value: str) -> int:
    # Supports normal digits, commas and narrow no-break spaces used by some locales.
    digits = re.sub(r"[^0-9]", "", value or "")
    return safe_int(digits)


def parse_capinfos(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}

    data = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_norm = key.strip().lower().replace(" ", "_")
        data[key_norm] = value.strip()
    return data


def parse_protocol_hierarchy(path: Path, top_limit: int = 25) -> list[dict[str, Any]]:
    if not path.is_file():
        return []

    rows = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        raw = line.rstrip()
        low = raw.lower()
        if not raw or raw.startswith("=") or "protocol hierarchy statistics" in low or low.startswith("filter:"):
            continue
        if "frames" not in low or "bytes" not in low:
            continue

        # Example lines differ by tshark version/locale:
        # eth                                      frames:7366222 bytes:955900000
        #   ip                                    frames:7 366 bytes:955 MB
        proto_part = raw.split("frames", 1)[0].strip()
        proto_part = proto_part.replace("|", " ").replace("`", " ").replace("-", " ").strip()
        if not proto_part:
            continue

        proto = proto_part.split()[-1]
        m_frames = re.search(r"frames\s*:\s*([0-9][0-9\s,.\u202f\u00a0]*)", raw, flags=re.IGNORECASE)
        m_bytes = re.search(r"bytes\s*:\s*([0-9][0-9\s,.\u202f\u00a0]*)", raw, flags=re.IGNORECASE)

        if not m_frames:
            continue

        rows.append({
            "protocol": proto,
            "frames": _num(m_frames.group(1)),
            "bytes": _num(m_bytes.group(1)) if m_bytes else 0,
        })

    # Remove zero rows and duplicate protocol names by keeping the largest frame count.
    best = {}
    for row in rows:
        if not row["frames"]:
            continue
        proto = row["protocol"]
        if proto not in best or row["frames"] > best[proto]["frames"]:
            best[proto] = row

    final = list(best.values())
    final.sort(key=lambda r: r.get("frames", 0), reverse=True)
    return final[:top_limit]


def load_tshark_summary(tshark_dir: Path, top_limit: int = 25) -> dict[str, Any]:
    return {
        "capinfos": parse_capinfos(tshark_dir / "capinfos.txt"),
        "protocol_hierarchy_top": parse_protocol_hierarchy(tshark_dir / "protocol_hierarchy.txt", top_limit=top_limit),
        "raw_files": {
            path.name: str(path)
            for path in sorted(tshark_dir.glob("*.txt"))
        },
    }

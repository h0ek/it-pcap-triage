from __future__ import annotations

from pathlib import Path
from typing import Any


def parse_zeek_log(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []

    fields: list[str] | None = None
    records: list[dict[str, Any]] = []

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw:
            continue
        if raw.startswith("#fields"):
            fields = raw.split("\t")[1:]
            continue
        if raw.startswith("#"):
            continue
        if fields is None:
            continue

        values = raw.split("\t")
        row = {field: values[idx] if idx < len(values) else "" for idx, field in enumerate(fields)}
        records.append(row)

    return records


def load_zeek_logs(zeek_dir: Path) -> dict[str, list[dict[str, Any]]]:
    names = [
        "conn.log",
        "dns.log",
        "http.log",
        "ssl.log",
        "x509.log",
        "kerberos.log",
        "ntlm.log",
        "smb_files.log",
        "smb_mapping.log",
        "notice.log",
        "weird.log",
    ]
    return {name: parse_zeek_log(zeek_dir / name) for name in names}

from __future__ import annotations

import os
import shutil
from pathlib import Path


REQUIRED_BINARIES = ["zeek", "suricata", "tshark", "capinfos"]

SURICATA_CONFIG_CANDIDATES = [
    "/etc/suricata/suricata.yaml",
    "/usr/local/etc/suricata/suricata.yaml",
    "/usr/share/suricata/suricata.yaml",
]


def find_binary(name: str) -> str | None:
    return shutil.which(name)


def check_binaries() -> tuple[bool, dict[str, str | None]]:
    results = {binary: find_binary(binary) for binary in REQUIRED_BINARIES}
    return all(results.values()), results


def find_suricata_config(path: str | None = None) -> tuple[bool, str, str]:
    """
    Returns:
      ok, path, status

    status:
      ok
      not_found
      not_file
      not_readable
    """
    candidates = [path] if path else SURICATA_CONFIG_CANDIDATES

    for candidate_raw in candidates:
        if not candidate_raw:
            continue

        candidate = Path(candidate_raw)

        if not candidate.exists():
            continue

        if not candidate.is_file():
            return False, str(candidate), "not_file"

        if not os.access(candidate, os.R_OK):
            return False, str(candidate), "not_readable"

        return True, str(candidate), "ok"

    fallback = path or SURICATA_CONFIG_CANDIDATES[0]
    return False, fallback, "not_found"


def check_suricata_config(path: str | None = None) -> tuple[bool, str]:
    ok, config_path, _status = find_suricata_config(path)
    return ok, config_path

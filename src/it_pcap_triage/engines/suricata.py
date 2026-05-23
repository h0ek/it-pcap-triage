from __future__ import annotations

from pathlib import Path
from ..utils import ensure_dir, run_cmd


def run_suricata(pcap: Path, out_dir: Path, log_file: Path, config_path: str) -> float:
    ensure_dir(out_dir)
    return run_cmd(
        [
            "suricata",
            "-r", str(pcap.resolve()),
            "-c", config_path,
            "-l", str(out_dir.resolve()),
            "-k", "none",
        ],
        cwd=None,
        log_file=log_file,
    )

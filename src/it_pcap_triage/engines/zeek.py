from __future__ import annotations

from pathlib import Path
from ..utils import ensure_dir, run_cmd


def run_zeek(pcap: Path, out_dir: Path, log_file: Path) -> float:
    ensure_dir(out_dir)
    return run_cmd(["zeek", "-r", str(pcap.resolve())], cwd=out_dir, log_file=log_file)

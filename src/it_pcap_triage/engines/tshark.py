from __future__ import annotations

import subprocess
import time
from pathlib import Path
from ..utils import ensure_dir, human_duration


def _capture(cmd: list[str], output_file: Path, log_file: Path) -> float:
    start = time.perf_counter()
    with log_file.open("a", encoding="utf-8") as log:
        log.write(f"\n$ {' '.join(cmd)} > {output_file}\n")
        log.flush()
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        elapsed = time.perf_counter() - start
        output_file.write_text(proc.stdout, encoding="utf-8", errors="replace")
        log.write(f"[exit_code] {proc.returncode}\n")
        log.write(f"[elapsed] {human_duration(elapsed)}\n")
        log.flush()
        if proc.returncode != 0:
            raise RuntimeError(f"Command failed with exit code {proc.returncode}: {' '.join(cmd)}")
    return elapsed


def run_tshark_summary(pcap: Path, out_dir: Path, log_file: Path) -> dict[str, float]:
    """
    TShark is intentionally used only for compact capture summaries.

    Heavy raw conversation/endpoints dumps are not generated. Conversation and endpoint
    summaries are calculated from Zeek conn.log instead, which is more suitable for
    report generation and avoids massive HTML/raw output.
    """
    ensure_dir(out_dir)
    pcap_s = str(pcap.resolve())

    commands = {
        "capinfos.txt": ["capinfos", pcap_s],
        "protocol_hierarchy.txt": ["tshark", "-r", pcap_s, "-q", "-z", "io,phs"],
    }

    timings: dict[str, float] = {}
    for filename, cmd in commands.items():
        timings[filename] = _capture(cmd, out_dir / filename, log_file)

    return timings

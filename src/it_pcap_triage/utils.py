from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from pathlib import Path
from typing import Any


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")


def human_duration(seconds: float) -> str:
    seconds_i = int(seconds)
    hours, rem = divmod(seconds_i, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def human_bytes(value: int | float | str | None) -> str:
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        size = 0.0
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"


def run_cmd(cmd: list[str], cwd: Path | None, log_file: Path, timeout: int | None = None) -> float:
    start = time.perf_counter()
    with log_file.open("a", encoding="utf-8") as log:
        log.write(f"\n$ {' '.join(cmd)}\n")
        log.flush()
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - start
        log.write(f"[exit_code] {proc.returncode}\n")
        log.write(f"[elapsed] {human_duration(elapsed)}\n")
        log.flush()
        if proc.returncode != 0:
            raise RuntimeError(f"Command failed with exit code {proc.returncode}: {' '.join(cmd)}")
    return elapsed


def is_ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)
    except ValueError:
        return False


def safe_int(value: str | int | None, default: int = 0) -> int:
    try:
        if value is None or value == "-":
            return default
        return int(float(str(value)))
    except (ValueError, TypeError):
        return default


def safe_float(value: str | float | None, default: float = 0.0) -> float:
    try:
        if value is None or value == "-":
            return default
        return float(str(value))
    except (ValueError, TypeError):
        return default

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .checks.dependencies import check_binaries, find_suricata_config
from .config import load_config
from .analyzer import analyze


def _print_suricata_fix(config_path: str) -> None:
    parent = Path(config_path).parent
    print("        Fix:")
    print(f"        sudo chmod 755 {parent}")
    print(f"        sudo chmod 644 {config_path}")


def cmd_check(args: argparse.Namespace) -> int:
    ok_bins, binaries = check_binaries()
    ok_suricata_cfg, suricata_cfg, suricata_status = find_suricata_config(args.suricata_config)

    print("Dependency check\n")
    for name, path in binaries.items():
        if path:
            print(f"[OK] {name}: {path}")
        else:
            print(f"[ERROR] {name}: not found")

    if ok_suricata_cfg:
        print(f"[OK] suricata config: {suricata_cfg}")
    else:
        if suricata_status == "not_readable":
            print(f"[ERROR] suricata config exists but is not readable: {suricata_cfg}")
            _print_suricata_fix(suricata_cfg)
        elif suricata_status == "not_file":
            print(f"[ERROR] suricata config path is not a file: {suricata_cfg}")
        else:
            print(f"[ERROR] suricata config not found: {suricata_cfg}")

    if ok_bins and ok_suricata_cfg:
        print("\nReady.")
        return 0

    print("\nAnalysis cannot continue until required dependencies are available.")
    return 1


def cmd_analyze(args: argparse.Namespace) -> int:
    pcap = Path(args.pcap)
    out_dir = Path(args.out)

    if not pcap.is_file():
        print(f"[ERROR] PCAP not found or not readable: {pcap}", file=sys.stderr)
        return 3

    ok_bins, binaries = check_binaries()
    ok_suricata_cfg, suricata_cfg, suricata_status = find_suricata_config(args.suricata_config)

    if not ok_bins:
        for name, path in binaries.items():
            if not path:
                print(f"[ERROR] Missing required dependency: {name}", file=sys.stderr)
        return 1

    if not ok_suricata_cfg:
        if suricata_status == "not_readable":
            print(f"[ERROR] Suricata config exists but is not readable: {suricata_cfg}", file=sys.stderr)
            print(f"[FIX] sudo chmod 755 {Path(suricata_cfg).parent}", file=sys.stderr)
            print(f"[FIX] sudo chmod 644 {suricata_cfg}", file=sys.stderr)
        elif suricata_status == "not_file":
            print(f"[ERROR] Suricata config path is not a file: {suricata_cfg}", file=sys.stderr)
        else:
            print(f"[ERROR] Suricata config not found: {suricata_cfg}", file=sys.stderr)
        return 2

    config = load_config(args.config)

    try:
        analyze(
            pcap=pcap,
            out_dir=out_dir,
            config=config,
            suricata_config=suricata_cfg,
        )
    except Exception as exc:
        print(f"[ERROR] Analysis failed: {exc}", file=sys.stderr)
        print(f"[INFO] See run log if created: {out_dir / 'logs' / 'run.log'}", file=sys.stderr)
        return 4

    print(f"[OK] Report generated: {out_dir / 'report.html'}")
    print(f"[OK] Evidence DB: {out_dir / 'triage.db'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="it-pcap-triage",
        description="Offline IT PCAP analyzer using Zeek, Suricata and compact tshark summaries.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Check required local dependencies.")
    check.add_argument("--suricata-config", default=None, help="Path to suricata.yaml. Default: auto-detect common system paths")
    check.set_defaults(func=cmd_check)

    analyze_p = sub.add_parser("analyze", help="Analyze a PCAP/PCAPNG file and generate a compact security report.")
    analyze_p.add_argument("pcap", help="Path to PCAP/PCAPNG file.")
    analyze_p.add_argument("--out", default="out/report", help="Output directory.")
    analyze_p.add_argument("--config", default=None, help="Project policy config YAML.")
    analyze_p.add_argument("--suricata-config", default=None, help="Path to suricata.yaml. Default: auto-detect common system paths")
    analyze_p.set_defaults(func=cmd_analyze)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()

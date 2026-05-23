from __future__ import annotations

import time
from pathlib import Path

from .engines.zeek import run_zeek
from .engines.suricata import run_suricata
from .engines.tshark import run_tshark_summary
from .parsers.zeek_logs import load_zeek_logs
from .parsers.suricata_eve import load_eve, split_eve
from .parsers.tshark_stats import load_tshark_summary
from .detectors.cleartext_auth import detect_cleartext_auth
from .detectors.insecure_protocols import detect_insecure_protocols
from .detectors.dns_anomalies import detect_dns_anomalies
from .detectors.tls_hygiene import detect_tls_hygiene
from .detectors.windows_auth import detect_windows_auth
from .detectors.scanning import detect_scanning
from .detectors.suricata_alerts import detect_suricata_alerts
from .detectors.exfiltration import detect_large_outbound
from .scoring.risk import sort_findings, build_host_profiles
from .report.html import render_report
from .stats import zeek_network_stats
from .storage.sqlite_store import EvidenceStore
from .references import enrich_findings_with_references, load_reference_catalog
from .utils import ensure_dir, write_json, human_duration


def _stage(label: str) -> None:
    print(label, flush=True)


def analyze(
    pcap: Path,
    out_dir: Path,
    config: dict,
    suricata_config: str,
) -> None:
    total_start = time.perf_counter()
    ensure_dir(out_dir)

    logs_dir = out_dir / "logs"
    engines_dir = out_dir / "engines"
    zeek_dir = engines_dir / "zeek"
    suricata_dir = engines_dir / "suricata"
    tshark_dir = engines_dir / "tshark"
    ensure_dir(logs_dir)
    ensure_dir(engines_dir)

    run_log = logs_dir / "run.log"
    run_log.write_text("", encoding="utf-8")

    timings: dict[str, object] = {}

    _stage("[1/5] Running Zeek behavioral analysis...")
    timings["zeek"] = run_zeek(pcap, zeek_dir, run_log)

    _stage("[2/5] Running Suricata IDS analysis...")
    timings["suricata"] = run_suricata(pcap, suricata_dir, run_log, suricata_config)

    _stage("[3/5] Running capture/protocol summary...")
    tshark_timings = run_tshark_summary(pcap, tshark_dir, run_log)
    timings["tshark_summary"] = sum(tshark_timings.values())
    timings["tshark_files"] = tshark_timings

    _stage("[4/5] Parsing, correlating and storing evidence...")
    parse_start = time.perf_counter()
    zeek = load_zeek_logs(zeek_dir)
    eve = load_eve(suricata_dir / "eve.json")
    eve_by_type = split_eve(eve)
    top_limit = int(config.get("report", {}).get("top_limit", 25))
    tshark_summary = load_tshark_summary(tshark_dir, top_limit=top_limit)
    zeek_stats = zeek_network_stats(zeek, config=config, top_limit=top_limit)

    findings = []
    findings.extend(detect_cleartext_auth(zeek, eve_by_type, config))
    findings.extend(detect_insecure_protocols(zeek, tshark_summary, config))
    findings.extend(detect_dns_anomalies(zeek, eve_by_type, config))
    findings.extend(detect_tls_hygiene(zeek, eve_by_type, config))
    findings.extend(detect_windows_auth(zeek, config))
    findings.extend(detect_scanning(zeek, config))
    findings.extend(detect_suricata_alerts(eve_by_type, config))
    findings.extend(detect_large_outbound(zeek, config))
    findings = enrich_findings_with_references(sort_findings(findings))

    hosts = build_host_profiles(zeek, findings, eve_by_type)
    timings["parsing_and_detection"] = time.perf_counter() - parse_start

    db_path = out_dir / "triage.db"
    if db_path.exists():
        db_path.unlink()
    store = EvidenceStore(db_path)
    store.set_meta("pcap", str(pcap))
    store.set_meta("timings", timings)
    store.insert_reference_catalog(load_reference_catalog())
    store.insert_stat("tshark_summary", tshark_summary)
    store.insert_stat("zeek_network_stats", zeek_stats)
    for finding in findings:
        store.insert_finding(finding)
    for host in hosts:
        store.insert_host(host)
    for event in eve_by_type.get("alert", []):
        store.insert_suricata_alert(event)
    store.commit()
    store.close()

    _stage("[5/5] Generating compact report...")
    report_start = time.perf_counter()
    write_json(out_dir / "findings.json", [f.to_dict() for f in findings])
    write_json(out_dir / "hosts.json", [h.to_dict() for h in hosts])
    write_json(out_dir / "summary.json", {
        "pcap": str(pcap),
        "finding_count": len(findings),
        "host_count": len(hosts),
        "timings": timings,
        "tshark_summary": tshark_summary,
        "zeek_network_stats": zeek_stats,
        "evidence_db": str(db_path),
    })

    render_report(
        out_dir / "report.html",
        pcap,
        findings,
        hosts,
        tshark_summary,
        zeek_stats,
        config,
        timings=timings,
        db_path=db_path,
    )
    timings["report_generation"] = time.perf_counter() - report_start
    timings["total"] = time.perf_counter() - total_start

    write_json(out_dir / "timings.json", timings)

    _stage(f"[OK] Analysis completed in {human_duration(timings['total'])}")

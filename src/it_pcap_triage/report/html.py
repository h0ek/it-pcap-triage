from __future__ import annotations

from pathlib import Path
from jinja2 import Environment, PackageLoader, select_autoescape

from ..model.finding import Finding
from ..model.host import HostProfile
from ..scoring.risk import overall_score
from ..utils import human_bytes, human_duration


def _bar_width(value: int | float, max_value: int | float) -> int:
    try:
        if not max_value:
            return 0
        return max(1, min(100, int((float(value) / float(max_value)) * 100)))
    except Exception:
        return 0


def render_report(
    out_file: Path,
    pcap: Path,
    findings: list[Finding],
    hosts: list[HostProfile],
    tshark_summary: dict,
    zeek_stats: dict,
    config: dict,
    timings: dict[str, object] | None = None,
    db_path: Path | None = None,
) -> None:
    env = Environment(
        loader=PackageLoader("it_pcap_triage", "report/templates"),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["human_bytes"] = human_bytes
    env.globals["bar_width"] = _bar_width

    template = env.get_template("report.html")
    html = template.render(
        title=config.get("project", {}).get("name", "IT PCAP Triage"),
        pcap=str(pcap),
        findings=findings,
        hosts=hosts[:50],
        score=overall_score(findings),
        tshark_summary=tshark_summary,
        zeek_stats=zeek_stats,
        timings=timings or {},
        db_path=str(db_path) if db_path else "",
        human_duration=human_duration,
        severity_counts={
            sev: len([f for f in findings if f.severity == sev])
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        },
    )
    out_file.write_text(html, encoding="utf-8")

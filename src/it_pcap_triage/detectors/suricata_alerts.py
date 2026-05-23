from __future__ import annotations

from collections import Counter
from ..model.finding import Finding


def detect_suricata_alerts(eve_by_type: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    alerts = eve_by_type.get("alert", [])
    if not alerts:
        return findings

    severities = Counter()
    hosts = Counter()
    samples = []

    for event in alerts:
        alert = event.get("alert", {})
        severity = alert.get("severity", "unknown")
        severities[str(severity)] += 1
        if event.get("src_ip"):
            hosts[event["src_ip"]] += 1
        if len(samples) < 20:
            samples.append({
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "src_port": event.get("src_port"),
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "signature": alert.get("signature"),
                "category": alert.get("category"),
                "severity": severity,
            })

    max_sev = min([int(k) for k in severities if str(k).isdigit()] or [3])
    mapped_sev = "HIGH" if max_sev <= 2 else "MEDIUM"

    findings.append(Finding(
        title="Suricata IDS alerts observed",
        severity=mapped_sev,
        confidence="HIGH",
        category="Suricata/IDS",
        data_source="Suricata eve.json",
        affected_hosts=[host for host, _ in hosts.most_common(25)],
        description="Suricata generated IDS alerts for traffic in this capture.",
        recommendation="Review alert signatures, affected hosts and payload context. Validate true positives before containment actions.",
        evidence={
            "alert_count": len(alerts),
            "severity_counts": dict(severities),
            "top_source_hosts": hosts.most_common(10),
            "samples": samples,
        },
    ))

    return findings

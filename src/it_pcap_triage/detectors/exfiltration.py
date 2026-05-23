from __future__ import annotations

from collections import defaultdict
from ..model.finding import Finding
from ..utils import safe_int, is_ip_in_cidrs


def detect_large_outbound(zeek: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    conn_rows = zeek.get("conn.log", [])
    internal_cidrs = config.get("network", {}).get("internal_cidrs", [])
    threshold = config.get("thresholds", {}).get("large_outbound_bytes", 104857600)

    sent_external = defaultdict(int)

    for row in conn_rows:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        bytes_sent = safe_int(row.get("orig_bytes"))
        if src and dst and is_ip_in_cidrs(src, internal_cidrs) and not is_ip_in_cidrs(dst, internal_cidrs):
            sent_external[src] += bytes_sent

    large = {host: total for host, total in sent_external.items() if total >= threshold}
    if large:
        findings.append(Finding(
            title="Large outbound data transfer observed",
            severity="MEDIUM",
            confidence="LOW",
            category="Data Movement",
            data_source="Zeek conn.log",
            affected_hosts=sorted(large),
            description="One or more internal hosts sent a large volume of data to external destinations within the capture.",
            recommendation="Validate whether this is expected business traffic, backup, cloud sync, update traffic or possible exfiltration.",
            evidence=large,
        ))

    return findings

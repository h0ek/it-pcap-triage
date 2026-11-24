from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address
from ..model.finding import Finding
from ..utils import safe_int, is_ip_in_cidrs


def detect_large_outbound(zeek: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    conn_rows = zeek.get("conn.log", [])
    internal_cidrs = config.get("network", {}).get("internal_cidrs", [])
    threshold = config.get("thresholds", {}).get("large_outbound_bytes", 104857600)

    sent_external = defaultdict(int)

    def external(ip):
        try:
            addr = ip_address(ip)
            return not is_ip_in_cidrs(ip, internal_cidrs) and not (addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_link_local or addr.is_reserved)
        except ValueError:
            return False

    for row in conn_rows:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        bytes_sent = safe_int(row.get("orig_bytes"))
        if src and dst and is_ip_in_cidrs(src, internal_cidrs) and external(dst):
            sent_external[src] += bytes_sent
        elif src and dst and is_ip_in_cidrs(dst, internal_cidrs) and external(src):
            sent_external[dst] += safe_int(row.get("resp_bytes"))

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

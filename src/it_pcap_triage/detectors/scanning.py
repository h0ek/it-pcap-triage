from __future__ import annotations

from collections import defaultdict
from ..model.finding import Finding
from ..utils import safe_int, is_ip_in_cidrs


def _sample_dsts(mapping: dict[str, set[str]], src: str, limit: int = 25) -> list[str]:
    return sorted(mapping[src])[:limit]


def detect_scanning(zeek: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    conn_rows = zeek.get("conn.log", [])
    thresholds = config.get("thresholds", {})
    internal_cidrs = config.get("network", {}).get("internal_cidrs", [])

    dst_hosts_by_src: dict[str, set[str]] = defaultdict(set)
    dst_ports_by_src: dict[str, set[int]] = defaultdict(set)
    smb_hosts_by_src: dict[str, set[str]] = defaultdict(set)

    for row in conn_rows:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        port = safe_int(row.get("id.resp_p"))
        if not src or not dst or port == 0:
            continue

        dst_hosts_by_src[src].add(dst)
        dst_ports_by_src[src].add(port)

        if port == 445 and is_ip_in_cidrs(dst, internal_cidrs):
            smb_hosts_by_src[src].add(dst)

    horizontal = [src for src, dsts in dst_hosts_by_src.items() if len(dsts) >= thresholds.get("scan_unique_hosts", 30)]
    if horizontal:
        evidence = {}
        for src in horizontal[:50]:
            evidence[src] = {
                "source": src,
                "unique_destination_hosts": len(dst_hosts_by_src[src]),
                "destination_samples": _sample_dsts(dst_hosts_by_src, src),
                "wireshark_filter": f"ip.src == {src}",
            }
        findings.append(Finding(
            title="Horizontal scanning pattern observed",
            severity="MEDIUM",
            confidence="MEDIUM",
            category="Scanning/Lateral Movement",
            data_source="Zeek conn.log",
            affected_hosts=sorted(horizontal),
            description="One or more source hosts connected to many unique destination hosts within the capture.",
            recommendation="Validate whether these source hosts are approved scanners, monitoring systems or management servers.",
            evidence=evidence,
        ))

    vertical = [src for src, ports in dst_ports_by_src.items() if len(ports) >= thresholds.get("scan_unique_ports", 20)]
    if vertical:
        evidence = {}
        for src in vertical[:50]:
            evidence[src] = {
                "source": src,
                "unique_destination_ports": len(dst_ports_by_src[src]),
                "destination_port_samples": sorted(dst_ports_by_src[src])[:50],
                "wireshark_filter": f"ip.src == {src}",
            }
        findings.append(Finding(
            title="Vertical port scanning pattern observed",
            severity="MEDIUM",
            confidence="MEDIUM",
            category="Scanning/Lateral Movement",
            data_source="Zeek conn.log",
            affected_hosts=sorted(vertical),
            description="One or more source hosts connected to many unique destination ports.",
            recommendation="Validate whether this is approved scanning or unexpected reconnaissance.",
            evidence=evidence,
        ))

    smb_fanout = [src for src, dsts in smb_hosts_by_src.items() if len(dsts) >= thresholds.get("smb_fanout_hosts", 25)]
    if smb_fanout:
        evidence = {}
        for src in smb_fanout[:50]:
            evidence[src] = {
                "source": src,
                "destination_port": 445,
                "unique_smb_destination_hosts": len(smb_hosts_by_src[src]),
                "destination_samples": _sample_dsts(smb_hosts_by_src, src),
                "wireshark_filter": f"ip.src == {src} && tcp.dstport == 445",
            }
        findings.append(Finding(
            title="SMB fan-out pattern observed",
            severity="HIGH",
            confidence="MEDIUM",
            category="Scanning/Lateral Movement",
            data_source="Zeek conn.log",
            affected_hosts=sorted(smb_fanout),
            description="One or more source hosts initiated SMB connections to many internal destination hosts. This can indicate admin activity, vulnerability scanning, software deployment or malware/ransomware-like propagation.",
            recommendation="Validate whether affected source hosts are approved scanners or management systems. Investigate immediately if unexpected.",
            evidence=evidence,
        ))

    return findings

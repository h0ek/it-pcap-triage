from __future__ import annotations

from collections import Counter, defaultdict, deque
from math import isfinite
from ..model.finding import Finding
from ..utils import safe_float, safe_int, is_ip_in_cidrs


def _peak(events, seconds):
    counts = Counter()
    queue = deque()
    best = set()
    for ts, value in sorted(events):
        while queue and ts - queue[0][0] >= seconds:
            _, old = queue.popleft()
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
        queue.append((ts, value))
        counts[value] += 1
        if len(counts) > len(best):
            best = set(counts)
    return best


def detect_scanning(zeek: dict, config: dict) -> list[Finding]:
    thresholds = config.get("thresholds", {})
    window = thresholds.get("scan_window_seconds", 60)
    if window <= 0:
        raise ValueError("scan_window_seconds must be positive")
    internal = config.get("network", {}).get("internal_cidrs", [])
    horizontal, vertical, smb = defaultdict(list), defaultdict(list), defaultdict(list)
    for row in zeek.get("conn.log", []):
        src, dst = row.get("id.orig_h"), row.get("id.resp_h")
        port = safe_int(row.get("id.resp_p"))
        ts = safe_float(row.get("ts"), float("nan"))
        transport = str(row.get("proto", "tcp")).lower()
        if not src or not dst or not port or not isfinite(ts) or transport not in {"tcp", "udp"}:
            continue
        horizontal[(src, port, transport)].append((ts, dst))
        vertical[(src, dst, transport)].append((ts, port))
        if port == 445 and transport == "tcp" and is_ip_in_cidrs(dst, internal):
            smb[(src, port, transport)].append((ts, dst))
    findings = []
    for groups, key, default, title, severity in (
        (horizontal, "scan_unique_hosts", 30, "Horizontal scanning pattern observed", "MEDIUM"),
        (vertical, "scan_unique_ports", 20, "Vertical port scanning pattern observed", "MEDIUM"),
        (smb, "smb_fanout_hosts", 25, "SMB fan-out pattern observed", "HIGH"),
    ):
        samples, hosts = [], set()
        for (src, target, transport), events in groups.items():
            peak = _peak(events, window)
            if len(peak) >= thresholds.get(key, default):
                hosts.add(src)
                if len(samples) < 50:
                    samples.append({"source": src, "destination" if key == "scan_unique_ports" else "destination_port": target, "transport": transport, "unique_count": len(peak), "samples": sorted(peak)[:50]})
        if hosts:
            findings.append(Finding(title=title, severity=severity, confidence="MEDIUM", category="Scanning/Lateral Movement", data_source="Zeek conn.log", affected_hosts=sorted(hosts), description=f"Multiple distinct targets were contacted within a rolling {window}-second window. This is a behavioral indicator, not proof of scanning.", recommendation="Validate whether activity is approved scanning, monitoring, deployment or unexpected reconnaissance.", evidence={"window_seconds": window, "groups": samples}))
    return findings

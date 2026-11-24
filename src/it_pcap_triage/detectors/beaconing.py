from collections import defaultdict
from math import isfinite
from statistics import median

from ..model.finding import Finding
from ..utils import safe_float, safe_int


def detect_beaconing(zeek, config):
    thresholds = config.get("thresholds", {})
    minimum = max(3, int(thresholds.get("beacon_min_connections", 10)))
    jitter = thresholds.get("beacon_jitter_percent", 20) / 100
    groups = defaultdict(set)
    for row in zeek.get("conn.log", []):
        src, dst = row.get("id.orig_h"), row.get("id.resp_h")
        port = safe_int(row.get("id.resp_p"))
        ts = safe_float(row.get("ts"), float("nan"))
        if src and dst and port and port not in {53, 123, 67, 68} and isfinite(ts):
            groups[(src, dst, port, row.get("proto", ""))].add(ts)
    hosts, samples = set(), []
    for (src, dst, port, transport), times in groups.items():
        if len(times) < minimum:
            continue
        ordered = sorted(times)
        gaps = [b - a for a, b in zip(ordered, ordered[1:])]
        interval = median(gaps)
        if interval < 1 or not all(abs(gap - interval) <= interval * jitter for gap in gaps):
            continue
        hosts.add(src)
        if len(samples) < 50:
            samples.append({"source": src, "destination": dst, "port": port, "transport": transport, "connections": len(times), "median_interval_seconds": interval})
    if not hosts:
        return []
    return [Finding(title="Possible periodic beaconing observed", severity="MEDIUM", confidence="LOW", category="Network Behavior", data_source="Zeek conn.log", affected_hosts=sorted(hosts), description="Repeated connection starts at regular intervals were observed. Legitimate polling and keepalives can produce the same pattern.", recommendation="Review destination ownership and process context before attributing activity to malware.", evidence={"groups": samples})]

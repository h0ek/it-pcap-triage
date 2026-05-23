from __future__ import annotations

from collections import defaultdict
from ..model.finding import Finding, SEVERITY_ORDER
from ..model.host import HostProfile
from ..utils import safe_int


SEVERITY_POINTS = {
    "CRITICAL": 100,
    "HIGH": 60,
    "MEDIUM": 30,
    "LOW": 10,
    "INFO": 0,
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)


def overall_score(findings: list[Finding]) -> int:
    if not findings:
        return 0
    score = sum(SEVERITY_POINTS.get(f.severity, 0) for f in findings)
    return min(score, 100)


def build_host_profiles(zeek: dict, findings: list[Finding], eve_by_type: dict) -> list[HostProfile]:
    profiles: dict[str, HostProfile] = {}

    def host(ip: str) -> HostProfile:
        if ip not in profiles:
            profiles[ip] = HostProfile(ip=ip)
        return profiles[ip]

    for row in zeek.get("conn.log", []):
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        service = row.get("service", "")
        port = safe_int(row.get("id.resp_p"))
        orig_bytes = safe_int(row.get("orig_bytes"))
        resp_bytes = safe_int(row.get("resp_bytes"))

        if src:
            h = host(src)
            if service and service != "-":
                h.protocols.add(service)
            if port:
                h.ports_contacted.add(port)
            if dst:
                h.peers.add(dst)
            h.bytes_sent += orig_bytes
            h.bytes_received += resp_bytes

        if dst:
            h2 = host(dst)
            if src:
                h2.peers.add(src)
            h2.bytes_received += orig_bytes
            h2.bytes_sent += resp_bytes

    for finding in findings:
        points = SEVERITY_POINTS.get(finding.severity, 0)
        for ip in finding.affected_hosts:
            if not ip:
                continue
            h = host(ip)
            h.finding_titles.append(finding.title)
            h.risk_score += points

    for event in eve_by_type.get("alert", []):
        for ip in [event.get("src_ip"), event.get("dest_ip")]:
            if ip:
                h = host(ip)
                h.suricata_alerts += 1
                h.risk_score += 10

    return sorted(profiles.values(), key=lambda h: h.risk_score, reverse=True)

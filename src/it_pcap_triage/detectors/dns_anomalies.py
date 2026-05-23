from __future__ import annotations

import math
from collections import Counter, defaultdict
from ..model.finding import Finding
from ..utils import is_ip_in_cidrs


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def detect_dns_anomalies(zeek: dict, eve_by_type: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    dns_rows = zeek.get("dns.log", [])
    if not dns_rows:
        return findings

    thresholds = config.get("thresholds", {})
    network = config.get("network", {})
    internal_cidrs = network.get("internal_cidrs", [])
    allowed_dns = set(network.get("dns_servers", []) or [])

    queries_by_host = defaultdict(list)
    long_domains = []
    high_entropy = []
    nxdomain_by_host = Counter()

    for row in dns_rows:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        query = row.get("query", "")
        rcode = str(row.get("rcode_name", "")).upper()
        if src and query:
            queries_by_host[src].append(query)
        if query and len(max(query.split("."), key=len, default="")) >= thresholds.get("dns_long_label_length", 50):
            long_domains.append({"src": src, "query": query})
        if query and _entropy(query.replace(".", "")) >= thresholds.get("dns_entropy_threshold", 4.0):
            high_entropy.append({"src": src, "query": query})
        if rcode == "NXDOMAIN":
            nxdomain_by_host[src] += 1

        if allowed_dns and is_ip_in_cidrs(src, internal_cidrs) and dst and dst not in allowed_dns:
            findings.append(Finding(
                title="Unauthorized DNS resolver used",
                severity="MEDIUM",
                confidence="HIGH",
                category="DNS",
                data_source="Zeek dns.log",
                affected_hosts=[src],
                description=f"Internal host {src} queried DNS server {dst}, which is not in the configured allowed DNS server list.",
                recommendation="Force clients to use approved internal resolvers and block direct DNS egress where appropriate.",
                evidence={"src": src, "dns_server": dst},
            ))
            break

    noisy_hosts = [host for host, queries in queries_by_host.items() if len(queries) >= thresholds.get("dns_queries_per_minute", 300)]
    if noisy_hosts:
        findings.append(Finding(
            title="High DNS query volume observed",
            severity="MEDIUM",
            confidence="MEDIUM",
            category="DNS",
            data_source="Zeek dns.log",
            affected_hosts=sorted(noisy_hosts),
            description="One or more hosts generated high DNS query volume within the capture.",
            recommendation="Validate whether this is expected application behavior, misconfiguration, DNS brute forcing, malware, or tunneling.",
            evidence={"hosts": sorted(noisy_hosts)[:25]},
        ))

    if long_domains or high_entropy:
        hosts = sorted({item["src"] for item in long_domains + high_entropy if item.get("src")})
        findings.append(Finding(
            title="Possible DNS tunneling indicators",
            severity="HIGH",
            confidence="MEDIUM",
            category="DNS",
            data_source="Zeek dns.log",
            affected_hosts=hosts,
            description="Long DNS labels and/or high-entropy DNS names were observed. This may indicate DNS tunneling, DGA, tracking, or unusual application behavior.",
            recommendation="Investigate the affected hosts and domains. Validate whether the domains belong to approved software/services.",
            evidence={
                "long_domain_samples": long_domains[:10],
                "high_entropy_samples": high_entropy[:10],
            },
            mappings={"MITRE ATT&CK": ["T1071.004"]},
        ))

    nx_hosts = [host for host, count in nxdomain_by_host.items() if count >= 50]
    if nx_hosts:
        findings.append(Finding(
            title="Excessive NXDOMAIN responses observed",
            severity="MEDIUM",
            confidence="MEDIUM",
            category="DNS",
            data_source="Zeek dns.log",
            affected_hosts=sorted(nx_hosts),
            description="Hosts generated many DNS queries resulting in NXDOMAIN responses.",
            recommendation="Investigate for typo-heavy applications, DGA-like behavior, broken resolvers, or DNS discovery activity.",
            evidence={"hosts": {h: nxdomain_by_host[h] for h in nx_hosts[:25]}},
        ))

    return findings

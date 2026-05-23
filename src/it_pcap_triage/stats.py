from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from .utils import safe_int, is_ip_in_cidrs


def zeek_network_stats(zeek: dict, config: dict | None = None, top_limit: int = 25) -> dict[str, Any]:
    conn = zeek.get("conn.log", [])
    dns = zeek.get("dns.log", [])
    http = zeek.get("http.log", [])
    ssl = zeek.get("ssl.log", [])
    alerts = []

    cfg = config or {}
    internal_cidrs = cfg.get("network", {}).get("internal_cidrs", [])

    top_talkers = Counter()
    top_services = Counter()
    top_ports = Counter()
    top_pairs = Counter()
    top_conversations_bytes = Counter()
    bytes_by_src = Counter()
    packets_by_src = Counter()
    endpoint_bytes = Counter()
    internal_hosts = set()
    external_hosts = set()
    service_by_src = defaultdict(Counter)
    ports_by_src = defaultdict(Counter)

    for row in conn:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        service = row.get("service", "")
        port = row.get("id.resp_p", "")
        proto = row.get("proto", "")
        orig_bytes = safe_int(row.get("orig_bytes"))
        resp_bytes = safe_int(row.get("resp_bytes"))
        total_bytes = orig_bytes + resp_bytes
        orig_pkts = safe_int(row.get("orig_pkts"))
        resp_pkts = safe_int(row.get("resp_pkts"))
        total_pkts = orig_pkts + resp_pkts

        for ip in [src, dst]:
            if not ip:
                continue
            if is_ip_in_cidrs(ip, internal_cidrs):
                internal_hosts.add(ip)
            else:
                external_hosts.add(ip)

        if src:
            top_talkers[src] += 1
            bytes_by_src[src] += orig_bytes
            packets_by_src[src] += total_pkts
            endpoint_bytes[src] += total_bytes
        if dst:
            endpoint_bytes[dst] += total_bytes

        if service and service != "-":
            top_services[service] += 1
            if src:
                service_by_src[src][service] += 1

        if port and port != "-":
            top_ports[str(port)] += 1
            if src:
                ports_by_src[src][str(port)] += 1

        if src and dst:
            pair = f"{src} -> {dst}"
            top_pairs[pair] += 1
            top_conversations_bytes[pair] += total_bytes

    dns_queries = Counter(row.get("query", "") for row in dns if row.get("query") not in ("", "-"))
    http_hosts = Counter(row.get("host", "") for row in http if row.get("host") not in ("", "-"))
    tls_sni = Counter(row.get("server_name", "") for row in ssl if row.get("server_name") not in ("", "-"))

    top_host_services = []
    for host, counter in service_by_src.items():
        top_host_services.append({
            "host": host,
            "services": counter.most_common(8),
            "total": sum(counter.values()),
        })
    top_host_services.sort(key=lambda x: x["total"], reverse=True)

    return {
        "connection_count": len(conn),
        "dns_query_count": len(dns),
        "http_request_count": len(http),
        "tls_session_count": len(ssl),
        "internal_host_count": len(internal_hosts),
        "external_host_count": len(external_hosts),
        "top_talkers": top_talkers.most_common(top_limit),
        "top_services": top_services.most_common(top_limit),
        "top_ports": top_ports.most_common(top_limit),
        "top_pairs": top_pairs.most_common(top_limit),
        "top_conversations_by_bytes": top_conversations_bytes.most_common(top_limit),
        "top_endpoints_by_bytes": endpoint_bytes.most_common(top_limit),
        "top_bytes_by_source": bytes_by_src.most_common(top_limit),
        "top_packets_by_source": packets_by_src.most_common(top_limit),
        "top_dns_queries": dns_queries.most_common(top_limit),
        "top_http_hosts": http_hosts.most_common(top_limit),
        "top_tls_sni": tls_sni.most_common(top_limit),
        "top_host_services": top_host_services[:top_limit],
    }

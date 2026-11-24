from ..model.finding import Finding
from ..utils import is_ip_in_cidrs, safe_int
from .insecure_protocols import service_tokens


def detect_network_policy(zeek, config):
    network = config.get("network", {})
    findings = []
    for key, label, services, ports in (
        ("ntp_servers", "NTP", {"ntp"}, {123}),
        ("domain_controllers", "Kerberos/LDAP", {"kerberos", "ldap"}, {88, 389, 636, 3268, 3269}),
    ):
        allowed = set(network.get(key, []))
        if not allowed:
            continue
        pairs = set()
        for row in zeek.get("conn.log", []):
            src, dst = row.get("id.orig_h"), row.get("id.resp_h")
            if src and dst and is_ip_in_cidrs(src, network.get("internal_cidrs", [])) and dst not in allowed and (service_tokens(row.get("service")) & services or safe_int(row.get("id.resp_p")) in ports):
                pairs.add((src, dst))
        if pairs:
            findings.append(Finding(title=f"Possible unapproved {label} destination", severity="MEDIUM", confidence="MEDIUM", category="Network Policy", data_source="Zeek conn.log", affected_hosts=sorted({src for src, _ in pairs}), description=f"Traffic matching {label} service names or ports targeted destinations outside the configured allowlist.", recommendation="Verify service identity and the approved infrastructure list.", evidence={"pairs": sorted(pairs)[:50], "pair_count": len(pairs)}))
    return findings

from collections import Counter

from .detectors.insecure_protocols import service_tokens
from .utils import safe_int


PORTS = {
    ("tcp", 21): "FTP", ("tcp", 22): "SSH", ("tcp", 23): "Telnet", ("tcp", 25): "SMTP",
    ("tcp", 53): "DNS", ("udp", 53): "DNS", ("tcp", 80): "HTTP", ("tcp", 88): "Kerberos", ("udp", 88): "Kerberos",
    ("tcp", 110): "POP3", ("tcp", 135): "DCE/RPC endpoint mapper", ("tcp", 139): "NetBIOS session", ("tcp", 143): "IMAP",
    ("udp", 123): "NTP", ("udp", 137): "NBNS", ("udp", 138): "NetBIOS datagram", ("udp", 161): "SNMP", ("udp", 162): "SNMP trap",
    ("tcp", 179): "BGP", ("tcp", 389): "LDAP", ("udp", 389): "CLDAP", ("tcp", 443): "HTTPS", ("udp", 443): "QUIC/HTTP3",
    ("tcp", 445): "SMB", ("udp", 500): "IKE", ("udp", 4500): "IPsec NAT-T", ("udp", 514): "Syslog", ("tcp", 636): "LDAPS",
    ("udp", 69): "TFTP", ("tcp", 873): "rsync", ("tcp", 993): "IMAPS", ("tcp", 995): "POP3S", ("tcp", 587): "SMTP submission",
    ("tcp", 1194): "OpenVPN", ("udp", 1194): "OpenVPN", ("tcp", 1433): "MSSQL", ("udp", 1434): "SQL Browser",
    ("tcp", 1521): "Oracle TNS", ("tcp", 1883): "MQTT", ("tcp", 2049): "NFS", ("udp", 2049): "NFS", ("tcp", 3306): "MySQL",
    ("tcp", 3389): "RDP", ("udp", 3389): "RDP", ("udp", 1900): "SSDP", ("udp", 3702): "WS-Discovery", ("udp", 5353): "mDNS",
    ("udp", 5355): "LLMNR", ("tcp", 5432): "PostgreSQL", ("tcp", 5672): "AMQP", ("tcp", 5900): "VNC", ("tcp", 5985): "WinRM",
    ("tcp", 5986): "WinRM TLS", ("tcp", 6379): "Redis", ("tcp", 8883): "MQTT TLS", ("tcp", 9092): "Kafka", ("tcp", 27017): "MongoDB",
    ("udp", 51820): "WireGuard", ("udp", 623): "IPMI/RMCP", ("udp", 1701): "L2TP", ("tcp", 1723): "PPTP",
}


def protocol_inventory(zeek, tshark_summary):
    decoded = tshark_summary.get("protocol_hierarchy", [])
    services, candidates = Counter(), Counter()
    for row in zeek.get("conn.log", []):
        tokens = service_tokens(row.get("service"))
        services.update(tokens)
        transport = str(row.get("proto", "")).lower()
        port = safe_int(row.get("id.resp_p"))
        if not tokens and (transport, port) in PORTS:
            candidates[(transport, port)] += 1
    return {
        "decoded": decoded,
        "zeek_services": [{"name": name, "connections": count} for name, count in services.most_common()],
        "port_candidates": [{"name": PORTS[key], "transport": key[0], "port": key[1], "connections": count} for key, count in candidates.most_common()],
    }

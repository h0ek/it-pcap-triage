from __future__ import annotations

from ..model.finding import Finding


def detect_insecure_protocols(zeek: dict, tshark_summary: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    protocol_rows = tshark_summary.get("protocol_hierarchy_top", []) if isinstance(tshark_summary, dict) else []
    protocols = {str(row.get("protocol", "")).lower(): row for row in protocol_rows if isinstance(row, dict)}

    # Also use Zeek conn.log services where available.
    services = {
        str(row.get("service", "")).lower()
        for row in zeek.get("conn.log", [])
        if row.get("service") not in ("", "-")
    }

    observed = set(protocols) | services

    checks = [
        ("llmnr", "MEDIUM", "LLMNR traffic observed", "Disable LLMNR where not required. Prefer DNS with controlled internal resolvers."),
        ("nbns", "MEDIUM", "NBT-NS traffic observed", "Disable NetBIOS name service where not required and reduce spoofing/relay exposure."),
        ("mdns", "LOW", "mDNS traffic observed", "Validate whether mDNS is expected in this segment."),
        ("tftp", "MEDIUM", "TFTP traffic observed", "Remove TFTP or restrict it to controlled provisioning networks."),
        ("ftp", "HIGH", "FTP traffic observed", "Replace FTP with SFTP/FTPS or HTTPS-based transfer."),
        ("telnet", "HIGH", "Telnet traffic observed", "Replace Telnet with SSH."),
    ]

    for token, severity, title, recommendation in checks:
        if any(token in proto for proto in observed):
            findings.append(Finding(
                title=title,
                severity=severity,
                confidence="MEDIUM",
                category="Legacy/Insecure Protocols",
                data_source="Zeek conn.log / tshark protocol hierarchy",
                description=f"{token.upper()} appears in protocol statistics or Zeek service metadata.",
                recommendation=recommendation,
                evidence={
                    "protocol": token,
                    "wireshark_filter": token,
                },
            ))

    return findings

from __future__ import annotations

from ..model.finding import Finding


def detect_cleartext_auth(zeek: dict, eve_by_type: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []

    http_rows = zeek.get("http.log", [])
    auth_hosts = sorted({
        row.get("id.orig_h", "")
        for row in http_rows
        if row.get("username") not in ("", "-", None) or "Authorization" in str(row)
    })
    if auth_hosts:
        findings.append(Finding(
            title="HTTP authentication metadata observed",
            severity="MEDIUM",
            confidence="MEDIUM",
            category="Cleartext/Auth",
            data_source="Zeek http.log",
            affected_hosts=auth_hosts,
            description="HTTP authentication-related metadata was observed. If this traffic is not protected by TLS, credentials or session data may be exposed.",
            recommendation="Move authentication flows to HTTPS only. Disable Basic authentication over cleartext HTTP.",
            evidence={"hosts": auth_hosts, "sample_count": len(auth_hosts)},
        ))

    protocols = []
    conn_rows = zeek.get("conn.log", [])
    service_map = {
        "ftp": ("HIGH", "FTP traffic observed"),
        "telnet": ("HIGH", "Telnet traffic observed"),
        "pop3": ("MEDIUM", "POP3 traffic observed"),
        "imap": ("MEDIUM", "IMAP traffic observed"),
        "smtp": ("LOW", "SMTP traffic observed"),
    }

    for service, (severity, title) in service_map.items():
        rows = [row for row in conn_rows if service in str(row.get("service", "")).lower()]
        if rows:
            hosts = sorted({r.get("id.orig_h", "") for r in rows if r.get("id.orig_h")})
            protocols.append(service)
            findings.append(Finding(
                title=title,
                severity=severity,
                confidence="HIGH",
                category="Cleartext/Auth",
                data_source="Zeek conn.log",
                affected_hosts=hosts,
                description=f"{service.upper()} traffic was observed in the capture. This may indicate use of a cleartext or legacy protocol.",
                recommendation=f"Replace {service.upper()} with a secure alternative or require TLS-protected transport where applicable.",
                evidence={"connections": len(rows), "hosts": hosts[:25]},
            ))

    return findings

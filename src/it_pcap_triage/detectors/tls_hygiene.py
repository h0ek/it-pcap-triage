from __future__ import annotations

from ..model.finding import Finding


def detect_tls_hygiene(zeek: dict, eve_by_type: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    ssl_rows = zeek.get("ssl.log", [])
    x509_rows = zeek.get("x509.log", [])

    old_tls = []
    for row in ssl_rows:
        version = str(row.get("version", "")).lower()
        if "tlsv10" in version or "tlsv11" in version or "ssl" in version:
            old_tls.append(row)

    if old_tls:
        hosts = sorted({r.get("id.orig_h", "") for r in old_tls if r.get("id.orig_h")})
        findings.append(Finding(
            title="Deprecated TLS/SSL version observed",
            severity="HIGH",
            confidence="HIGH",
            category="TLS/Web",
            data_source="Zeek ssl.log",
            affected_hosts=hosts,
            description="Deprecated SSL/TLS protocol versions were observed in the capture.",
            recommendation="Disable SSLv2/SSLv3/TLS 1.0/TLS 1.1 and require TLS 1.2+ or TLS 1.3.",
            evidence={"samples": old_tls[:10]},
        ))

    self_signed = [r for r in x509_rows if str(r.get("certificate.issuer", "")) == str(r.get("certificate.subject", "")) and r.get("certificate.subject")]
    if self_signed:
        findings.append(Finding(
            title="Self-signed certificates observed",
            severity="MEDIUM",
            confidence="MEDIUM",
            category="TLS/Web",
            data_source="Zeek x509.log",
            description="Self-signed certificates were observed. This may be expected internally, but should be validated.",
            recommendation="Use managed internal PKI or trusted certificates for production services where appropriate.",
            evidence={"samples": self_signed[:10]},
        ))

    return findings

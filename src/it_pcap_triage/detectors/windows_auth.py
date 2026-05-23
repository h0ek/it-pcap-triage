from __future__ import annotations

from ..model.finding import Finding


def detect_windows_auth(zeek: dict, config: dict) -> list[Finding]:
    findings: list[Finding] = []

    ntlm_rows = zeek.get("ntlm.log", [])
    if ntlm_rows and config.get("policy", {}).get("warn_on_ntlm", True):
        hosts = sorted({r.get("id.orig_h", "") for r in ntlm_rows if r.get("id.orig_h")})
        findings.append(Finding(
            title="NTLM authentication observed",
            severity="MEDIUM",
            confidence="HIGH",
            category="Windows/AD",
            data_source="Zeek ntlm.log",
            affected_hosts=hosts,
            description="NTLM authentication was observed. NTLM increases relay and downgrade risk compared to Kerberos-centric authentication.",
            recommendation="Reduce NTLM usage where possible, enforce SMB signing where applicable and investigate unexpected NTLM paths.",
            evidence={"events": len(ntlm_rows), "hosts": hosts[:25]},
        ))

    kerberos_rows = zeek.get("kerberos.log", [])
    rc4 = [r for r in kerberos_rows if "rc4" in str(r).lower()]
    if rc4:
        hosts = sorted({r.get("id.orig_h", "") for r in rc4 if r.get("id.orig_h")})
        findings.append(Finding(
            title="Kerberos RC4 usage observed",
            severity="MEDIUM",
            confidence="MEDIUM",
            category="Windows/AD",
            data_source="Zeek kerberos.log",
            affected_hosts=hosts,
            description="Kerberos activity appears to include RC4-related encryption. This may indicate legacy compatibility or weaker Kerberos configuration.",
            recommendation="Validate domain encryption settings and reduce/disable RC4 where operationally possible.",
            evidence={"samples": rc4[:10]},
        ))

    return findings

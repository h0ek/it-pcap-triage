from __future__ import annotations

import re
from ..model.finding import Finding
from ..config import DEFAULT_CONFIG


def service_tokens(value):
    return set(re.split(r"[,\s]+", str(value or "").lower())) - {"", "-"}


def detect_insecure_protocols(zeek: dict, tshark_summary: dict, config: dict) -> list[Finding]:
    protocol_rows = tshark_summary.get("protocol_hierarchy", tshark_summary.get("protocol_hierarchy_top", []))
    protocols = {str(row.get("protocol", "")).lower() for row in protocol_rows}
    services = set()
    for row in zeek.get("conn.log", []):
        services.update(service_tokens(row.get("service")))
    observed = protocols | services
    aliases = {"smbv1": {"smb", "smbv1"}, "nbns": {"nbns", "nbt-ns"}}
    risks = {"llmnr": "MEDIUM", "nbns": "MEDIUM", "mdns": "LOW", "tftp": "MEDIUM", "ftp": "HIGH", "telnet": "HIGH", "smbv1": "HIGH"}
    names = {"llmnr": "LLMNR", "nbns": "NBT-NS", "mdns": "mDNS", "tftp": "TFTP", "ftp": "FTP", "telnet": "Telnet", "smbv1": "SMBv1"}
    findings = []
    for token in sorted({str(p).lower() for p in config.get("policy", {}).get("disallowed_protocols", DEFAULT_CONFIG["policy"]["disallowed_protocols"])}):
        matched = aliases.get(token, {token}) & observed
        if token == "smbv1":
            matched = {"smb"} if tshark_summary.get("smbv1_activity", {}).get("count", 0) else set()
        if not matched:
            continue
        hosts = sorted({row["id.orig_h"] for row in zeek.get("conn.log", []) if row.get("id.orig_h") and service_tokens(row.get("service")) & matched and token != "smbv1"})
        findings.append(Finding(
            title=f"{names.get(token, token.upper())} traffic observed",
            severity=risks.get(token, "MEDIUM"), confidence="HIGH", category="Legacy/Insecure Protocols",
            data_source="Zeek conn.log / tshark protocol hierarchy", affected_hosts=hosts,
            description=("Non-negotiation SMBv1 commands were decoded; SMBv1-format negotiation alone is excluded." if token == "smbv1" else f"A protocol disallowed by policy ({token}) was observed."),
            recommendation="Validate the business need and disable or replace the protocol where possible.",
            evidence={"protocol": token, "matched_names": sorted(matched), **({"wireshark_filter": "smb && smb.cmd != 0x72", **tshark_summary["smbv1_activity"]} if token == "smbv1" else {})},
        ))
    return findings

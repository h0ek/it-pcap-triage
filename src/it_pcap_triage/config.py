from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml


DEFAULT_CONFIG = {
    "project": {"name": "IT PCAP Triage"},
    "network": {
        "internal_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "dns_servers": [],
        "ntp_servers": [],
        "domain_controllers": [],
        "proxy_servers": [],
    },
    "policy": {
        "disallowed_protocols": ["telnet", "ftp", "tftp", "smbv1", "llmnr", "nbns"],
        "warn_on_external_dns": True,
        "warn_on_tls10": True,
        "warn_on_tls11": True,
        "warn_on_http_auth": True,
        "warn_on_ntlm": True,
    },
    "thresholds": {
        "scan_unique_hosts": 30,
        "scan_unique_ports": 20,
        "smb_fanout_hosts": 25,
        "dns_queries_per_minute": 300,
        "dns_long_label_length": 50,
        "dns_entropy_threshold": 4.0,
        "beacon_min_connections": 10,
        "beacon_jitter_percent": 20,
        "large_outbound_bytes": 104857600,
    },
}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | None) -> dict[str, Any]:
    cfg = DEFAULT_CONFIG
    if path:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        cfg = deep_merge(cfg, data)
    return cfg

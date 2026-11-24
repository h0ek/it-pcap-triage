from __future__ import annotations

from pathlib import Path
from typing import Any
from copy import deepcopy
import ipaddress
import math
import yaml


DEFAULT_CONFIG = {
    "project": {"name": "IT PCAP Triage"},
    "network": {
        "internal_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "dns_servers": [],
        "ntp_servers": [],
        "domain_controllers": [],
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
        "scan_window_seconds": 60,
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
    cfg = deepcopy(DEFAULT_CONFIG)
    if path:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("Configuration must be a mapping")
        cfg = deep_merge(cfg, data)
    if cfg["network"].get("proxy_servers"):
        raise ValueError("proxy_servers is not supported; remove this unused setting")
    for key, value in cfg["thresholds"].items():
        if key not in DEFAULT_CONFIG["thresholds"]:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"Invalid positive threshold: {key}")
    for key, default in DEFAULT_CONFIG["policy"].items():
        value = cfg["policy"][key]
        if isinstance(default, bool) and not isinstance(value, bool):
            raise ValueError(f"Policy {key} must be boolean")
    for key in ("dns_servers", "ntp_servers", "domain_controllers", "internal_cidrs"):
        values = cfg["network"][key]
        if not isinstance(values, list):
            raise ValueError(f"Network {key} must be a list")
        cfg["network"][key] = [str(ipaddress.ip_network(value, strict=False) if key == "internal_cidrs" else ipaddress.ip_address(value)) for value in values]
    if not isinstance(cfg["policy"]["disallowed_protocols"], list) or not all(isinstance(p, str) for p in cfg["policy"]["disallowed_protocols"]):
        raise ValueError("disallowed_protocols must be a list of protocol names")
    limit = cfg.get("report", {}).get("top_limit", 25)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("report.top_limit must be a positive integer")
    return cfg

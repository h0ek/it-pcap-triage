from dataclasses import dataclass, field
from typing import Any


@dataclass
class HostProfile:
    ip: str
    protocols: set[str] = field(default_factory=set)
    ports_contacted: set[int] = field(default_factory=set)
    peers: set[str] = field(default_factory=set)
    bytes_sent: int = 0
    bytes_received: int = 0
    finding_titles: list[str] = field(default_factory=list)
    suricata_alerts: int = 0
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "protocols": sorted(self.protocols),
            "ports_contacted": sorted(self.ports_contacted),
            "peers": sorted(self.peers),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "finding_titles": self.finding_titles,
            "suricata_alerts": self.suricata_alerts,
            "risk_score": self.risk_score,
        }

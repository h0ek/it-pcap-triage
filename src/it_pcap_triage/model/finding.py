from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    recommendation: str
    confidence: str = "MEDIUM"
    category: str = "General"
    data_source: str = ""
    affected_hosts: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    mappings: dict[str, list[str]] = field(default_factory=dict)
    references: list[dict[str, str]] = field(default_factory=list)
    basis: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "data_source": self.data_source,
            "affected_hosts": self.affected_hosts,
            "evidence": self.evidence,
            "mappings": self.mappings,
            "references": self.references,
            "basis": self.basis,
        }

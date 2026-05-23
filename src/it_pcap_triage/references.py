from __future__ import annotations

from importlib.resources import files
from typing import Any
import yaml

from .model.finding import Finding


def _load_yaml(package_file: str) -> dict[str, Any]:
    resource = files("it_pcap_triage").joinpath("data", package_file)
    return yaml.safe_load(resource.read_text(encoding="utf-8")) or {}


def load_reference_catalog() -> dict[str, Any]:
    return _load_yaml("reference_catalog.yml")


def load_security_mappings() -> dict[str, Any]:
    return _load_yaml("security_mappings.yml")


def enrich_findings_with_references(findings: list[Finding]) -> list[Finding]:
    mappings_doc = load_security_mappings()
    mappings = mappings_doc.get("mappings", {})

    for finding in findings:
        refs = []
        basis_parts = []

        for mapping_name, mapping in mappings.items():
            categories = set(mapping.get("categories", []))
            if finding.category not in categories:
                continue

            if mapping.get("basis"):
                basis_parts.append(mapping["basis"])

            for ref in mapping.get("references", []):
                ref_item = dict(ref)
                ref_item["mapping"] = mapping_name
                refs.append(ref_item)

            # DNS tunneling already has explicit MITRE mapping in some detectors. Keep both.
            if mapping_name == "dns" and "DNS tunneling" in finding.title:
                finding.mappings.setdefault("MITRE ATT&CK", [])
                if "T1071.004" not in finding.mappings["MITRE ATT&CK"]:
                    finding.mappings["MITRE ATT&CK"].append("T1071.004")

        if refs:
            finding.references = refs

        if basis_parts and not finding.basis:
            finding.basis = " ".join(basis_parts)

    return findings

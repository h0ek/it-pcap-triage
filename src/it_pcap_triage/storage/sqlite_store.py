from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class EvidenceStore:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                confidence TEXT,
                data_source TEXT,
                description TEXT,
                recommendation TEXT,
                basis TEXT,
                evidence_json TEXT,
                mappings_json TEXT,
                references_json TEXT
            );

            CREATE TABLE IF NOT EXISTS finding_hosts (
                finding_id INTEGER NOT NULL,
                host TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS host_profiles (
                host TEXT PRIMARY KEY,
                risk_score INTEGER,
                suricata_alerts INTEGER,
                protocols_json TEXT,
                ports_json TEXT,
                peers_count INTEGER,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                findings_json TEXT
            );

            CREATE TABLE IF NOT EXISTS stats (
                name TEXT PRIMARY KEY,
                data_json TEXT
            );

            CREATE TABLE IF NOT EXISTS reference_catalog (
                source_id TEXT PRIMARY KEY,
                data_json TEXT
            );

            CREATE TABLE IF NOT EXISTS suricata_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dest_ip TEXT,
                dest_port INTEGER,
                proto TEXT,
                signature TEXT,
                category TEXT,
                severity INTEGER,
                raw_json TEXT
            );
            """
        )
        self.conn.commit()

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (key, json.dumps(value, default=str)),
        )

    def insert_reference_catalog(self, catalog: dict[str, Any]) -> None:
        for source_id, data in catalog.get("sources", {}).items():
            self.conn.execute(
                "INSERT OR REPLACE INTO reference_catalog(source_id, data_json) VALUES (?, ?)",
                (source_id, json.dumps(data, default=str)),
            )

    def insert_finding(self, finding: Any) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO findings
            (severity, category, title, confidence, data_source, description, recommendation,
             basis, evidence_json, mappings_json, references_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.severity,
                finding.category,
                finding.title,
                finding.confidence,
                finding.data_source,
                finding.description,
                finding.recommendation,
                finding.basis,
                json.dumps(finding.evidence, default=str),
                json.dumps(finding.mappings, default=str),
                json.dumps(finding.references, default=str),
            ),
        )
        finding_id = int(cur.lastrowid)
        for host in finding.affected_hosts:
            if host:
                self.conn.execute(
                    "INSERT INTO finding_hosts(finding_id, host) VALUES (?, ?)",
                    (finding_id, host),
                )
        return finding_id

    def insert_host(self, host: Any) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO host_profiles
            (host, risk_score, suricata_alerts, protocols_json, ports_json, peers_count,
             bytes_sent, bytes_received, findings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                host.ip,
                host.risk_score,
                host.suricata_alerts,
                json.dumps(sorted(host.protocols), default=str),
                json.dumps(sorted(host.ports_contacted), default=str),
                len(host.peers),
                host.bytes_sent,
                host.bytes_received,
                json.dumps(host.finding_titles, default=str),
            ),
        )

    def insert_stat(self, name: str, data: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO stats(name, data_json) VALUES (?, ?)",
            (name, json.dumps(data, default=str)),
        )

    def insert_suricata_alert(self, event: dict[str, Any]) -> None:
        alert = event.get("alert", {})
        self.conn.execute(
            """
            INSERT INTO suricata_alerts
            (ts, src_ip, src_port, dest_ip, dest_port, proto, signature, category, severity, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("timestamp"),
                event.get("src_ip"),
                event.get("src_port"),
                event.get("dest_ip"),
                event.get("dest_port"),
                event.get("proto"),
                alert.get("signature"),
                alert.get("category"),
                alert.get("severity"),
                json.dumps(event, default=str),
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

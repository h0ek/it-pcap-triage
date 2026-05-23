# IT PCAP Triage

Offline analyzer for enterprise IT packet captures.

The tool runs **Zeek**, **Suricata**, **capinfos** and compact **tshark** protocol summaries against a PCAP/PCAPNG file, parses their output, correlates activity by host/protocol, scores findings and generates a compact HTML report.

The project does not implement its own packet inspection engine. It orchestrates trusted offline engines and turns their output into an evidence-based security report.

## Architecture

```text
PCAP
 ├── Zeek       → behavioral logs / metadata / protocol logs
 ├── Suricata   → IDS alerts / IOC / exploit-pattern alerts
 ├── capinfos   → PCAP metadata
 ├── tshark     → protocol hierarchy summary
 └── Python     → correlation / scoring / SQLite evidence / HTML report
```

TShark is not used to dump huge raw conversation logs into the report. It is used as a compact statistics source. Conversation, endpoint, top talker, service and port summaries are calculated from Zeek `conn.log`.

## Focus areas

- cleartext protocols and exposed credentials,
- legacy/insecure IT protocols,
- SMB/NTLM/Kerberos/LDAP/Windows network risks,
- DNS abuse and tunneling indicators,
- TLS and HTTP hygiene issues,
- scanning and lateral movement patterns,
- Suricata IDS alerts,
- suspicious beaconing and data movement,
- policy violations based on a user-defined network baseline.

## Required system tools

The tool fails closed if any required engine is missing:

- `zeek`
- `suricata`
- `tshark`
- `capinfos`

## Install system dependencies

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tshark zeek suricata
```

### Fedora

```bash
sudo dnf install -y python3 python3-pip wireshark-cli zeek suricata
```

## Local development

```bash
cd it-pcap-triage

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

Check dependencies:

```bash
it-pcap-triage check
```

Run analysis:

```bash
it-pcap-triage analyze samples/test.pcapng --out out/test-report
```

There is no special heavy/full mode. The normal analysis performs all agreed checks and produces summaries instead of raw dumps.

## Output

```text
out/test-report/
├── report.html
├── summary.json
├── findings.json
├── hosts.json
├── timings.json
├── triage.db
├── logs/
│   └── run.log
└── engines/
    ├── zeek/
    ├── suricata/
    └── tshark/
```

## Evidence DB

```bash
sqlite3 out/test-report/triage.db '.tables'

sqlite3 out/test-report/triage.db \
  'select severity, category, title from findings order by id;'

sqlite3 out/test-report/triage.db \
  'select host, risk_score, suricata_alerts, peers_count from host_profiles order by risk_score desc limit 20;'

sqlite3 out/test-report/triage.db \
  'select src_ip, dest_ip, signature, severity from suricata_alerts limit 20;'
```

This is a triage tool, not a SIEM, permanent IDS sensor or full forensic platform.

Findings such as DNS tunneling, beaconing, lateral movement or ransomware-like behavior are indicators and require validation.


## Reference mapping policy

The project does not bundle NIST PDFs, CIS PDFs, MITRE STIX bundles or other third-party source documents.

Runtime enrichment uses curated source names and mappings in:

```text
src/it_pcap_triage/data/reference_catalog.yml
src/it_pcap_triage/data/security_mappings.yml
```

This avoids redistributing third-party documents and keeps the report clear about which public framework or document each recommendation is based on.

The report references documents by name, section/control/technique and URL where applicable, for example:

```text
NIST SP 800-52 Rev.2
NIST SP 800-81 Rev.3
NIST SP 800-41 Rev.1
CIS Controls v8.1
MITRE ATT&CK Enterprise
```

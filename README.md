# IT PCAP Triage

Offline analyzer for enterprise IT packet captures.

IT PCAP Triage runs **Zeek**, **Suricata**, **capinfos** and compact **tshark** protocol summaries against a PCAP/PCAPNG file. It parses their output, correlates activity by host/protocol, scores findings and generates a compact HTML security report.

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

```
sudo apt update
sudo apt install -y python3 python3-pip pipx tshark zeek suricata
```

### Fedora

```
sudo dnf install -y python3 python3-pip pipx wireshark-cli zeek suricata
```

Make sure `pipx` is available in your shell:

```
pipx ensurepath
```

Restart your shell if needed.

## Install IT PCAP Triage

Install from PyPI with `pipx`:

```
pipx install it-pcap-triage
```

Check the installation and required system tools:

```
it-pcap-triage check
```

Run analysis:

```
it-pcap-triage analyze samples/test.pcapng --out out/test-report
```

Open the report:

```
xdg-open out/test-report/report.html
```

## Output

```
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

The main output is:

```
report.html
```

The JSON files and SQLite database are intended for automation, debugging and deeper investigation.

## Advanced: Evidence DB

The analysis also creates a SQLite evidence store:

```
triage.db
```

Useful inspection commands:

```
sqlite3 out/test-report/triage.db '.tables'
sqlite3 out/test-report/triage.db \
  'select severity, category, title from findings order by id;'
sqlite3 out/test-report/triage.db \
  'select host, risk_score, suricata_alerts, peers_count from host_profiles order by risk_score desc limit 20;'
sqlite3 out/test-report/triage.db \
  'select src_ip, dest_ip, signature, severity from suricata_alerts limit 20;'
```

## Reference mapping policy

The project does not bundle NIST PDFs, CIS PDFs, MITRE STIX bundles or other third-party source documents.

Runtime enrichment uses curated source names and mappings in:

```
src/it_pcap_triage/data/reference_catalog.yml
src/it_pcap_triage/data/security_mappings.yml
```

This avoids redistributing third-party documents and keeps the report clear about which public framework or document each recommendation is based on.

The report references documents by name, section/control/technique and URL where applicable, for example:

```
NIST SP 800-52 Rev.2
NIST SP 800-81 Rev.3
NIST SP 800-41 Rev.1
CIS Controls v8.1
MITRE ATT&CK Enterprise
```

## Local development

```
git clone https://github.com/h0ek/it-pcap-triage.git
cd it-pcap-triage

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

Run locally:

```
it-pcap-triage check
it-pcap-triage analyze samples/test.pcapng --out out/test-report
```

## Limitations

This is a triage tool, not a SIEM, permanent IDS sensor or full forensic platform.

Findings such as DNS tunneling, beaconing, lateral movement or ransomware-like behavior are indicators and require validation.
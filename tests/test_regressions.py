import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from it_pcap_triage.analyzer import analyze
from it_pcap_triage.config import load_config
from it_pcap_triage.detectors.beaconing import detect_beaconing
from it_pcap_triage.detectors.cleartext_auth import detect_cleartext_auth
from it_pcap_triage.detectors.dns_anomalies import detect_dns_anomalies
from it_pcap_triage.detectors.exfiltration import detect_large_outbound
from it_pcap_triage.detectors.insecure_protocols import detect_insecure_protocols
from it_pcap_triage.detectors.scanning import detect_scanning
from it_pcap_triage.detectors.tls_hygiene import detect_tls_hygiene
from it_pcap_triage.detectors.network_policy import detect_network_policy
from it_pcap_triage.engines.tshark import run_tshark_summary
from it_pcap_triage.parsers.suricata_eve import load_eve
from it_pcap_triage.parsers.tshark_stats import load_tshark_summary
from it_pcap_triage.protocol_inventory import protocol_inventory
from pcap_fixture import write_fixture


def titles(findings):
    return {f.title for f in findings}


def conn(ts=1, dst="8.8.8.8", port=443, **kwargs):
    return {"ts": ts, "id.orig_h": "10.0.0.2", "id.resp_h": dst, "id.resp_p": port, "proto": "tcp", **kwargs}


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config(None)

    def test_dns_continues_after_resolver_and_deduplicates(self):
        rows = [{"id.orig_h": "10.0.0.2", "id.resp_h": "8.8.8.8", "ts": i / 10, "query": "a" * 55 + ".test", "rcode_name": "NXDOMAIN"} for i in range(400)]
        result = detect_dns_anomalies({"dns.log": rows}, {}, self.cfg)
        self.assertEqual(sum(f.title == "Unauthorized DNS resolver used" for f in result), 1)
        self.assertIn("Possible DNS tunneling indicators", titles(result))
        self.assertIn("Excessive NXDOMAIN responses observed", titles(result))
        self.assertIn("High DNS query volume observed", titles(result))
        self.cfg["policy"]["warn_on_external_dns"] = False
        self.assertNotIn("Unauthorized DNS resolver used", titles(detect_dns_anomalies({"dns.log": rows}, {}, self.cfg)))

    def test_dns_slow_traffic_and_window_boundary(self):
        rows = [{"id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.3", "ts": 60*i, "query": "example.com"} for i in range(300)]
        self.assertNotIn("High DNS query volume observed", titles(detect_dns_anomalies({"dns.log": rows}, {}, self.cfg)))
        self.cfg["thresholds"]["dns_queries_per_minute"] = 3
        for row, ts in zip(rows[:3], [59, 60, 61]):
            row["ts"] = ts
        self.assertIn("High DNS query volume observed", titles(detect_dns_anomalies({"dns.log": rows[:3]}, {}, self.cfg)))

    def test_full_hierarchy_exact_and_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "protocol_hierarchy.txt").write_text("".join(f"p{i} frames:100 bytes:1000\n" for i in range(26)) + "llmnr frames:1 bytes:10\ntftp frames:1 bytes:10\n")
            summary = load_tshark_summary(root, 25)
            self.assertEqual(len(summary["protocol_hierarchy_top"]), 25)
            result = titles(detect_insecure_protocols({"conn.log": [conn(service="tftp")]}, summary, self.cfg))
            self.assertIn("LLMNR traffic observed", result)
            self.assertIn("TFTP traffic observed", result)
            self.assertNotIn("FTP traffic observed", result)
            self.cfg["policy"]["disallowed_protocols"] = []
            self.assertFalse(detect_insecure_protocols({}, summary, self.cfg))

    def test_smbv1_negotiation_excluded(self):
        summary = {"protocol_hierarchy": [{"protocol": "smb"}, {"protocol": "smb2"}], "smbv1_activity": {"count": 0, "frames": []}}
        self.assertNotIn("SMBv1 traffic observed", titles(detect_insecure_protocols({}, summary, self.cfg)))
        summary["smbv1_activity"] = {"count": 1, "frames": [5]}
        self.assertIn("SMBv1 traffic observed", titles(detect_insecure_protocols({}, summary, self.cfg)))

    def test_tls_and_http_policy(self):
        self.cfg["policy"].update(warn_on_tls10=False, warn_on_tls11=False, warn_on_http_auth=False)
        self.assertFalse(detect_tls_hygiene({"ssl.log": [{"version": "TLSv10"}, {"version": "TLSv11"}]}, {}, self.cfg))
        self.assertFalse(detect_cleartext_auth({"http.log": [{"username": "user", "id.orig_h": "10.0.0.2"}]}, {}, self.cfg))
        self.cfg["policy"]["warn_on_tls10"] = True
        self.assertTrue(detect_tls_hygiene({"ssl.log": [{"version": "TLSv10"}]}, {}, self.cfg))

    def test_reverse_transfer(self):
        row = conn(**{"id.orig_h": "8.8.8.8", "id.resp_h": "10.0.0.2", "resp_bytes": 200000000})
        self.assertEqual(detect_large_outbound({"conn.log": [row]}, self.cfg)[0].evidence, {"10.0.0.2": 200000000})

    def test_vertical_scan_per_target_and_time(self):
        self.cfg["thresholds"]["scan_unique_ports"] = 3
        mixed = [conn(i, f"10.0.0.{i+3}", 100+i) for i in range(4)]
        slow = [conn(i*61, "10.0.0.3", 100+i) for i in range(4)]
        fast = [conn(i, "10.0.0.3", 100+i) for i in range(4)]
        for rows in [mixed, slow]:
            self.assertNotIn("Vertical port scanning pattern observed", titles(detect_scanning({"conn.log": rows}, self.cfg)))
        self.assertIn("Vertical port scanning pattern observed", titles(detect_scanning({"conn.log": fast}, self.cfg)))

    def test_beaconing(self):
        rows = [conn(i*30) for i in range(12)]
        self.assertTrue(detect_beaconing({"conn.log": rows}, self.cfg))
        rows[-1]["ts"] = 9999
        self.assertFalse(detect_beaconing({"conn.log": rows}, self.cfg))

    def test_network_policy_and_inventory(self):
        self.cfg["network"]["ntp_servers"] = ["10.0.0.3"]
        self.assertTrue(detect_network_policy({"conn.log": [conn(port=123, proto="udp")]}, self.cfg))
        rows = [conn(port=51820, proto="udp"), conn(port=502, service="http"), conn(port=51820, proto="tcp")]
        inv = protocol_inventory({"conn.log": rows}, {"protocol_hierarchy": [{"protocol": "http"}]})
        self.assertEqual([r["name"] for r in inv["port_candidates"]], ["WireGuard"])
        self.assertEqual(inv["zeek_services"][0]["name"], "http")

    def test_missing_and_invalid_eve(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "eve.json"
            with self.assertRaises(RuntimeError):
                load_eve(path)
            path.write_text("")
            self.assertEqual(load_eve(path), [])
            path.write_text("{broken")
            with self.assertRaises(RuntimeError):
                load_eve(path)

    def test_nonempty_output_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "ssl.log").write_text("old")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                analyze(Path("test.pcap"), out, self.cfg, "config")
            self.assertEqual((out / "ssl.log").read_text(), "old")

    def test_mocked_engine_pipeline(self):
        def zeek(pcap, dest, log):
            dest.mkdir(parents=True)
            return 0.1
        def suricata(pcap, dest, log, cfg):
            dest.mkdir(parents=True)
            (dest / "eve.json").write_text("")
            return 0.1
        def tshark(pcap, dest, log):
            dest.mkdir(parents=True)
            (dest / "protocol_hierarchy.txt").write_text("llmnr frames:1 bytes:100\n")
            return {"hierarchy": 0.1}
        with tempfile.TemporaryDirectory() as tmp, patch("it_pcap_triage.analyzer.run_zeek", zeek), patch("it_pcap_triage.analyzer.run_suricata", suricata), patch("it_pcap_triage.analyzer.run_tshark_summary", tshark):
            out = Path(tmp) / "out"
            analyze(Path(tmp)/"test.pcap", out, self.cfg, "config")
            self.assertTrue((out / "triage.db").exists())
            self.assertIn("Protocol Inventory", (out / "report.html").read_text())
            self.assertEqual(json.loads((out / "findings.json").read_text())[0]["title"], "LLMNR traffic observed")

    @unittest.skipUnless(shutil.which("tshark") and shutil.which("capinfos"), "TShark/capinfos not installed")
    def test_real_tshark_pcap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root / "fixture.pcap")
            run_tshark_summary(root / "fixture.pcap", root / "output", root / "run.log")
            summary = load_tshark_summary(root / "output", 1)
            self.assertIn("dns", {r["protocol"] for r in summary["protocol_hierarchy"]})
            self.assertIn("ntp", {r["protocol"] for r in summary["protocol_hierarchy"]})


if __name__ == "__main__":
    unittest.main()

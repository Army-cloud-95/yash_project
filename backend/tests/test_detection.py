import unittest
from app.detection import analyze_series, correlate, detect, parse_pcap, parse_telemetry
from app.pcapgen import build_pcap, frame, modbus

CFG = {"assets": {"10.0.0.10": "PLC-01"}, "allow": ["10.0.0.50"]}
W = lambda src, fc=16, vlan=False: (1.0, frame(src, "10.0.0.10", 50000, 502, modbus(1, fc, 20, b"\x00\x01"), vlan=vlan))

class DetectionTests(unittest.TestCase):
    def run_rules(self, pk, **kw):
        p, _ = parse_pcap(build_pcap(pk, **kw)); return {e["rule"] for e in detect(p, CFG)}

    def test_write_from_unlisted_host_is_flagged(self): self.assertIn("R-MB-03", self.run_rules([W("10.0.0.77")]))
    def test_write_from_allow_listed_host_is_not(self): self.assertEqual(self.run_rules([W("10.0.0.50")]), set())
    def test_read_is_not_a_write(self): self.assertEqual(self.run_rules([W("10.0.0.50", 3)]), set())
    def test_all_write_function_codes(self):
        for fc in (5, 6, 15, 16): self.assertIn("R-MB-03", self.run_rules([W("10.0.0.77", fc)]))
    def test_vlan_tagged_write_is_flagged(self): self.assertIn("R-MB-03", self.run_rules([W("10.0.0.77", vlan=True)]))
    def test_big_endian_pcap_parses(self): self.assertIn("R-MB-03", self.run_rules([W("10.0.0.77")], big_endian=True))
    def test_response_direction_is_ignored(self):
        self.assertNotIn("R-MB-03", self.run_rules([(1.0, frame("10.0.0.10", "10.0.0.77", 502, 50000, modbus(1, 16, 20)))]))
    def test_retransmitted_write_gives_one_finding(self):
        p, _ = parse_pcap(build_pcap([W("10.0.0.77"), (2.0, W("10.0.0.77")[1])]))
        self.assertEqual(len([e for e in detect(p, CFG) if e["rule"] == "R-MB-03"]), 1)
    def test_truncated_capture_does_not_crash(self):
        pk = [W("10.0.0.50"), (2.0, W("10.0.0.77")[1])]
        parse_pcap(build_pcap(pk, truncate_last=10))
    def test_non_pcap_is_rejected(self):
        for bad in (b"", b"x" * 40, b"\x0a\x0d\x0d\x0a" + b"\0" * 40):
            with self.assertRaises(ValueError): parse_pcap(bad)
    def test_dnp3_cleartext_flagged(self):
        pk = [(1.0, frame("10.0.0.50", "10.0.0.21", 50410, 20000, bytes([5, 0x64, 5, 0xC0, 1, 0])))]
        self.assertIn("R-PR-01", self.run_rules(pk))
    def test_unlisted_reader_is_asset_finding_only(self):
        self.assertEqual(self.run_rules([W("10.0.0.88", 3)]), {"R-AS-01"})

class TelemetryTests(unittest.TestCase):
    HEAD = "timestamp,pressure_bar,temperature_c,voltage_v,current_a,motor_state,valve_state\n"
    def csv(self, vals): return self.HEAD + "".join(f"2026-10-14T10:00:{i:02d}Z,{v},70,400,12,ON,OPEN\n" for i, v in enumerate(vals))
    def test_stats_and_deviations(self):
        r = analyze_series(parse_telemetry(self.csv(["6", "6.2", "", "9", "6.1"]), "pressure_bar", 0, 100), 5, 7.5)
        self.assertEqual((r["missing"], r["deviations"], r["first_deviation"] - r["first_deviation"] + 0), (1, 1, 0))
    def test_validation_errors(self):
        with self.assertRaises(ValueError): parse_telemetry("a,b\n1,2\n", "pressure_bar", 0, 100)
        with self.assertRaises(ValueError): parse_telemetry(self.csv(["6", "abc"]), "pressure_bar", 0, 100)
        with self.assertRaises(ValueError): parse_telemetry(self.csv(["6", "500"]), "pressure_bar", 0, 100)
        with self.assertRaises(ValueError): parse_telemetry(self.csv(["", ""]), "pressure_bar", 0, 100)

class CorrelationTests(unittest.TestCase):
    def test_confidence_levels_and_no_causation_claim(self):
        n, a = [{"ts": 100, "asset": "PLC-01"}], [{"ts": 130, "asset": "PLC-01"}]
        self.assertEqual(correlate(n, a, 150, 120, "PLC-01")["confidence"], "moderate")
        self.assertEqual(correlate(n, [], 150, 120, "PLC-01")["confidence"], "low")
        self.assertEqual(correlate(n, a, 150, 10, "PLC-01")["confidence"], "none")
        self.assertEqual(correlate(n, a, None, 120, "PLC-01")["confidence"], "none")
        self.assertIn("does not show", correlate(n, a, 150, 120, "PLC-01")["note"])
    def test_other_asset_is_not_linked(self):
        self.assertEqual(correlate([{"ts": 100, "asset": "RTU-09"}], [], 100, 60, "PLC-01")["linked"], [])

if __name__ == "__main__": unittest.main()

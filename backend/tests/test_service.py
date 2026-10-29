import os, tempfile, unittest
from app.pcapgen import build_pcap, frame, modbus
from app.security import hash_password
from app.service import Service, TooManyAttempts, validate_upload
from seed import seed

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Service(os.path.join(self.tmp.name, "t.db"), "s" * 32, os.path.join(self.tmp.name, "up"))
        seed(self.s.db)
        self.admin = self.s.user_from_token(self.s.login("company.admin", "Admin@2026"))
        self.a = self.s.user_from_token(self.s.login("plant.a", "PlantA@2026"))
        self.b = self.s.user_from_token(self.s.login("plant.b", "PlantB@2026"))
    def tearDown(self): self.tmp.cleanup()

    def test_passwords_are_stored_hashed(self):
        for (h,) in self.s.db.execute("SELECT pw_hash FROM users"): self.assertTrue(h.startswith("scrypt$")); self.assertNotIn("@2026", h)
    def test_wrong_password_and_unknown_user(self):
        for u, p in (("plant.a", "nope"), ("ghost", "x")):
            with self.assertRaises(PermissionError): self.s.login(u, p)
    def test_lockout_after_repeated_failures(self):
        for _ in range(5):
            with self.assertRaises(PermissionError): self.s.login("plant.c", "bad")
        with self.assertRaises(TooManyAttempts): self.s.login("plant.c", "PlantC@2026")
    def test_disabled_user_cannot_log_in(self):
        self.s.db.execute("UPDATE users SET active=0 WHERE username='plant.d'"); self.s.db.commit()
        with self.assertRaises(PermissionError): self.s.login("plant.d", "PlantD@2026")
    def test_admin_sees_all_plants_plant_user_sees_one(self):
        self.assertEqual(len(self.s.plants(self.admin)), 4); self.assertEqual([p["id"] for p in self.s.plants(self.a)], [1])
    def test_plant_isolation_on_every_scoped_call(self):
        calls = [lambda: self.s.assets(self.a, 2), lambda: self.s.findings(self.a, 2), lambda: self.s.correlation(self.a, 2),
                 lambda: self.s.report_csv(self.a, 2), lambda: self.s.add_asset(self.a, 2, "X1", "x"),
                 lambda: self.s.analyze_pcap(self.a, 2, "a.pcap", build_pcap([(1, frame("10.0.0.1", "10.0.0.2", 1, 502))]))]
        for c in calls:
            with self.assertRaises(PermissionError): c()
    def test_admin_gets_404_for_missing_plant(self):
        with self.assertRaises(LookupError): self.s.assets(self.admin, 99)
    def test_user_cannot_use_other_plants_data_after_analysis(self):
        pk = [(1.0, frame("10.20.4.77", "10.20.4.10", 50000, 502, modbus(1, 16, 20, b"\x00\x01")))]
        r = self.s.analyze_pcap(self.a, 1, "x.pcap", build_pcap(pk))
        self.assertTrue(any(f["rule"] == "R-MB-03" for f in r["findings"]))
        self.assertTrue(self.s.findings(self.a, 1)); self.assertEqual(self.s.findings(self.admin, 2), [])
        with self.assertRaises(PermissionError): self.s.findings(self.b, 1)
    def test_asset_validation_and_duplicates(self):
        for args in (("bad code!", "n"), ("OK1", ""), ("OK1", "n", "999.1.1.1")):
            with self.assertRaises(ValueError): self.s.add_asset(self.a, 1, *args)
        self.s.add_asset(self.a, 1, "PLC-09", "New PLC", "10.20.4.99")
        with self.assertRaises(ValueError): self.s.add_asset(self.a, 1, "PLC-09", "Again")
    def test_upload_validation(self):
        good = build_pcap([(1, frame("10.0.0.1", "10.0.0.2", 1, 502))])
        self.assertEqual(validate_upload("pcap", "../../evil.pcap", good), "evil.pcap")
        for kind, name, data in (("pcap", "a.txt", good), ("pcap", "a.pcap", b"junk"), ("pcap", "a.pcap", b""), ("pdf", "a.pdf", b"not pdf"),
                                 ("csv", "a.csv", b"\x00\x01"), ("exe", "a.exe", b"x"), ("pcap", "a.pcap", good + b"0" * (51 * 1048576))):
            with self.assertRaises(ValueError): validate_upload(kind, name, data)
    def test_uploads_stay_inside_upload_dir_with_random_names(self):
        good = build_pcap([(1, frame("10.0.0.1", "10.0.0.2", 1, 502))])
        self.s.analyze_pcap(self.a, 1, "../../../etc/cron.pcap", good)
        path = self.s.db.execute("SELECT stored_path FROM uploads").fetchone()[0]
        self.assertTrue(os.path.abspath(path).startswith(self.s.upload_dir)); self.assertNotIn("cron", os.path.basename(path))
    def test_report_neutralizes_csv_formulas(self):
        self.s._add_findings(1, [dict(rule="R", sev="low", title="=HYPERLINK(1)", asset="A", evidence="+x", ts=1)])
        self.assertIn("'=HYPERLINK", self.s.report_csv(self.a, 1))
    def test_token_for_removed_user_is_rejected(self):
        t = self.s.login("plant.a", "PlantA@2026")
        self.s.db.execute("UPDATE users SET active=0 WHERE username='plant.a'"); self.s.db.commit()
        with self.assertRaises(PermissionError): self.s.user_from_token(t)
    def test_secret_must_be_strong(self):
        with self.assertRaises(ValueError): Service(":memory:", "short", self.tmp.name)

if __name__ == "__main__": unittest.main()

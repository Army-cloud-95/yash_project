import io, os, tempfile, unittest
from fastapi.testclient import TestClient
from app.pcapgen import build_pcap, frame, modbus
from app.security import make_token
from app.service import Service
from seed import seed
import app.main as main_module

SAMPLE_AUDIT_CSV = """timestamp,asset_id,event_id,user,action,object,old_value,new_value,cpu_mode,source,data_label
2026-10-14T10:00:05Z,PLC-01,A-0901,engineer.demo,LOGIN,session,,,RUN,engineering-ws 10.20.4.30,SYNTHETIC
2026-10-14T10:41:40Z,PLC-01,A-0918,unknown,REGISTER_WRITE,holding_register_40021,5800,7900,RUN,network 10.20.4.77,SYNTHETIC
"""

class ApiIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(self.tmp.name, "test_api.db")
        upload_dir = os.path.join(self.tmp.name, "uploads")
        self.secret = "test-secret-key-at-least-32-chars-long!"
        
        # Point the module service to our isolated test database and directory
        self.svc = Service(db_path, self.secret, upload_dir)
        seed(self.svc.db)
        main_module.svc = self.svc
        self.client = TestClient(main_module.app)

    def tearDown(self):
        try:
            self.svc.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "ok"})

    def test_login_success(self):
        res = self.client.post("/auth/login", json={"username": "company.admin", "password": "Admin@2026"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")

    def test_login_failure(self):
        res = self.client.post("/auth/login", json={"username": "company.admin", "password": "WrongPassword"})
        self.assertEqual(res.status_code, 401)
        self.assertIn("detail", res.json())

    def test_login_lockout(self):
        for _ in range(5):
            self.client.post("/auth/login", json={"username": "plant.c", "password": "bad"})
        res = self.client.post("/auth/login", json={"username": "plant.c", "password": "PlantC@2026"})
        self.assertEqual(res.status_code, 429)

    def test_me_and_plant_isolation(self):
        tok_admin = self.client.post("/auth/login", json={"username": "company.admin", "password": "Admin@2026"}).json()["access_token"]
        me_admin = self.client.get("/me", headers={"Authorization": f"Bearer {tok_admin}"}).json()
        self.assertEqual(me_admin["role"], "company_admin")
        self.assertEqual(me_admin["plants"], [1, 2, 3, 4])
        plants_admin = self.client.get("/plants", headers={"Authorization": f"Bearer {tok_admin}"}).json()
        self.assertEqual(len(plants_admin), 4)

        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]
        me_a = self.client.get("/me", headers={"Authorization": f"Bearer {tok_a}"}).json()
        self.assertEqual(me_a["role"], "plant_user")
        self.assertEqual(me_a["plants"], [1])
        plants_a = self.client.get("/plants", headers={"Authorization": f"Bearer {tok_a}"}).json()
        self.assertEqual(len(plants_a), 1)
        self.assertEqual(plants_a[0]["id"], 1)

        tok_b = self.client.post("/auth/login", json={"username": "plant.b", "password": "PlantB@2026"}).json()["access_token"]
        me_b = self.client.get("/me", headers={"Authorization": f"Bearer {tok_b}"}).json()
        self.assertEqual(me_b["role"], "plant_user")
        self.assertEqual(me_b["plants"], [2])
        plants_b = self.client.get("/plants", headers={"Authorization": f"Bearer {tok_b}"}).json()
        self.assertEqual(len(plants_b), 1)
        self.assertEqual(plants_b[0]["id"], 2)

    def test_cross_plant_access_is_denied(self):
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]
        tok_b = self.client.post("/auth/login", json={"username": "plant.b", "password": "PlantB@2026"}).json()["access_token"]

        self.assertEqual(self.client.get("/plants/1/assets", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 200)
        self.assertEqual(self.client.get("/plants/1/findings", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 200)
        self.assertEqual(self.client.get("/plants/1/report.csv", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 200)

        self.assertEqual(self.client.get("/plants/2/assets", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 403)
        self.assertEqual(self.client.get("/plants/2/findings", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 403)
        self.assertEqual(self.client.get("/plants/2/report.csv", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 403)
        self.assertEqual(self.client.get("/plants/2/correlation", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 403)

        self.assertEqual(self.client.get("/plants/2/assets", headers={"Authorization": f"Bearer {tok_b}"}).status_code, 200)
        self.assertEqual(self.client.get("/plants/1/assets", headers={"Authorization": f"Bearer {tok_b}"}).status_code, 403)

    def test_token_validation_errors(self):
        res = self.client.get("/me")
        self.assertEqual(res.status_code, 401)

        res = self.client.get("/me", headers={"Authorization": "Bearer bad.token"})
        self.assertEqual(res.status_code, 401)

        exp_token = make_token(self.secret, "plant.a", ttl=-10)
        res = self.client.get("/me", headers={"Authorization": f"Bearer {exp_token}"})
        self.assertEqual(res.status_code, 401)

        tampered = make_token("different-secret-key-32-chars-long!", "plant.a", ttl=3600)
        res = self.client.get("/me", headers={"Authorization": f"Bearer {tampered}"})
        self.assertEqual(res.status_code, 401)

    def test_pcap_upload_and_findings(self):
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]
        pk = [(1.0, frame("10.20.4.77", "10.20.4.10", 50000, 502, modbus(1, 16, 20, b"\x00\x01")))]
        pcap_data = build_pcap(pk)

        res = self.client.post(
            "/plants/1/uploads/pcap",
            headers={"Authorization": f"Bearer {tok_a}"},
            files={"file": ("test.pcap", io.BytesIO(pcap_data), "application/vnd.tcpdump.pcap")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("packets", data)
        self.assertIn("findings", data)
        self.assertTrue(any(f["rule"] == "R-MB-03" for f in data["findings"]))

        res_findings = self.client.get("/plants/1/findings", headers={"Authorization": f"Bearer {tok_a}"})
        self.assertEqual(res_findings.status_code, 200)
        findings_list = res_findings.json()
        self.assertTrue(len(findings_list) > 0)
        self.assertTrue(any(f["rule"] == "R-MB-03" for f in findings_list))
        # Ensure MITRE ATT&CK mapping is included
        mb_finding = next(f for f in findings_list if f["rule"] == "R-MB-03")
        self.assertEqual(mb_finding.get("mitre_id"), "T0855")

        res_report = self.client.get("/plants/1/report.csv", headers={"Authorization": f"Bearer {tok_a}"})
        self.assertEqual(res_report.status_code, 200)
        self.assertIn("text/csv", res_report.headers["content-type"])
        self.assertIn("R-MB-03", res_report.text)

    def test_invalid_upload_rejected(self):
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]
        res = self.client.post(
            "/plants/1/uploads/pcap",
            headers={"Authorization": f"Bearer {tok_a}"},
            files={"file": ("fake.pcap", io.BytesIO(b"not-a-pcap-file"), "application/octet-stream")}
        )
        self.assertEqual(res.status_code, 422)

    def test_asset_lifecycle_management(self):
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]
        tok_b = self.client.post("/auth/login", json={"username": "plant.b", "password": "PlantB@2026"}).json()["access_token"]

        # Add asset
        res_add = self.client.post(
            "/plants/1/assets",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"code": "PLC-99", "name": "Backup Controller", "ip": "10.20.4.99"}
        )
        self.assertEqual(res_add.status_code, 201)

        # Update asset
        res_update = self.client.put(
            "/plants/1/assets/PLC-99",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"name": "Primary Controller", "firmware": "v2.4.1"}
        )
        self.assertEqual(res_update.status_code, 200)
        self.assertEqual(res_update.json()["name"], "Primary Controller")
        self.assertEqual(res_update.json()["firmware"], "v2.4.1")

        # Verify asset
        res_verify = self.client.post(
            "/plants/1/assets/PLC-99/verify",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"verified": True}
        )
        self.assertEqual(res_verify.status_code, 200)
        self.assertEqual(res_verify.json()["verified"], 1)

        # Cross-plant unauthorized asset deletion attempt (Plant B -> Plant 1)
        res_cross_del = self.client.delete(
            "/plants/1/assets/PLC-99",
            headers={"Authorization": f"Bearer {tok_b}"}
        )
        self.assertEqual(res_cross_del.status_code, 403)

        # Authorized asset deletion
        res_del = self.client.delete(
            "/plants/1/assets/PLC-99",
            headers={"Authorization": f"Bearer {tok_a}"}
        )
        self.assertEqual(res_del.status_code, 200)
        self.assertEqual(res_del.json()["deleted"], "PLC-99")

    def test_plc_audit_upload_and_tri_source_correlation(self):
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]

        # 1. Upload PCAP network write
        pk = [(1728902500.0, frame("10.20.4.77", "10.20.4.10", 50000, 502, modbus(1, 16, 20, b"\x00\x01")))]
        self.client.post(
            "/plants/1/uploads/pcap",
            headers={"Authorization": f"Bearer {tok_a}"},
            files={"file": ("test.pcap", io.BytesIO(build_pcap(pk)), "application/vnd.tcpdump.pcap")}
        )

        # 2. Upload telemetry CSV with process excursion
        head = "timestamp,pressure_bar,temperature_c,voltage_v,current_a,motor_state,valve_state\n"
        csv_tel = head + "2026-10-14T10:41:00Z,5.5,70,400,12,ON,OPEN\n2026-10-14T10:42:00Z,18.0,70,400,12,ON,OPEN\n"
        self.client.post(
            "/plants/1/uploads/telemetry?column=pressure_bar&lo=0&hi=10",
            headers={"Authorization": f"Bearer {tok_a}"},
            files={"file": ("telemetry.csv", io.BytesIO(csv_tel.encode()), "text/csv")}
        )

        # 3. Upload host PLC audit log CSV
        res_audit = self.client.post(
            "/plants/1/uploads/audit",
            headers={"Authorization": f"Bearer {tok_a}"},
            files={"file": ("audit.csv", io.BytesIO(SAMPLE_AUDIT_CSV.encode()), "text/csv")}
        )
        self.assertEqual(res_audit.status_code, 200)
        self.assertEqual(res_audit.json()["events"], 2)

        # 4. Check correlation engine
        res_corr = self.client.get(
            "/plants/1/correlation?window=120",
            headers={"Authorization": f"Bearer {tok_a}"}
        )
        self.assertEqual(res_corr.status_code, 200)
        corr_data = res_corr.json()
        # With both network event and audit event within window of process excursion, confidence is moderate
        self.assertIn("linked", corr_data)
        self.assertIn(corr_data["confidence"], ("moderate", "low"))

    def test_audit_log_compliance_endpoints(self):
        tok_admin = self.client.post("/auth/login", json={"username": "company.admin", "password": "Admin@2026"}).json()["access_token"]
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]
        tok_b = self.client.post("/auth/login", json={"username": "plant.b", "password": "PlantB@2026"}).json()["access_token"]

        # Admin can view fleet-wide audit log
        res_admin_audit = self.client.get("/audit?limit=10", headers={"Authorization": f"Bearer {tok_admin}"})
        self.assertEqual(res_admin_audit.status_code, 200)
        self.assertIsInstance(res_admin_audit.json(), list)

        # Plant A can view Plant 1 audit
        res_a_audit = self.client.get("/plants/1/audit", headers={"Authorization": f"Bearer {tok_a}"})
        self.assertEqual(res_a_audit.status_code, 200)

        # Plant B cannot view Plant 1 audit (403 Forbidden)
        res_b_audit = self.client.get("/plants/1/audit", headers={"Authorization": f"Bearer {tok_b}"})
        self.assertEqual(res_b_audit.status_code, 403)

    def test_password_rotation(self):
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]

        # Change password
        res_change = self.client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"old_password": "PlantA@2026", "new_password": "NewSecretPassword@2026"}
        )
        self.assertEqual(res_change.status_code, 200)

        # Old password should now fail
        res_old = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"})
        self.assertEqual(res_old.status_code, 401)

        # New password should succeed
        res_new = self.client.post("/auth/login", json={"username": "plant.a", "password": "NewSecretPassword@2026"})
        self.assertEqual(res_new.status_code, 200)
        self.assertIn("access_token", res_new.json())

    def test_posture_and_fleet_summaries(self):
        tok_admin = self.client.post("/auth/login", json={"username": "company.admin", "password": "Admin@2026"}).json()["access_token"]
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]

        # Plant summary
        res_p1 = self.client.get("/plants/1/summary", headers={"Authorization": f"Bearer {tok_a}"})
        self.assertEqual(res_p1.status_code, 200)
        p1_data = res_p1.json()
        self.assertIn("posture_score", p1_data)
        self.assertIn("total_assets", p1_data)
        self.assertIn("iec_62443_ready", p1_data)

        # Fleet summary
        res_fleet = self.client.get("/fleet/summary", headers={"Authorization": f"Bearer {tok_admin}"})
        self.assertEqual(res_fleet.status_code, 200)
        fleet_data = res_fleet.json()
        self.assertIn("plants_count", fleet_data)
        self.assertIn("total_assets", fleet_data)
        self.assertIn("average_posture_score", fleet_data)
        self.assertEqual(fleet_data["plants_count"], 4)

if __name__ == "__main__":
    unittest.main()

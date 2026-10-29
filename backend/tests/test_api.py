import io, os, tempfile, unittest
from fastapi.testclient import TestClient
from app.pcapgen import build_pcap, frame, modbus
from app.security import make_token
from app.service import Service
from seed import seed
import app.main as main_module

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
        # Admin
        tok_admin = self.client.post("/auth/login", json={"username": "company.admin", "password": "Admin@2026"}).json()["access_token"]
        me_admin = self.client.get("/me", headers={"Authorization": f"Bearer {tok_admin}"}).json()
        self.assertEqual(me_admin["role"], "company_admin")
        self.assertEqual(me_admin["plants"], [1, 2, 3, 4])
        plants_admin = self.client.get("/plants", headers={"Authorization": f"Bearer {tok_admin}"}).json()
        self.assertEqual(len(plants_admin), 4)

        # Plant A
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]
        me_a = self.client.get("/me", headers={"Authorization": f"Bearer {tok_a}"}).json()
        self.assertEqual(me_a["role"], "plant_user")
        self.assertEqual(me_a["plants"], [1])
        plants_a = self.client.get("/plants", headers={"Authorization": f"Bearer {tok_a}"}).json()
        self.assertEqual(len(plants_a), 1)
        self.assertEqual(plants_a[0]["id"], 1)

        # Plant B
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

        # Plant A accesses Plant 1 (Allowed)
        self.assertEqual(self.client.get("/plants/1/assets", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 200)
        self.assertEqual(self.client.get("/plants/1/findings", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 200)
        self.assertEqual(self.client.get("/plants/1/report.csv", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 200)

        # Plant A attempts to access Plant 2 (Forbidden)
        self.assertEqual(self.client.get("/plants/2/assets", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 403)
        self.assertEqual(self.client.get("/plants/2/findings", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 403)
        self.assertEqual(self.client.get("/plants/2/report.csv", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 403)
        self.assertEqual(self.client.get("/plants/2/correlation", headers={"Authorization": f"Bearer {tok_a}"}).status_code, 403)

        # Plant B accesses Plant 2 (Allowed)
        self.assertEqual(self.client.get("/plants/2/assets", headers={"Authorization": f"Bearer {tok_b}"}).status_code, 200)

        # Plant B attempts to access Plant 1 (Forbidden)
        self.assertEqual(self.client.get("/plants/1/assets", headers={"Authorization": f"Bearer {tok_b}"}).status_code, 403)

    def test_token_validation_errors(self):
        # Missing token
        res = self.client.get("/me")
        self.assertEqual(res.status_code, 401)

        # Invalid token format
        res = self.client.get("/me", headers={"Authorization": "Bearer bad.token"})
        self.assertEqual(res.status_code, 401)

        # Expired token
        exp_token = make_token(self.secret, "plant.a", ttl=-10)
        res = self.client.get("/me", headers={"Authorization": f"Bearer {exp_token}"})
        self.assertEqual(res.status_code, 401)

        # Tampered token (wrong secret)
        tampered = make_token("different-secret-key-32-chars-long!", "plant.a", ttl=3600)
        res = self.client.get("/me", headers={"Authorization": f"Bearer {tampered}"})
        self.assertEqual(res.status_code, 401)

    def test_pcap_upload_and_findings(self):
        tok_a = self.client.post("/auth/login", json={"username": "plant.a", "password": "PlantA@2026"}).json()["access_token"]
        
        # Generate valid test pcap with an unlisted modbus write
        pk = [(1.0, frame("10.20.4.77", "10.20.4.10", 50000, 502, modbus(1, 16, 20, b"\x00\x01")))]
        pcap_data = build_pcap(pk)

        # Upload to plant 1
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

        # Verify findings are persisted
        res_findings = self.client.get("/plants/1/findings", headers={"Authorization": f"Bearer {tok_a}"})
        self.assertEqual(res_findings.status_code, 200)
        findings_list = res_findings.json()
        self.assertTrue(len(findings_list) > 0)
        self.assertTrue(any(f["rule"] == "R-MB-03" for f in findings_list))

        # Check CSV report export
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

if __name__ == "__main__":
    unittest.main()

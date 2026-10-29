import time, unittest
from app.security import hash_password, make_token, read_token, safe_filename, verify_password

class SecurityTests(unittest.TestCase):
    def test_password_roundtrip_and_salt(self):
        a, b = hash_password("Secret#1"), hash_password("Secret#1")
        self.assertNotEqual(a, b)
        self.assertNotIn("Secret#1", a)
        self.assertTrue(verify_password("Secret#1", a))
        self.assertFalse(verify_password("secret#1", a))
        self.assertFalse(verify_password("x", "garbage"))

    def test_token_valid_expired_tampered_wrong_secret(self):
        s = "k" * 32
        t = make_token(s, "alice", ttl=60)
        self.assertEqual(read_token(s, t), "alice")
        with self.assertRaises(ValueError): read_token(s, make_token(s, "alice", ttl=-5))
        with self.assertRaises(ValueError): read_token("z" * 32, t)
        body, sig = t.split(".")
        with self.assertRaises(ValueError): read_token(s, make_token(s, "bob", 60).split(".")[0] + "." + sig)
        with self.assertRaises(ValueError): read_token(s, "not-a-token")

    def test_filenames_are_sanitized(self):
        for bad in ["../../etc/passwd", "..\\..\\win.ini", "/abs/path.pcap", ".hidden", "a b$c.csv", ""]:
            n = safe_filename(bad)
            self.assertNotIn("/", n); self.assertNotIn("\\", n); self.assertFalse(n.startswith("."))
        self.assertEqual(safe_filename("../../x.pcap"), "x.pcap")

if __name__ == "__main__": unittest.main()

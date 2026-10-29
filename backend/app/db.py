import sqlite3
SCHEMA = """
CREATE TABLE IF NOT EXISTS plants(id INTEGER PRIMARY KEY, name TEXT NOT NULL, write_allow TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN('company_admin','plant_user')), pw_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS user_plants(user_id INTEGER NOT NULL REFERENCES users(id), plant_id INTEGER NOT NULL REFERENCES plants(id), PRIMARY KEY(user_id, plant_id));
CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, plant_id INTEGER NOT NULL REFERENCES plants(id), code TEXT NOT NULL, name TEXT NOT NULL,
  ip TEXT, manufacturer TEXT, model TEXT, firmware TEXT, verified INTEGER NOT NULL DEFAULT 0, UNIQUE(plant_id, code));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, plant_id INTEGER NOT NULL REFERENCES plants(id), rule TEXT NOT NULL, severity TEXT NOT NULL,
  title TEXT NOT NULL, asset TEXT, evidence TEXT NOT NULL, kind TEXT NOT NULL, ts REAL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS uploads(id INTEGER PRIMARY KEY, plant_id INTEGER NOT NULL REFERENCES plants(id), kind TEXT NOT NULL, original_name TEXT NOT NULL,
  stored_path TEXT NOT NULL, size INTEGER NOT NULL, uploaded_by INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, username TEXT, action TEXT NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY, username TEXT NOT NULL, ts REAL NOT NULL, ok INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_findings_plant ON findings(plant_id);
"""
def connect(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA)
    return db

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS plants(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    write_allow TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN('company_admin','plant_user')),
    pw_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_plants(
    user_id INTEGER NOT NULL REFERENCES users(id),
    plant_id INTEGER NOT NULL REFERENCES plants(id),
    PRIMARY KEY(user_id, plant_id)
);

CREATE TABLE IF NOT EXISTS assets(
    id INTEGER PRIMARY KEY,
    plant_id INTEGER NOT NULL REFERENCES plants(id),
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    ip TEXT,
    manufacturer TEXT,
    model TEXT,
    firmware TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    UNIQUE(plant_id, code)
);

CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY,
    plant_id INTEGER NOT NULL REFERENCES plants(id),
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    asset TEXT,
    evidence TEXT NOT NULL,
    kind TEXT NOT NULL,
    ts REAL,
    created_at TEXT NOT NULL,
    mitre_id TEXT,
    mitre_name TEXT
);

CREATE TABLE IF NOT EXISTS uploads(
    id INTEGER PRIMARY KEY,
    plant_id INTEGER NOT NULL REFERENCES plants(id),
    kind TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    uploaded_by INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    username TEXT,
    action TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts(
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    ts REAL NOT NULL,
    ok INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS plc_audit_events(
    id INTEGER PRIMARY KEY,
    plant_id INTEGER NOT NULL REFERENCES plants(id),
    asset_id TEXT NOT NULL,
    event_id TEXT,
    user TEXT,
    action TEXT NOT NULL,
    object TEXT,
    old_value TEXT,
    new_value TEXT,
    cpu_mode TEXT,
    source TEXT,
    ts REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_assets_plant ON assets(plant_id);
CREATE INDEX IF NOT EXISTS ix_findings_plant ON findings(plant_id);
CREATE INDEX IF NOT EXISTS ix_findings_plant_ts ON findings(plant_id, ts);
CREATE INDEX IF NOT EXISTS ix_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS ix_login_attempts_username_ts ON login_attempts(username, ts);
CREATE INDEX IF NOT EXISTS ix_plc_audit_plant_ts ON plc_audit_events(plant_id, ts);
"""

def connect(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    # High-concurrency performance and reliability pragmas
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.OperationalError:
        pass
    db.executescript(SCHEMA)

    # Safe lightweight schema migrations for existing DB instances
    for col, col_def in [("mitre_id", "TEXT"), ("mitre_name", "TEXT")]:
        try:
            db.execute(f"ALTER TABLE findings ADD COLUMN {col} {col_def}")
        except sqlite3.OperationalError:
            pass

    return db

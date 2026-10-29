"""Business logic. Every plant-scoped method calls authorize() first, so isolation does not depend on the HTTP layer."""
import csv, io, json, os, re, threading, time, uuid
from datetime import datetime, timezone
from . import detection as D
from .db import connect
from .security import hash_password, make_token, read_token, safe_filename, verify_password

class TooManyAttempts(Exception): pass

LIMITS = {"pcap": (50, ".pcap"), "csv": (20, ".csv"), "pdf": (20, ".pdf")}
MAX_FAILS, FAIL_WINDOW = 5, 900
DUMMY = hash_password("dummy-password-for-timing")
CODE_RE, IP_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$"), re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
now_iso = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")

def csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s

def validate_upload(kind, filename, data):
    if kind not in LIMITS: raise ValueError("unknown upload kind")
    mb, ext = LIMITS[kind]
    name = safe_filename(filename)
    if not name.lower().endswith(ext): raise ValueError(f"unsupported file type, expected {ext}")
    if not data: raise ValueError("file is empty")
    if len(data) > mb * 1048576: raise ValueError(f"file is larger than {mb} MB")
    if kind == "pdf" and not data.startswith(b"%PDF-"): raise ValueError("file does not look like a PDF")
    if kind == "pcap" and bytes(data[:4]) not in D.MAGICS: raise ValueError("not a classic pcap file")
    if kind == "csv" and b"\x00" in data[:4096]: raise ValueError("file does not look like text")
    return name

class Service:
    def __init__(self, db_path, secret, upload_dir, ttl=3600):
        if not secret or len(secret) < 16: raise ValueError("OTS_SECRET must be set to a long random value")
        self.db, self.secret, self.ttl, self.lock = connect(db_path), secret, ttl, threading.Lock()
        self.upload_dir = os.path.abspath(upload_dir)

    def audit(self, username, action, detail=""):
        with self.lock:
            self.db.execute("INSERT INTO audit_log(ts,username,action,detail) VALUES(?,?,?,?)", (now_iso(), username, action, detail))
            self.db.commit()

    def get_audit_log(self, user, plant_id=None, limit=100, offset=0, action=None):
        if plant_id is not None:
            self.authorize(user, plant_id)
            query = "SELECT id, ts, username, action, detail FROM audit_log WHERE detail LIKE ?"
            params = [f"%plant {plant_id}%"]
        elif user["role"] == "company_admin":
            query = "SELECT id, ts, username, action, detail FROM audit_log WHERE 1=1"
            params = []
        else:
            allowed_plants = user.get("plants", set())
            if not allowed_plants: return []
            clauses = ["username = ?"] + [f"detail LIKE '%plant {p}%'" for p in allowed_plants]
            query = f"SELECT id, ts, username, action, detail FROM audit_log WHERE ({' OR '.join(clauses)})"
            params = [user["username"]]

        if action:
            query += " AND action = ?"
            params.append(action)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([min(limit, 500), max(offset, 0)])
        return [dict(r) for r in self.db.execute(query, params)]

    # ---- authentication & user management ----
    def login(self, username, password):
        cut = time.time() - FAIL_WINDOW
        fails = self.db.execute("SELECT COUNT(*) FROM login_attempts WHERE username=? AND ok=0 AND ts>?", (username, cut)).fetchone()[0]
        if fails >= MAX_FAILS:
            self.audit(username, "login_blocked", "too many failed attempts")
            raise TooManyAttempts()
        row = self.db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        ok = verify_password(password, row["pw_hash"] if row else DUMMY) and row is not None and row["active"] == 1
        with self.lock:
            self.db.execute("INSERT INTO login_attempts(username,ts,ok) VALUES(?,?,?)", (username, time.time(), int(ok)))
            self.db.commit()
        self.audit(username, "login_ok" if ok else "login_failed")
        if not ok: raise PermissionError("invalid credentials")
        return make_token(self.secret, username, self.ttl)

    def change_password(self, user, old_password, new_password):
        row = self.db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not row or not verify_password(old_password, row["pw_hash"]):
            raise PermissionError("incorrect current password")
        if not new_password or len(new_password) < 8:
            raise ValueError("new password must be at least 8 characters long")
        if len(new_password) > 128:
            raise ValueError("new password must not exceed 128 characters")
        new_hash = hash_password(new_password)
        with self.lock:
            self.db.execute("UPDATE users SET pw_hash=? WHERE id=?", (new_hash, user["id"]))
            self.db.commit()
        self.audit(user["username"], "password_changed", f"user {user['username']}")
        return {"status": "password updated successfully"}

    def user_from_token(self, token):
        try: username = read_token(self.secret, token)
        except ValueError as e: raise PermissionError(str(e))
        r = self.db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if not r: raise PermissionError("unknown or disabled user")
        plants = {x[0] for x in self.db.execute("SELECT plant_id FROM user_plants WHERE user_id=?", (r["id"],))}
        return dict(id=r["id"], username=r["username"], name=r["name"], role=r["role"], plants=plants)

    # ---- authorization ----
    def authorize(self, user, plant_id):
        exists = self.db.execute("SELECT 1 FROM plants WHERE id=?", (plant_id,)).fetchone()
        if user["role"] == "company_admin":
            if not exists: raise LookupError("plant not found")
            return
        if plant_id not in user["plants"]: raise PermissionError("no access to this plant")

    def plants(self, user):
        if user["role"] == "company_admin": rows = self.db.execute("SELECT id,name FROM plants")
        elif user["plants"]:
            rows = self.db.execute("SELECT id,name FROM plants WHERE id IN (%s)" % ",".join("?" * len(user["plants"])), tuple(user["plants"]))
        else: return []
        return [dict(r) for r in rows]

    # ---- asset lifecycle management ----
    def assets(self, user, plant_id):
        self.authorize(user, plant_id)
        return [dict(r) for r in self.db.execute("SELECT code,name,ip,manufacturer,model,firmware,verified FROM assets WHERE plant_id=? ORDER BY code", (plant_id,))]

    def add_asset(self, user, plant_id, code, name, ip=None, manufacturer=None, model=None, firmware=None):
        self.authorize(user, plant_id)
        if not CODE_RE.match(code or ""): raise ValueError("asset code may use letters, numbers, - and _ (max 32)")
        if not (name or "").strip(): raise ValueError("name is required")
        if ip and (not IP_RE.match(ip) or any(int(x) > 255 for x in ip.split("."))): raise ValueError("invalid IPv4 address")
        try:
            with self.lock:
                self.db.execute("INSERT INTO assets(plant_id,code,name,ip,manufacturer,model,firmware,verified) VALUES(?,?,?,?,?,?,?,0)",
                                (plant_id, code, name.strip()[:120], ip, manufacturer, model, firmware))
                self.db.commit()
        except Exception as e:
            if "UNIQUE" in str(e): raise ValueError("asset code already exists")
            raise
        self.audit(user["username"], "asset_added", f"plant {plant_id} {code}")

    def update_asset(self, user, plant_id, code, name=None, ip=None, manufacturer=None, model=None, firmware=None):
        self.authorize(user, plant_id)
        row = self.db.execute("SELECT * FROM assets WHERE plant_id=? AND code=?", (plant_id, code)).fetchone()
        if not row: raise LookupError("asset not found")
        if name is not None and not name.strip(): raise ValueError("name cannot be empty")
        if ip and (not IP_RE.match(ip) or any(int(x) > 255 for x in ip.split("."))): raise ValueError("invalid IPv4 address")
        new_name = name.strip()[:120] if name is not None else row["name"]
        new_ip = ip if ip is not None else row["ip"]
        new_mfg = manufacturer if manufacturer is not None else row["manufacturer"]
        new_model = model if model is not None else row["model"]
        new_fw = firmware if firmware is not None else row["firmware"]
        with self.lock:
            self.db.execute("UPDATE assets SET name=?, ip=?, manufacturer=?, model=?, firmware=? WHERE plant_id=? AND code=?",
                            (new_name, new_ip, new_mfg, new_model, new_fw, plant_id, code))
            self.db.commit()
        self.audit(user["username"], "asset_updated", f"plant {plant_id} {code}")
        return dict(code=code, name=new_name, ip=new_ip, manufacturer=new_mfg, model=new_model, firmware=new_fw, verified=row["verified"])

    def verify_asset(self, user, plant_id, code, verified: bool = True):
        self.authorize(user, plant_id)
        row = self.db.execute("SELECT * FROM assets WHERE plant_id=? AND code=?", (plant_id, code)).fetchone()
        if not row: raise LookupError("asset not found")
        with self.lock:
            self.db.execute("UPDATE assets SET verified=? WHERE plant_id=? AND code=?", (int(verified), plant_id, code))
            self.db.commit()
        self.audit(user["username"], "asset_verified" if verified else "asset_unverified", f"plant {plant_id} {code}")
        return {"code": code, "verified": int(verified)}

    def delete_asset(self, user, plant_id, code):
        self.authorize(user, plant_id)
        row = self.db.execute("SELECT * FROM assets WHERE plant_id=? AND code=?", (plant_id, code)).fetchone()
        if not row: raise LookupError("asset not found")
        with self.lock:
            self.db.execute("DELETE FROM assets WHERE plant_id=? AND code=?", (plant_id, code))
            self.db.commit()
        self.audit(user["username"], "asset_deleted", f"plant {plant_id} {code}")
        return {"deleted": code}

    # ---- uploads and analysis ----
    def _store(self, user, plant_id, kind, filename, data):
        name = validate_upload(kind, filename, data)
        folder = os.path.join(self.upload_dir, str(int(plant_id)))
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, uuid.uuid4().hex + os.path.splitext(name)[1].lower())
        if os.path.commonpath([self.upload_dir, os.path.abspath(path)]) != self.upload_dir: raise ValueError("invalid path")
        with open(path, "wb") as f: f.write(data)
        with self.lock:
            self.db.execute("INSERT INTO uploads(plant_id,kind,original_name,stored_path,size,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?)",
                            (plant_id, kind, name, path, len(data), user["id"], now_iso()))
            self.db.commit()
        return path

    def _add_findings(self, plant_id, events, kind="observed"):
        with self.lock:
            for e in events:
                m_id = e.get("mitre_id") or D.MITRE_ICS.get(e.get("rule"), ("T0800", "ICS Attack"))[0]
                m_name = e.get("mitre_name") or D.MITRE_ICS.get(e.get("rule"), ("T0800", "ICS Attack"))[1]
                self.db.execute(
                    "INSERT INTO findings(plant_id,rule,severity,title,asset,evidence,kind,ts,created_at,mitre_id,mitre_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (plant_id, e["rule"], e["sev"], e["title"], e["asset"], e["evidence"], kind, e["ts"], now_iso(), m_id, m_name)
                )
            self.db.commit()

    def analyze_pcap(self, user, plant_id, filename, data):
        self.authorize(user, plant_id)
        self._store(user, plant_id, "pcap", filename, data)
        packets, total = D.parse_pcap(data)
        assets = {a["ip"]: a["code"] for a in self.assets(user, plant_id) if a["ip"]}
        allow = json.loads(self.db.execute("SELECT write_allow FROM plants WHERE id=?", (plant_id,)).fetchone()[0])
        events = D.detect(packets, {"assets": assets, "allow": allow})
        self._add_findings(plant_id, events)
        self.audit(user["username"], "pcap_analyzed", f"plant {plant_id}, {total} packets, {len(events)} findings")
        return dict(packets=total, findings=events)

    def analyze_telemetry(self, user, plant_id, filename, data, column, lo, hi, plausible=(0, 10000)):
        self.authorize(user, plant_id)
        if column not in D.REQUIRED[1:5]: raise ValueError("unknown parameter column")
        self._store(user, plant_id, "csv", filename, data)
        rows = D.parse_telemetry(data.decode("utf-8", "replace"), column, *plausible)
        res = D.analyze_series(rows, lo, hi)
        if res["deviations"]:
            self._add_findings(plant_id, [dict(rule="R-PV-01", sev="medium", asset="PLC-01", ts=res["first_deviation"],
                title=f"{column} outside {lo} to {hi}", evidence=f"{res['deviations']} samples outside the limits")])
        self.audit(user["username"], "telemetry_analyzed", f"plant {plant_id}, {res['n']} rows")
        return res

    def analyze_audit_log(self, user, plant_id, filename, data):
        """Parses and ingests PLC host audit event log (CSV) for multi-source correlation."""
        self.authorize(user, plant_id)
        self._store(user, plant_id, "csv", filename, data)
        events = D.parse_plc_audit(data.decode("utf-8", "replace"))
        with self.lock:
            for ev in events:
                self.db.execute(
                    "INSERT INTO plc_audit_events(plant_id,asset_id,event_id,user,action,object,old_value,new_value,cpu_mode,source,ts,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (plant_id, ev["asset"], ev["event_id"], ev["user"], ev["action"], ev["object"], ev["old_value"], ev["new_value"], ev["cpu_mode"], ev["source"], ev["ts"], now_iso())
                )
            self.db.commit()
        # Surface security-relevant audit events as findings
        abnormal = [ev for ev in events if ev["action"] in ("REGISTER_WRITE", "MODE_CHANGE", "FORCE_OUTPUT")]
        if abnormal:
            findings_to_add = []
            for ab in abnormal:
                findings_to_add.append(dict(
                    rule="R-AU-01",
                    sev="high" if "REGISTER" in ab["action"] else "medium",
                    asset=ab["asset"] or "PLC-01",
                    ts=ab["ts"],
                    title=f"Host Audit: {ab['action']} on {ab.get('object') or 'PLC'}",
                    evidence=f"User '{ab.get('user') or 'unknown'}' executed {ab['action']} ({ab.get('old_value')} -> {ab.get('new_value')}) via {ab.get('source')}"
                ))
            self._add_findings(plant_id, findings_to_add, kind="observed")
        self.audit(user["username"], "audit_analyzed", f"plant {plant_id}, {len(events)} events")
        return dict(events=len(events), flagged=len(abnormal))

    def findings(self, user, plant_id):
        self.authorize(user, plant_id)
        return [dict(r) for r in self.db.execute("SELECT id,rule,severity,title,asset,evidence,kind,ts,mitre_id,mitre_name FROM findings WHERE plant_id=? ORDER BY ts", (plant_id,))]

    def correlation(self, user, plant_id, window=120, asset="PLC-01"):
        self.authorize(user, plant_id)
        f = self.findings(user, plant_id)
        net = [x for x in f if x["rule"].startswith(("R-MB", "R-AS", "R-PR"))]
        dev = next((x["ts"] for x in f if x["rule"] == "R-PV-01"), None)
        # Fetch host audit events for correlation
        audit_rows = [dict(r) for r in self.db.execute(
            "SELECT ts, asset_id as asset, action, object, user, old_value, new_value, source FROM plc_audit_events WHERE plant_id=?",
            (plant_id,)
        )]
        return D.correlate(net, audit_rows, dev, window, asset)

    def report_csv(self, user, plant_id):
        out = io.StringIO(); w = csv.writer(out)
        w.writerow(["rule", "severity", "title", "asset", "evidence", "evidence_type", "mitre_id", "mitre_name"])
        for x in self.findings(user, plant_id):
            w.writerow([csv_safe(x[k]) for k in ("rule", "severity", "title", "asset", "evidence", "kind", "mitre_id", "mitre_name")])
        self.audit(user["username"], "report_exported", f"plant {plant_id}")
        return out.getvalue()

    # ---- metrics, posture score & multi-plant summary ----
    def plant_summary(self, user, plant_id):
        self.authorize(user, plant_id)
        plant = self.db.execute("SELECT id, name FROM plants WHERE id=?", (plant_id,)).fetchone()
        if not plant: raise LookupError("plant not found")

        asset_counts = self.db.execute(
            "SELECT COUNT(*) as total, SUM(verified) as verified FROM assets WHERE plant_id=?", (plant_id,)
        ).fetchone()
        total_assets = asset_counts["total"] or 0
        verified_assets = asset_counts["verified"] or 0

        findings_rows = self.db.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE plant_id=? GROUP BY severity", (plant_id,)
        ).fetchall()
        sev_map = {r["severity"].lower(): r["count"] for r in findings_rows}
        high_findings = sev_map.get("high", 0)
        medium_findings = sev_map.get("medium", 0)
        low_findings = sev_map.get("low", 0)
        total_findings = sum(sev_map.values())

        score = 100 - (high_findings * 15) - (medium_findings * 8) - (low_findings * 3)
        if total_assets > 0:
            unverified = total_assets - verified_assets
            score -= min(unverified * 5, 20)
        score = max(0, min(100, score))

        return {
            "plant_id": plant["id"],
            "name": plant["name"],
            "total_assets": total_assets,
            "verified_assets": verified_assets,
            "total_findings": total_findings,
            "findings_by_severity": {
                "high": high_findings,
                "medium": medium_findings,
                "low": low_findings
            },
            "posture_score": score,
            "iec_62443_ready": verified_assets == total_assets and high_findings == 0
        }

    def fleet_summary(self, user):
        plant_list = self.plants(user)
        summaries = [self.plant_summary(user, p["id"]) for p in plant_list]
        total_assets = sum(s["total_assets"] for s in summaries)
        total_findings = sum(s["total_findings"] for s in summaries)
        high_findings = sum(s["findings_by_severity"]["high"] for s in summaries)
        avg_posture = round(sum(s["posture_score"] for s in summaries) / max(len(summaries), 1), 1)

        return {
            "plants_count": len(summaries),
            "total_assets": total_assets,
            "total_findings": total_findings,
            "high_severity_findings": high_findings,
            "average_posture_score": avg_posture,
            "plants": summaries
        }

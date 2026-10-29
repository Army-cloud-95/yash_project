"""Creates the database with four plants and five accounts. Passwords are hashed with scrypt.
Set OTS_ADMIN_PASSWORD / OTS_PLANT_PASSWORD to choose your own. Defaults are for local demos only."""
import json, os
from app.db import connect
from app.security import hash_password

PLANTS = [("Plant A Boiler House", ["10.20.4.50", "10.20.4.30"]), ("Plant B Water Treatment", ["10.40.1.50"]),
          ("Plant C Power Substation", ["10.30.1.50"]), ("Plant D Packaging Line", ["10.50.2.50"])]
ASSETS = {1: [("PLC-01", "Boiler line controller", "10.20.4.10"), ("RTU-04", "Remote pump RTU", "10.20.4.21"), ("HMI-02", "Operator panel", "10.20.4.50")],
          2: [("PLC-01", "Intake pump controller", "10.40.1.10"), ("RTU-02", "Reservoir level RTU", "10.40.1.21"), ("HMI-01", "Control room HMI", "10.40.1.50")],
          3: [("PLC-01", "Bay protection controller", "10.30.1.10"), ("RTU-03", "Transformer monitor RTU", "10.30.1.22"), ("HMI-01", "Station HMI", "10.30.1.50")],
          4: [("PLC-01", "Packaging line controller", "10.50.2.10"), ("HMI-01", "Line HMI", "10.50.2.50")]}

def seed(db, admin_pw="Admin@2026", plant_pw=None):
    plant_pw = plant_pw or {i: f"Plant{'ABCD'[i-1]}@2026" for i in range(1, 5)}
    for i, (n, allow) in enumerate(PLANTS, 1):
        db.execute("INSERT OR IGNORE INTO plants(id,name,write_allow) VALUES(?,?,?)", (i, n, json.dumps(allow)))
        for code, name, ip in ASSETS[i]:
            db.execute("INSERT OR IGNORE INTO assets(plant_id,code,name,ip,verified) VALUES(?,?,?,?,0)", (i, code, name, ip))
    db.execute("INSERT OR IGNORE INTO users(id,username,name,role,pw_hash) VALUES(1,'company.admin','Company Admin','company_admin',?)", (hash_password(admin_pw),))
    for i in range(1, 5):
        db.execute("INSERT OR IGNORE INTO users(id,username,name,role,pw_hash) VALUES(?,?,?,?,?)",
                   (i + 1, f"plant.{'abcd'[i-1]}", f"Plant {'ABCD'[i-1]} Operator", "plant_user", hash_password(plant_pw[i])))
        db.execute("INSERT OR IGNORE INTO user_plants(user_id,plant_id) VALUES(?,?)", (i + 1, i))
    for p in range(1, 5): db.execute("INSERT OR IGNORE INTO user_plants(user_id,plant_id) VALUES(1,?)", (p,))
    db.commit()

if __name__ == "__main__":
    path = os.environ.get("OTS_DB", "./data/otsentinel.db"); os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    seed(connect(path), os.environ.get("OTS_ADMIN_PASSWORD", "Admin@2026")); print("seeded", path)

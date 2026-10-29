# OT Sentinel — Industrial Cybersecurity Monitoring & Analysis Platform

> **Notice**: All industrial telemetry, network captures, and asset names are **SYNTHETIC** for demonstration and offline analysis.

OT Sentinel is an OT/ICS cybersecurity monitoring and multi-plant situational awareness platform designed for industrial networks. It integrates a React dashboard with a FastAPI backend featuring scrypt-hashed credentials, HMAC-SHA256 bearer tokens, per-plant access isolation, offline PCAP/telemetry analysis, deterministic detection rules, and SQLite-backed persistent findings and assets.

---

## Architecture Overview

```
ot-sentinel-demo/
├── backend/
│   ├── app/
│   │   ├── main.py        # FastAPI HTTP layer (CORS, error handlers, endpoints)
│   │   ├── service.py     # Core business logic, token validation & plant authorization
│   │   ├── detection.py   # Modbus/DNP3 offline packet parsing & detection rules
│   │   ├── security.py    # scrypt hashing, timing-safe compare, HMAC-SHA256 tokens
│   │   ├── telemetry.py   # CSV telemetry statistical parsing & excursion analysis
│   │   ├── correlation.py # Cross-source event correlation engine
│   │   └── db.py          # SQLite schema and connection management
│   ├── tests/             # Automated test suite (42 tests covering security & API)
│   ├── seed.py            # SQLite database seeder (4 plants, 5 user accounts)
│   ├── requirements.txt   # Python dependencies
│   └── .env.example       # Backend environment template
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   └── client.js  # Reusable API client (Bearer tokens, multipart uploads, error handlers)
│   │   ├── components/    # Layout, LoginPage, Header, Navigation, Modals
│   │   ├── views/         # Fleet Overview, Network Analysis, Process Analytics, Threat Intel, etc.
│   │   └── App.jsx        # Root application state & API integration wiring
│   └── package.json       # React + Vite frontend configuration
└── datasets/              # Sample PCAP network captures, telemetry CSVs, and datasheets
```

---

## Quickstart Guide

### 1. Backend Setup & Startup

#### Windows (PowerShell):
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env to verify OTS_SECRET or use the default generated token
python seed.py
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### macOS / Linux:
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python seed.py
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

* API Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* Health Check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### 2. Frontend Setup & Startup

```bash
cd frontend
npm install
npm run dev
```

* Open frontend: [http://localhost:5173](http://localhost:5173) (or [http://localhost:8080](http://localhost:8080) if configured)

To create a production build:
```bash
npm run build
npm run preview
```

---

## Seeded User Accounts

The database comes pre-populated with five accounts:

| Role | Username | Password | Authorized Plants |
|---|---|---|---|
| **Company Admin** | `company.admin` | `Admin@2026` | Fleet Overview and Plants 1–4 (All) |
| **Plant A Operator** | `plant.a` | `PlantA@2026` | Plant 1 (Plant A Boiler House) |
| **Plant B Operator** | `plant.b` | `PlantB@2026` | Plant 2 (Plant B Water Treatment) |
| **Plant C Operator** | `plant.c` | `PlantC@2026` | Plant 3 (Plant C Power Substation) |
| **Plant D Operator** | `plant.d` | `PlantD@2026` | Plant 4 (Plant D Packaging Line) |

---

## Datasets & Sample Files

Located in `datasets/`:
1. `03_plant_a_sample.pcap`: Sample Modbus/DNP3 industrial capture (728 packets) yielding 3 security findings (`R-MB-03` unauthorized write, `R-PR-01` protocol mix, `R-AS-01` unlisted IP).
2. `02_telemetry_plc01.csv`: 120 rows (30 s intervals) with pressure excursions (13 readings exceeding normal thresholds) and 2 missing values.
3. `04_plc_audit_events.csv`: Audit logs for correlation with network write events.
4. `01_nc400_plc_datasheet.pdf`: Mock PLC vendor datasheet for asset parsing.

---

## Running Automated Tests

Run the backend test suite (42 tests):
```bash
cd backend
python -m unittest discover -s tests -t .
```
All tests verify scrypt security, HMAC token validation, lockout after failed attempts, cross-plant authorization boundaries, PCAP upload parsing, telemetry bounds checking, and CSV report formula neutralization.

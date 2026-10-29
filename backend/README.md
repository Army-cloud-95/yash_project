# OT Sentinel Backend

FastAPI service providing server-side authentication, per-plant authorization, upload handling, deterministic offline detection, multi-source event correlation, and sanitized reporting.

## Test Suite Execution

Run the complete test suite:
```bash
python -m unittest discover -s tests -t .
```
- **47 automated tests**: covers password hashing (scrypt), token verification (HMAC-SHA256), brute-force lockout, cross-plant access control (Plant A vs Plant B), asset lifecycle (add/update/verify/delete), PCAP upload parsing, telemetry bounds checking, PLC host audit log ingestion & tri-source correlation, posture calculation, fleet summaries, and CSV formula neutralization.

## Environment Variables (.env)

| Variable | Default | Purpose |
|---|---|---|
| `OTS_SECRET` | *(required)* | 32+ character random secret used for HMAC-SHA256 token signing |
| `OTS_DB` | `./data/otsentinel.db` | Path to SQLite database file |
| `OTS_UPLOAD_DIR` | `./data/uploads` | Path to store uploaded PCAP/telemetry files |
| `OTS_TOKEN_TTL` | `3600` | Token time-to-live in seconds (1 hour) |
| `OTS_CORS_ORIGIN` | `http://localhost:8080,http://localhost:5173,http://127.0.0.1:8080,http://127.0.0.1:5173` | Allowed CORS origins for the frontend |

## Setup & Running

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python seed.py
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Windows (CMD)
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
copy .env.example .env
python seed.py
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python seed.py
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive API Documentation (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

## Seed Accounts

Pre-populated in `backend/data/otsentinel.db`:
- `company.admin` / `Admin@2026` (Access: All 4 plants)
- `plant.a` / `PlantA@2026` (Access: Plant A Boiler House, ID: 1)
- `plant.b` / `PlantB@2026` (Access: Plant B Water Treatment, ID: 2)
- `plant.c` / `PlantC@2026` (Access: Plant C Power Substation, ID: 3)
- `plant.d` / `PlantD@2026` (Access: Plant D Packaging Line, ID: 4)

## Endpoints Catalog

### Authentication & Users
| Method | Path | Description | Authorization |
|---|---|---|---|
| `POST` | `/auth/login` | Authenticate with username & password; returns bearer token | Public |
| `POST` | `/auth/change-password` | Rotate account password | Bearer Token |
| `GET` | `/me` | Get current authenticated user profile & plant permissions | Bearer Token |

### Plants & Fleet Overview
| Method | Path | Description | Authorization |
|---|---|---|---|
| `GET` | `/plants` | List plants authorized for current user | Bearer Token |
| `GET` | `/plants/{pid}/summary` | Get plant statistics, risk breakdown, and posture score | Bearer Token (Plant match) |
| `GET` | `/fleet/summary` | Aggregate multi-plant metrics across all authorized facilities | Bearer Token (Admin / multi-plant) |

### Asset Management (IEC 62443 Lifecycle)
| Method | Path | Description | Authorization |
|---|---|---|---|
| `GET` | `/plants/{pid}/assets` | List registered assets for plant | Bearer Token (Plant match) |
| `POST` | `/plants/{pid}/assets` | Add new asset to plant inventory | Bearer Token (Plant match) |
| `PUT` | `/plants/{pid}/assets/{code}` | Update asset details (IP, firmware, manufacturer, model) | Bearer Token (Plant match) |
| `POST` | `/plants/{pid}/assets/{code}/verify` | Verify or unverify an asset (rogue device mitigation) | Bearer Token (Plant match) |
| `DELETE` | `/plants/{pid}/assets/{code}` | Decommission / remove asset from plant | Bearer Token (Plant match) |

### Analysis & Ingestion Pipelines
| Method | Path | Description | Authorization |
|---|---|---|---|
| `POST` | `/plants/{pid}/uploads/pcap` | Upload and analyze industrial PCAP capture | Bearer Token (Plant match) |
| `POST` | `/plants/{pid}/uploads/telemetry` | Upload and analyze sensor CSV telemetry | Bearer Token (Plant match) |
| `POST` | `/plants/{pid}/uploads/audit` | Ingest PLC host audit event logs (CSV) | Bearer Token (Plant match) |

### Findings, Correlation & Reports
| Method | Path | Description | Authorization |
|---|---|---|---|
| `GET` | `/plants/{pid}/findings` | Retrieve all persistent findings with MITRE ATT&CK tags | Bearer Token (Plant match) |
| `GET` | `/plants/{pid}/correlation` | Correlate network writes + host audit logs + telemetry deviations | Bearer Token (Plant match) |
| `GET` | `/plants/{pid}/report.csv` | Download formula-neutralized CSV report | Bearer Token (Plant match) |

### Audit Trail & Compliance
| Method | Path | Description | Authorization |
|---|---|---|---|
| `GET` | `/audit` | Fleet-wide auditable security log | Bearer Token (Company Admin) |
| `GET` | `/plants/{pid}/audit` | Plant-scoped security event audit log | Bearer Token (Plant match) |

## Security & Architecture Highlights

1. **High-Concurrency SQLite PRAGMAs**: Configured with Write-Ahead Logging (`WAL`), `synchronous=NORMAL`, and `busy_timeout=5000` to eliminate database locking under concurrent API traffic.
2. **Password Hashing**: `hashlib.scrypt` with random 16-byte salt and constant-time comparison (`secrets.compare_digest`).
3. **Brute Force Defense**: Account lockout after 5 consecutive failed sign-in attempts within 15 minutes.
4. **Plant-Level Access Control**: Enforced within `Service.authorize()` before any database query or file operation is executed. Non-admin users attempting cross-plant access receive `403 Forbidden`.
5. **MITRE ATT&CK for ICS**: Every detection event is mapped to formal industrial techniques (e.g. `T0855 Unauthorized Command Message`, `T0846 Remote System Discovery`, `T0836 Modify Parameter`).
6. **Tri-Source Correlation Engine**: Links network packet writes, PLC host audit logs, and process sensor excursions onto a unified timeline with calculated confidence.
7. **CSV Injection Defense**: Formula neutralization prefixes `'` to any cell starting with `=`, `+`, `-`, or `@`.

# OT Sentinel Backend

FastAPI service providing server-side authentication, per-plant authorization, upload handling, deterministic offline detection, event correlation, and sanitized reporting.

## Test Suite Execution

Run the complete test suite:
```bash
python -m unittest discover -s tests -t .
```
- **42 automated tests**: covers password hashing (scrypt), token verification (HMAC-SHA256), brute-force lockout, cross-plant access control (Plant A vs Plant B), PCAP upload parsing, telemetry bounds checking, database persistence, and CSV injection formula neutralization.

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

- **Interactive API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

## Seed Accounts

Pre-populated in `backend/data/otsentinel.db`:
- `company.admin` / `Admin@2026` (Access: All 4 plants)
- `plant.a` / `PlantA@2026` (Access: Plant A Boiler House, ID: 1)
- `plant.b` / `PlantB@2026` (Access: Plant B Water Treatment, ID: 2)
- `plant.c` / `PlantC@2026` (Access: Plant C Power Substation, ID: 3)
- `plant.d` / `PlantD@2026` (Access: Plant D Packaging Line, ID: 4)

## Endpoints

| Method | Path | Description | Authorization |
|---|---|---|---|
| `POST` | `/auth/login` | Authenticate with username & password; returns bearer token | Public |
| `GET` | `/health` | Service health status | Public |
| `GET` | `/me` | Get current authenticated user profile & plant permissions | Bearer Token |
| `GET` | `/plants` | List plants authorized for current user | Bearer Token |
| `GET` | `/plants/{pid}/assets` | List registered assets for plant | Bearer Token (Plant match required) |
| `POST` | `/plants/{pid}/assets` | Add new asset to plant | Bearer Token (Plant match required) |
| `POST` | `/plants/{pid}/uploads/pcap` | Upload and analyze industrial PCAP file | Bearer Token (Plant match required) |
| `POST` | `/plants/{pid}/uploads/telemetry` | Upload and analyze sensor CSV telemetry | Bearer Token (Plant match required) |
| `GET` | `/plants/{pid}/findings` | Retrieve all persistent findings for plant | Bearer Token (Plant match required) |
| `GET` | `/plants/{pid}/correlation` | Retrieve cross-correlated security events | Bearer Token (Plant match required) |
| `GET` | `/plants/{pid}/report.csv` | Download formula-neutralized CSV report | Bearer Token (Plant match required) |

## Security Controls

1. **Password Hashing**: `hashlib.scrypt` with random 16-byte salt and constant-time comparison (`secrets.compare_digest`).
2. **Brute Force Defense**: Account lockout after 5 consecutive failed sign-in attempts within 15 minutes.
3. **Plant-Level Access Control**: Enforced within `Service.authorize()` before any database query or file operation is executed. Non-admin users attempting cross-plant access receive `403 Forbidden`.
4. **File Upload Security**: Magic-byte content validation, maximum file size check (50 MB), extension whitelisting, randomized safe storage filename outside web root. Offline parsing only (zero network transmission or replay).
5. **CSV Injection Defense**: Formula neutralization prefixes `'` to any cell starting with `=`, `+`, `-`, or `@`.

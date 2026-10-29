"""HTTP layer. Thin on purpose: all rules live in service.py and detection.py."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from backend folder or current working directory
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from .service import LIMITS, Service, TooManyAttempts

secret = os.environ.get("OTS_SECRET", "")
if not secret or len(secret) < 16:
    secret = "ots-sentinel-dev-secret-key-32chars-min!!"

db_path = os.environ.get("OTS_DB", "./data/otsentinel.db")
upload_dir = os.environ.get("OTS_UPLOAD_DIR", "./data/uploads")
os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
os.makedirs(os.path.abspath(upload_dir), exist_ok=True)

svc = Service(db_path, secret, upload_dir, int(os.environ.get("OTS_TOKEN_TTL", "3600")))
app = FastAPI(
    title="OT Sentinel API",
    description="OT/ICS cybersecurity monitoring, plant-level authorization, and offline industrial analysis engine.",
    version="2.0"
)

raw_origins = os.environ.get("OTS_CORS_ORIGIN", "http://localhost:8080,http://localhost:5173,http://127.0.0.1:8080,http://127.0.0.1:5173")
cors_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

@app.exception_handler(PermissionError)
async def _403(r: Request, e): return JSONResponse({"detail": str(e)}, status_code=403)
@app.exception_handler(LookupError)
async def _404(r: Request, e): return JSONResponse({"detail": str(e)}, status_code=404)
@app.exception_handler(ValueError)
async def _422(r: Request, e): return JSONResponse({"detail": str(e)}, status_code=422)
@app.exception_handler(TooManyAttempts)
async def _429(r: Request, e): return JSONResponse({"detail": "too many failed attempts, try again later"}, status_code=429)

def current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401, "missing bearer token")
    try: return svc.user_from_token(authorization[7:])
    except PermissionError as e: raise HTTPException(401, str(e))

class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)

class ChangePasswordIn(BaseModel):
    old_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=8, max_length=128)

class AssetIn(BaseModel):
    code: str = Field(max_length=32)
    name: str = Field(max_length=120)
    ip: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    firmware: str | None = None

class AssetUpdateIn(BaseModel):
    name: str | None = Field(None, max_length=120)
    ip: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    firmware: str | None = None

class AssetVerifyIn(BaseModel):
    verified: bool = True

@app.get("/health", tags=["System"])
def health(): return {"status": "ok"}

# ---- Authentication & User Management ----
@app.post("/auth/login", tags=["Authentication"])
def login(b: LoginIn):
    try: return {"access_token": svc.login(b.username, b.password), "token_type": "bearer"}
    except PermissionError: raise HTTPException(401, "invalid credentials")

@app.post("/auth/change-password", tags=["Authentication"])
def change_password(b: ChangePasswordIn, u=Depends(current_user)):
    return svc.change_password(u, b.old_password, b.new_password)

@app.get("/me", tags=["Authentication"])
def me(u=Depends(current_user)):
    return {**u, "plants": sorted(u["plants"])}

# ---- Plants & Multi-Plant Overview ----
@app.get("/plants", tags=["Plants"])
def plants(u=Depends(current_user)):
    return svc.plants(u)

@app.get("/fleet/summary", tags=["Plants"])
def fleet_summary(u=Depends(current_user)):
    return svc.fleet_summary(u)

@app.get("/plants/{pid}/summary", tags=["Plants"])
def plant_summary(pid: int, u=Depends(current_user)):
    return svc.plant_summary(u, pid)

# ---- Asset Inventory Lifecycle ----
@app.get("/plants/{pid}/assets", tags=["Assets"])
def assets(pid: int, u=Depends(current_user)):
    return svc.assets(u, pid)

@app.post("/plants/{pid}/assets", status_code=201, tags=["Assets"])
def add_asset(pid: int, b: AssetIn, u=Depends(current_user)):
    svc.add_asset(u, pid, **b.model_dump())
    return {"ok": True}

@app.put("/plants/{pid}/assets/{code}", tags=["Assets"])
def update_asset(pid: int, code: str, b: AssetUpdateIn, u=Depends(current_user)):
    return svc.update_asset(u, pid, code, **b.model_dump(exclude_unset=True))

@app.post("/plants/{pid}/assets/{code}/verify", tags=["Assets"])
def verify_asset(pid: int, code: str, b: AssetVerifyIn, u=Depends(current_user)):
    return svc.verify_asset(u, pid, code, b.verified)

@app.delete("/plants/{pid}/assets/{code}", tags=["Assets"])
def delete_asset(pid: int, code: str, u=Depends(current_user)):
    return svc.delete_asset(u, pid, code)

# ---- Uploads & Industrial Analysis ----
async def _read(f: UploadFile, kind: str):
    data = await f.read(LIMITS[kind][0] * 1048576 + 1)
    return f.filename or "upload", data

@app.post("/plants/{pid}/uploads/pcap", tags=["Analysis"])
async def up_pcap(pid: int, file: UploadFile = File(...), u=Depends(current_user)):
    n, d = await _read(file, "pcap")
    return svc.analyze_pcap(u, pid, n, d)

@app.post("/plants/{pid}/uploads/telemetry", tags=["Analysis"])
async def up_tel(pid: int, file: UploadFile = File(...), column: str = Query("pressure_bar"), lo: float = Query(...), hi: float = Query(...), u=Depends(current_user)):
    n, d = await _read(file, "csv")
    return svc.analyze_telemetry(u, pid, n, d, column, lo, hi)

@app.post("/plants/{pid}/uploads/audit", tags=["Analysis"])
async def up_audit(pid: int, file: UploadFile = File(...), u=Depends(current_user)):
    n, d = await _read(file, "csv")
    return svc.analyze_audit_log(u, pid, n, d)

# ---- Findings & Correlation ----
@app.get("/plants/{pid}/findings", tags=["Findings"])
def findings(pid: int, u=Depends(current_user)):
    return svc.findings(u, pid)

@app.get("/plants/{pid}/correlation", tags=["Findings"])
def correlation(pid: int, window: int = Query(120, ge=10, le=600), u=Depends(current_user)):
    return svc.correlation(u, pid, window)

@app.get("/plants/{pid}/report.csv", tags=["Reporting"])
def report(pid: int, u=Depends(current_user)):
    return Response(svc.report_csv(u, pid), media_type="text/csv")

# ---- Audit Trail & Compliance ----
@app.get("/audit", tags=["Compliance"])
def audit_all(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), action: str | None = None, u=Depends(current_user)):
    return svc.get_audit_log(u, plant_id=None, limit=limit, offset=offset, action=action)

@app.get("/plants/{pid}/audit", tags=["Compliance"])
def plant_audit(pid: int, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), action: str | None = None, u=Depends(current_user)):
    return svc.get_audit_log(u, plant_id=pid, limit=limit, offset=offset, action=action)

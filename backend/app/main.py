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
app = FastAPI(title="OT Sentinel API", version="1.0")

raw_origins = os.environ.get("OTS_CORS_ORIGIN", "http://localhost:8080,http://localhost:5173,http://127.0.0.1:8080,http://127.0.0.1:5173")
cors_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
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

class AssetIn(BaseModel):
    code: str = Field(max_length=32); name: str = Field(max_length=120)
    ip: str | None = None; manufacturer: str | None = None; model: str | None = None; firmware: str | None = None

@app.get("/health")
def health(): return {"status": "ok"}

@app.post("/auth/login")
def login(b: LoginIn):
    try: return {"access_token": svc.login(b.username, b.password), "token_type": "bearer"}
    except PermissionError: raise HTTPException(401, "invalid credentials")

@app.get("/me")
def me(u=Depends(current_user)): return {**u, "plants": sorted(u["plants"])}
@app.get("/plants")
def plants(u=Depends(current_user)): return svc.plants(u)
@app.get("/plants/{pid}/assets")
def assets(pid: int, u=Depends(current_user)): return svc.assets(u, pid)
@app.post("/plants/{pid}/assets", status_code=201)
def add_asset(pid: int, b: AssetIn, u=Depends(current_user)): svc.add_asset(u, pid, **b.model_dump()); return {"ok": True}

async def _read(f: UploadFile, kind: str):
    data = await f.read(LIMITS[kind][0] * 1048576 + 1)
    return f.filename or "upload", data

@app.post("/plants/{pid}/uploads/pcap")
async def up_pcap(pid: int, file: UploadFile = File(...), u=Depends(current_user)):
    n, d = await _read(file, "pcap"); return svc.analyze_pcap(u, pid, n, d)

@app.post("/plants/{pid}/uploads/telemetry")
async def up_tel(pid: int, file: UploadFile = File(...), column: str = Query("pressure_bar"), lo: float = Query(...), hi: float = Query(...), u=Depends(current_user)):
    n, d = await _read(file, "csv"); return svc.analyze_telemetry(u, pid, n, d, column, lo, hi)

@app.get("/plants/{pid}/findings")
def findings(pid: int, u=Depends(current_user)): return svc.findings(u, pid)
@app.get("/plants/{pid}/correlation")
def correlation(pid: int, window: int = Query(120, ge=10, le=600), u=Depends(current_user)): return svc.correlation(u, pid, window)
@app.get("/plants/{pid}/report.csv")
def report(pid: int, u=Depends(current_user)): return Response(svc.report_csv(u, pid), media_type="text/csv")

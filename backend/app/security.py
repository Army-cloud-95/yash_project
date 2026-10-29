"""Password hashing, signed tokens and filename safety. Standard library only."""
import base64, hashlib, hmac, json, os, re, time

def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    n, r, p = 2**14, 8, 1
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        cand = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(cand.hex(), dk)

def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _sig(secret: str, body: str) -> str:
    return _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())

def make_token(secret: str, sub: str, ttl: int = 3600, now: float | None = None) -> str:
    body = _b64(json.dumps({"sub": sub, "exp": int((now or time.time()) + ttl)}).encode())
    return body + "." + _sig(secret, body)

def read_token(secret: str, token: str, now: float | None = None) -> str:
    try:
        body, sig = token.split(".")
        ok = hmac.compare_digest(sig, _sig(secret, body))
        data = json.loads(_unb64(body))
    except (ValueError, TypeError, KeyError):
        raise ValueError("invalid token")
    if not ok:
        raise ValueError("invalid token")
    if data.get("exp", 0) < (now or time.time()):
        raise ValueError("token expired")
    return data["sub"]

def safe_filename(name: str) -> str:
    base = os.path.basename((name or "").replace("\\", "/"))
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")[:100]
    return base or "upload"

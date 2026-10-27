import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import ALLOWED_ORIGINS, NOTIFY_SERVICE_URL
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Vary"] = "Origin"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s (%s)", request.url.path, type(exc).__name__)
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ShareRequest(BaseModel):
    password: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login for username: %s", payload.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    # nosec B105 - "bearer" is the OAuth token type, not a hardcoded password.
return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    results = search_scans_by_query(db, q, current_user.id)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id, models.ScanResult.owner_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

@app.post("/scans/{scan_id}/share")
def create_share_link(
    scan_id: int,
    request: Request,
    payload: ShareRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    password_hash = get_password_hash(payload.password) if payload.password else None
    expires_at = datetime.utcnow() + timedelta(hours=24)
    share = models.SharedReportToken(
        token_hash=token_hash,
        scan_id=scan.id,
        password_hash=password_hash,
        expires_at=expires_at,
    )
    db.add(share)
    db.commit()
    share_url = str(request.base_url).rstrip("/") + "/share/" + raw_token
    return {"share_url": share_url, "expires_at": expires_at.isoformat() + "Z"}


@app.get("/share/{token}")
def read_shared_report(
    token: str,
    response: Response,
    password: Optional[str] = None,
    db: Session = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    share = db.query(models.SharedReportToken).filter(
        models.SharedReportToken.token_hash == token_hash
    ).first()
    if not share or share.expires_at <= datetime.utcnow():
        raise HTTPException(status_code=404, detail="Share link not found or expired")
    if share.password_hash and (
        not password or not verify_password(password, share.password_hash)
    ):
        raise HTTPException(status_code=401, detail="A valid share password is required")
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == share.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanOut.model_validate(scan).model_dump(mode="json")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}

"""Authenticated, role-authorized, local-first HR workflow API.

This is a working training service, NOT a production deployment recipe. No public
hosting, real applicant data, or external messaging. User accounts are provisioned
by the operator; passwords are never seeded or included in the repository.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .workflow import RecruitingWorkspace, WorkflowError, DEPARTMENTS
from .provider_clients import GreenhouseV3Reader, WorkdayTenantReader, ProviderError

WEB = Path(__file__).resolve().parents[2] / "secure_web"
COOKIE = "tahr_session"
SESSION_SECONDS = 8 * 60 * 60
LOCK_SECONDS = 15 * 60
MAX_LOGIN_FAILURES = 5
# OWASP-recommended floor: Argon2id, 19 MiB, 2 iterations, parallelism 1.
HASHER = PasswordHasher(time_cost=2, memory_cost=19_456, parallelism=1)
IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,39}$")
PERMISSIONS = {
    "admin": {"requisitions:read", "requisitions:create", "requisitions:approve", "applications:read", "applications:create", "applications:advance", "interviews:schedule", "metrics:read", "audit:read", "integrations:probe"},
    "recruiter": {"requisitions:read", "applications:read", "applications:create", "applications:advance", "interviews:schedule", "metrics:read"},
    "hiring_manager": {"requisitions:read", "requisitions:create", "requisitions:approve", "metrics:read"},
    "analyst": {"metrics:read"},
    "auditor": {"audit:read"},
}
ROLES = tuple(PERMISSIONS)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class IdentityStore:
    """SQLite auth store with token-hashed sessions and persistent failed-attempt tracking."""

    def __init__(self, database: str):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(database, check_same_thread=False)
        # Local SQLite account store must be readable only by the current user.
        if database != ":memory:" and os.name == "posix":
            os.chmod(database, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions (
            token_digest TEXT PRIMARY KEY, csrf_digest TEXT NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT NOT NULL, occurred INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS attempts_user_time ON login_attempts(username, occurred);
        CREATE TABLE IF NOT EXISTS access_audit (
            id INTEGER PRIMARY KEY, occurred INTEGER NOT NULL,
            actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
        """)
        self.db.commit()
        # Avoid a data-dependent password verification timing signal for unknown users.
        self._dummy_hash = HASHER.hash("unusable_password_for_timing_only")

    def create_user(self, username: str, password: str, role: str) -> None:
        if not IDENTITY_RE.fullmatch(username):
            raise ValueError("Username must be 3–40 lowercase letters, numbers, dots, underscores or hyphens")
        if role not in ROLES:
            raise ValueError("Unknown role")
        if not 15 <= len(password) <= 1024:
            raise ValueError("Use a password 15–1024 characters long")
        with self.lock, self.db:
            self.db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                            (username, HASHER.hash(password), role))
            self._audit(username, "user_provisioned", f"role={role}")

    def set_role(self, username: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError("Unknown role")
        with self.lock, self.db:
            cur = self.db.execute("UPDATE users SET role=? WHERE username=?", (role, username))
            if cur.rowcount != 1:
                raise ValueError("No such user")
            self.db.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)", (username,))
            self._audit(username, "role_changed_sessions_revoked", f"role={role}")

    def disable(self, username: str) -> None:
        with self.lock, self.db:
            cur = self.db.execute("UPDATE users SET enabled=0 WHERE username=?", (username,))
            if cur.rowcount != 1:
                raise ValueError("No such user")
            self.db.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)", (username,))
            self._audit(username, "disabled_sessions_revoked", "")

    def _audit(self, actor: str, event: str, detail: str = "") -> None:
        self.db.execute("INSERT INTO access_audit(occurred,actor,event,detail) VALUES(?,?,?,?)",
                        (int(time.time()), actor, event, detail[:100]))

    def authenticate(self, username: str, password: str) -> tuple[str, str] | None:
        now = int(time.time())
        username = username.strip().lower()[:40]
        with self.lock, self.db:
            self.db.execute("DELETE FROM login_attempts WHERE occurred<?", (now - LOCK_SECONDS,))
            recent = self.db.execute("SELECT COUNT(*) FROM login_attempts WHERE username=?", (username,)).fetchone()[0]
            row = self.db.execute("SELECT * FROM users WHERE username=? AND enabled=1", (username,)).fetchone()
            valid = False
            try:
                valid = HASHER.verify(row["password_hash"] if row else self._dummy_hash, password)
            except (VerifyMismatchError, InvalidHashError, VerificationError):
                pass
            if recent >= MAX_LOGIN_FAILURES or not row or not valid:
                self.db.execute("INSERT INTO login_attempts VALUES(?,?)", (username, now))
                self._audit(username, "login_denied", "rate_limited" if recent >= MAX_LOGIN_FAILURES else "bad_credentials")
                return None
            self.db.execute("DELETE FROM login_attempts WHERE username=?", (username,))
            # Single active login per user; new login invalidates old sessions.
            self.db.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
            token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
            self.db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (digest(token), digest(csrf), row["id"], now + SESSION_SECONDS))
            self._audit(username, "login_success")
            return token, csrf

    def identity(self, token: str | None) -> dict | None:
        if not token or len(token) > 200:
            return None
        with self.lock:
            row = self.db.execute("""SELECT u.username,u.role,s.csrf_digest,s.expires
                FROM sessions s JOIN users u ON u.id=s.user_id
                WHERE s.token_digest=? AND u.enabled=1""", (digest(token),)).fetchone()
            if row is None or row["expires"] <= int(time.time()):
                return None
            return dict(row)

    def check_csrf(self, token: str, csrf: str | None) -> bool:
        identity = self.identity(token)
        return bool(identity and csrf and len(csrf) <= 200 and hmac.compare_digest(identity["csrf_digest"], digest(csrf)))

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self.lock, self.db:
            row = self.db.execute("SELECT u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_digest=?", (digest(token),)).fetchone()
            self.db.execute("DELETE FROM sessions WHERE token_digest=?", (digest(token),))
            if row:
                self._audit(row["username"], "logout")

    def log(self, actor: str, event: str, entity: str) -> None:
        with self.lock, self.db:
            self._audit(actor, event, entity)

    def audit(self) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.db.execute(
                "SELECT occurred,actor,event,detail FROM access_audit ORDER BY id DESC LIMIT 100")]


class IntegrationProbe(BaseModel):
    provider: Literal["greenhouse", "workday"]


class Login(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=1, max_length=1024)


class RequisitionCreate(BaseModel):
    title: str = Field(min_length=1, max_length=90)
    department: Literal["Analytics", "Engineering", "Finance & Operations", "People & Culture", "Product", "Customer Success"]
    budget_usd: int = Field(ge=30000, le=500000)


class RequisitionApprove(BaseModel):
    req_id: str = Field(min_length=1, max_length=50)


class ApplicationCreate(BaseModel):
    req_id: str = Field(min_length=1, max_length=50)
    source: str = Field(min_length=1, max_length=50)


class ApplicationAdvance(BaseModel):
    app_id: str = Field(min_length=1, max_length=50)
    stage: str = Field(min_length=1, max_length=30)
    reason: str = Field(default="", max_length=160)


class InterviewCreate(BaseModel):
    app_id: str = Field(min_length=1, max_length=50)
    scheduled_at: str = Field(min_length=12, max_length=60)
    interviewer: str = Field(min_length=1, max_length=90)
    mode: Literal["Video", "Phone", "On-site"] = "Video"


def create_app(identity_db: str, workspace_db: str = ":memory:", *, cookie_secure: bool = False,
               allowed_hosts: list[str] | None = None) -> FastAPI:
    """Create the local-first API. `cookie_secure=False` is ONLY valid on loopback."""
    auth = IdentityStore(identity_db)
    workspace = RecruitingWorkspace(workspace_db)
    app = FastAPI(title="Synthetic Talent Operations Secure API", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.auth = auth
    app.state.workspace = workspace
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or ["localhost", "127.0.0.1", "testserver"])

    @app.middleware("http")
    async def harden(request: Request, call_next):
        # Explicitly disallow cross-origin browser writes and ambiguous content types.
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin", "")
            if origin:
                host = request.headers.get("host", "")
                expected = ("https" if cookie_secure else "http") + "://" + host
                if origin != expected:
                    return JSONResponse({"error": "Cross-origin request blocked"}, status_code=403)
            if not request.headers.get("content-type", "").lower().startswith("application/json"):
                return JSONResponse({"error": "JSON required"}, status_code=415)
            length = request.headers.get("content-length", "")
            if not length.isdigit():
                return JSONResponse({"error": "Content-Length required"}, status_code=411)
            if int(length) > 8192:
                return JSONResponse({"error": "Payload too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        return response

    def current(request: Request) -> dict:
        user = auth.identity(request.cookies.get(COOKIE))
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        return user

    def allow(permission: str):
        def guard(request: Request, user: dict = Depends(current)) -> dict:
            if permission not in PERMISSIONS[user["role"]]:
                auth.log(user["username"], "authorization_denied", permission)
                raise HTTPException(status_code=403, detail="Forbidden")
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                if not auth.check_csrf(request.cookies.get(COOKIE, ""), request.headers.get("X-CSRF-Token")):
                    raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
            return user
        return guard

    def execute(actor: str, action: str, fn):
        try:
            result = fn()
        except (WorkflowError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        auth.log(actor, action, result.get("id", "entity"))
        return {"ok": True, "result": result}

    @app.get("/healthz")
    def health():
        return {"status": "ok", "data_class": "synthetic", "auth": "required"}

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html", media_type="text/html")

    @app.get("/secure.css")
    def css():
        return FileResponse(WEB / "secure.css", media_type="text/css")

    @app.get("/secure.js")
    def script():
        return FileResponse(WEB / "secure.js", media_type="text/javascript")

    @app.post("/api/auth/login")
    def login(data: Login, response: Response):
        result = auth.authenticate(data.username, data.password)
        if result is None:
            raise HTTPException(status_code=401, detail="Invalid credentials or temporarily locked")
        token, csrf = result
        response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, httponly=True, secure=cookie_secure,
                            samesite="strict", path="/")
        return {"ok": True, "csrf_token": csrf, "username": data.username.lower()}

    @app.get("/api/auth/me")
    def me(user: dict = Depends(current)):
        return {"username": user["username"], "role": user["role"],
                "permissions": sorted(PERMISSIONS[user["role"]])}

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response, _user: dict = Depends(current)):
        # Logout should remain available even when an XSS defense has cleared the CSRF token;
        # a cross-site logout cannot forge the strict same-site cookie and Origin check.
        auth.logout(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/", samesite="strict", secure=cookie_secure)
        return {"ok": True}

    @app.get("/api/requisitions")
    def requisitions(user: dict = Depends(allow("requisitions:read"))):
        return {"items": workspace.snapshot()["requisitions"]}

    @app.get("/api/applications")
    def applications(user: dict = Depends(allow("applications:read"))):
        return {"items": workspace.snapshot()["applications"]}

    @app.post("/api/requisitions", status_code=201)
    def create_req(data: RequisitionCreate, user: dict = Depends(allow("requisitions:create"))):
        return execute(user["username"], "requisition_created", lambda: workspace.create_requisition(
            data.title, data.department, data.budget_usd, user["username"]))

    @app.post("/api/requisitions/approve")
    def approve_req(data: RequisitionApprove, user: dict = Depends(allow("requisitions:approve"))):
        return execute(user["username"], "requisition_approved", lambda: workspace.approve_requisition(data.req_id, user["username"]))

    @app.post("/api/applications", status_code=201)
    def create_application(data: ApplicationCreate, user: dict = Depends(allow("applications:create"))):
        return execute(user["username"], "application_created", lambda: workspace.create_application(data.req_id, data.source, user["username"]))

    @app.post("/api/applications/advance")
    def advance(data: ApplicationAdvance, user: dict = Depends(allow("applications:advance"))):
        return execute(user["username"], "stage_advanced", lambda: workspace.advance_application(data.app_id, data.stage, user["username"], data.reason))

    @app.post("/api/interviews", status_code=201)
    def interview(data: InterviewCreate, user: dict = Depends(allow("interviews:schedule"))):
        return execute(user["username"], "interview_scheduled", lambda: workspace.schedule_interview(data.app_id, data.scheduled_at, data.interviewer, data.mode))

    @app.get("/api/metrics")
    def metrics(user: dict = Depends(allow("metrics:read"))):
        snap = workspace.snapshot()
        apps = snap["applications"]
        return {"synthetic": True, "requisitions": len(snap["requisitions"]),
                "applications": len(apps),
                "by_stage": {stage: sum(a["stage"] == stage for a in apps) for stage in sorted(set(a["stage"] for a in apps))}}

    @app.post("/api/integrations/probe")
    def integration_probe(data: IntegrationProbe, user: dict = Depends(allow("integrations:probe"))):
        # Only admins; read-only; no caller-controlled URLs or secrets in body.
        # No outbound request occurs without operator-configured credentials.
        try:
            if data.provider == "greenhouse":
                client_id, secret = os.getenv("GREENHOUSE_CLIENT_ID"), os.getenv("GREENHOUSE_CLIENT_SECRET")
                if not client_id or not secret:
                    raise HTTPException(status_code=503, detail="Greenhouse connection not configured")
                jobs = GreenhouseV3Reader(client_id, secret).list_job_identifiers(max_pages=2)
                summary = {"provider": "greenhouse", "read_only": True, "job_count": len(jobs)}
            else:
                endpoint, token = os.getenv("WORKDAY_API_ENDPOINT"), os.getenv("WORKDAY_ACCESS_TOKEN")
                if not endpoint or not token:
                    raise HTTPException(status_code=503, detail="Workday connection not configured")
                summary = WorkdayTenantReader(endpoint, token).read_summary()
        except ProviderError:
            raise HTTPException(status_code=502, detail="Provider connection failed; check private server logs") from None
        auth.log(user["username"], "read_only_provider_probe", data.provider)
        return summary

    @app.get("/api/audit")
    def audit(user: dict = Depends(allow("audit:read"))):
        return {"items": auth.audit()}

    return app


def run_local():
    import uvicorn
    # Never accept a configurable 0.0.0.0 bind for this unaudited training service.
    base = os.getenv("TAHR_RUNTIME_DIR", str(Path.home() / ".tahr-local"))
    Path(base).mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(base, 0o700)
    app = create_app(str(Path(base) / "identities.sqlite"), str(Path(base) / "workspace.sqlite"))
    print("Synthetic secure HR training server on http://127.0.0.1:8766; never expose publicly")
    uvicorn.run(app, host="127.0.0.1", port=8766, access_log=False)


if __name__ == "__main__":
    run_local()

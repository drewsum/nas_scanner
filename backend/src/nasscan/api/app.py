import time
from pathlib import Path as FsPath

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import text

from nasscan import __version__
from nasscan.api import auth
from nasscan.api.deps import DB
from nasscan.config import get_settings


class Health(BaseModel):
    status: str
    version: str
    commit: str
    database: bool


class SessionOut(BaseModel):
    auth_enabled: bool  # false: no NASSCAN_ADMIN_PASSWORD, so everything is open
    authenticated: bool


class LoginRequest(BaseModel):
    password: str = Field(max_length=1024)


# On every response: no framing by other sites, no MIME sniffing, no full URLs in referrers.
SECURITY_HEADERS = {
    "Content-Security-Policy": "frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}
# Reachable without logging in: the container healthcheck, the login flow, and the SPA's
# static files (the login page itself; they hold no data).
PUBLIC_API = {"/api/health", "/api/auth/session", "/api/auth/login", "/api/auth/logout"}
PROTECTED_PREFIXES = ("/api/", "/docs", "/redoc", "/openapi.json")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="nasscan",
        version=__version__,
        description="NAS malware scanner: scan runs, findings and reports.",
    )
    failures = auth.FailedLogins()

    def logged_in(request: Request) -> bool:
        if not auth.auth_enabled(settings):
            return True
        return auth.token_valid(auth.signing_key(settings), request.cookies.get(auth.COOKIE))

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        if (
            path.startswith(PROTECTED_PREFIXES)
            and path not in PUBLIC_API
            and not logged_in(request)
        ):
            return JSONResponse({"detail": "login required"}, status_code=401)
        return await call_next(request)

    @app.get("/api/auth/session", response_model=SessionOut)
    def session_state(request: Request) -> SessionOut:
        return SessionOut(
            auth_enabled=auth.auth_enabled(settings), authenticated=logged_in(request)
        )

    @app.post("/api/auth/login", response_model=SessionOut)
    def login(body: LoginRequest, request: Request, response: Response) -> SessionOut:
        if not auth.auth_enabled(settings):
            raise HTTPException(400, "no admin password is set (NASSCAN_ADMIN_PASSWORD)")
        client = request.client.host if request.client else "?"
        if failures.locked(client):
            raise HTTPException(429, "too many failed logins; try again in a few minutes")
        if not auth.password_matches(settings, body.password):
            failures.record(client)
            raise HTTPException(401, "wrong password")
        failures.clear(client)
        max_age = int(settings.session_days * 86400)
        response.set_cookie(
            auth.COOKIE,
            auth.make_token(auth.signing_key(settings), int(time.time()) + max_age),
            max_age=max_age,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
        )
        return SessionOut(auth_enabled=True, authenticated=True)

    @app.post("/api/auth/logout", response_model=SessionOut)
    def logout(response: Response) -> SessionOut:
        response.delete_cookie(auth.COOKIE, httponly=True, samesite="strict")
        return SessionOut(auth_enabled=auth.auth_enabled(settings), authenticated=False)

    @app.get("/api/health", response_model=Health)
    def health(db: DB) -> Health:
        try:
            db.execute(text("SELECT 1"))
        except Exception as exc:
            raise HTTPException(503, "database unavailable") from exc
        return Health(status="ok", version=__version__, commit=settings.git_sha, database=True)

    _mount_spa(app, settings.web_dist_dir)
    return app


def _mount_spa(app: FastAPI, dist_dir: str | None) -> None:
    """Serve the built React app (production image). In dev, Vite serves it instead."""
    if not dist_dir or not (FsPath(dist_dir) / "index.html").is_file():
        return
    dist = FsPath(dist_dir)
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        candidate = (dist / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")

"""Portal: one process serves the API and the built React app.

uvicorn app.main:app --host 0.0.0.0 --port 8000
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app import auth, db
from app.auth import CurrentUser
from app.config import get_settings
from app.routers import aoc, microsoft, offices, onboarding


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    db.open_pool()
    yield
    db.close_pool()


app = FastAPI(title="Court Connection Readiness", lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")
app.include_router(auth.router)
app.include_router(offices.router)
app.include_router(onboarding.router)
app.include_router(onboarding.preview_router)
app.include_router(microsoft.router)
app.include_router(aoc.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    response: Response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/me")
def me(user: CurrentUser) -> dict[str, object]:
    return {
        "email": user.email,
        "groups": user.groups,
        "is_admin": user.is_admin,
        "is_aoc": user.is_aoc,
        "environment": get_settings().environment,
        "microsoft_configured": bool(get_settings().ms_client_id),
    }


# ---------- the React app (built into ./static by the image) ----------
_static = Path(get_settings().static_dir)
if (_static / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=_static / "assets"), name="assets")


@app.get("/{full_path:path}", include_in_schema=False)
def spa(full_path: str) -> Response:
    if full_path.startswith(("api/", "auth/")):
        return JSONResponse({"detail": "not found"}, status_code=404)
    index = _static / "index.html"
    if index.is_file():
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
    return JSONResponse({"detail": "frontend not built"}, status_code=404)

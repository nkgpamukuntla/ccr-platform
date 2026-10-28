"""AOC aggregate view: the courts workspace's summary (kept at its original address).

Counts across offices, never one county's detail beyond its status. See routers/workspaces.py."""

from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.access import viewer_workspaces
from app.auth import CurrentUser
from app.db import tx
from app.routers import workspaces

router = APIRouter(prefix="/api/aoc", tags=["aoc"])


@router.get("/summary")
def summary(user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        viewable = viewer_workspaces(conn, user)
        courts = conn.execute("SELECT id FROM workspace WHERE kind = 'courts' ORDER BY created_at").fetchall()
    ids = [c["id"] for c in courts if c["id"] in viewable]
    if not ids:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "AOC view only")
    return workspaces.summary(ids[0], user)

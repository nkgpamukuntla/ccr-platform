"""Workspaces: one per customer or programme (the Georgia courts, D-Biz, another organisation).

Platform administrators create workspaces and choose their read-only viewers. Offices are created
inside a workspace (routers/offices.py). The summary is the aggregate view a viewer sees: counts
and status across that workspace's offices, never another workspace."""

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app import audit, directory
from app.access import viewer_workspaces
from app.auth import CurrentUser, User, require_admin
from app.db import tx

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])


class WorkspaceIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: Literal["courts", "organization"]
    industry: str | None = Field(default=None, max_length=80)


class ViewerIn(BaseModel):
    email: EmailStr


@router.get("")
def workspaces(user: CurrentUser) -> list[dict[str, Any]]:
    """Workspaces this user can see: those they view, plus those holding their own offices."""
    with tx() as conn:
        viewable = list(viewer_workspaces(conn, user))
        return conn.execute(
            "SELECT w.id, w.name, w.kind, w.industry, w.created_at, w.id = ANY(%s) AS can_view_all, "
            "(SELECT count(*) FROM office o WHERE o.workspace_id = w.id) AS offices "
            "FROM workspace w WHERE w.id = ANY(%s) OR EXISTS ("
            " SELECT 1 FROM office o JOIN membership m ON m.office_id = o.id WHERE o.workspace_id = w.id AND m.email = %s) "
            "ORDER BY w.kind, w.name",
            (viewable, viewable, user.email.lower()),
        ).fetchall()


@router.post("", status_code=status.HTTP_201_CREATED)
def create(body: WorkspaceIn, user: Annotated[User, Depends(require_admin)]) -> dict[str, Any]:
    with tx() as conn:
        if conn.execute("SELECT 1 FROM workspace WHERE lower(name) = lower(%s)", (body.name,)).fetchone():
            raise HTTPException(status.HTTP_409_CONFLICT, "a workspace with this name exists")
        row = conn.execute(
            "INSERT INTO workspace (name, kind, industry, created_by) VALUES (%s, %s, %s, %s) RETURNING *",
            (body.name, body.kind, body.industry, user.email),
        ).fetchone()
        assert row is not None
        audit.record(conn, user, "workspace.create", None, workspace=str(row["id"]), name=body.name, kind=body.kind)
        return row


@router.get("/{workspace_id}/viewers")
def viewers(workspace_id: UUID, user: Annotated[User, Depends(require_admin)]) -> list[dict[str, Any]]:
    with tx() as conn:
        return conn.execute(
            "SELECT email, added_at, added_by FROM workspace_membership WHERE workspace_id = %s ORDER BY email", (workspace_id,)
        ).fetchall()


@router.post("/{workspace_id}/viewers", status_code=status.HTTP_201_CREATED)
def add_viewer(workspace_id: UUID, body: ViewerIn, user: Annotated[User, Depends(require_admin)]) -> dict[str, str]:
    email = str(body.email).lower()
    with tx() as conn:
        if conn.execute("SELECT 1 FROM workspace WHERE id = %s", (workspace_id,)).fetchone() is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    outcome = directory.ensure_user(email)
    with tx() as conn:
        conn.execute(
            "INSERT INTO workspace_membership (email, workspace_id, role, added_by) VALUES (%s, %s, 'workspace_viewer', %s) "
            "ON CONFLICT DO NOTHING",
            (email, workspace_id, user.email),
        )
        audit.record(conn, user, "workspace.viewer_add", None, workspace=str(workspace_id), email=email, directory=outcome)
    return {"status": outcome}


@router.delete("/{workspace_id}/viewers/{email}")
def remove_viewer(workspace_id: UUID, email: str, user: Annotated[User, Depends(require_admin)]) -> dict[str, str]:
    with tx() as conn:
        n = conn.execute(
            "DELETE FROM workspace_membership WHERE workspace_id = %s AND email = %s", (workspace_id, email.lower())
        ).rowcount
        if not n:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not a viewer of this workspace")
        audit.record(conn, user, "workspace.viewer_remove", None, workspace=str(workspace_id), email=email.lower())
    return {"status": "removed"}


@router.get("/{workspace_id}/summary")
def summary(workspace_id: UUID, user: CurrentUser) -> dict[str, Any]:
    """Aggregate across the workspace's offices; each office still sees only itself."""
    with tx() as conn:
        if workspace_id not in viewer_workspaces(conn, user):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "workspace viewers only")
        ws = conn.execute("SELECT id, name, kind, industry FROM workspace WHERE id = %s", (workspace_id,)).fetchone()
        totals = conn.execute(
            "SELECT count(*) AS offices, count(ob.live_at) AS live, "
            "(SELECT count(*) FROM site) AS sites_in_register, "
            "(SELECT count(DISTINCT os.site_id) FROM office_site os JOIN office o2 ON o2.id = os.office_id WHERE o2.workspace_id = %s) "
            "AS sites_covered FROM office o LEFT JOIN onboarding ob ON ob.office_id = o.id WHERE o.workspace_id = %s",
            (workspace_id, workspace_id),
        ).fetchone()
        by_profile = conn.execute(
            "SELECT COALESCE(ep.profile, '-') AS profile, count(*) AS offices FROM office o "
            "LEFT JOIN environment_profile ep ON ep.office_id = o.id WHERE o.workspace_id = %s GROUP BY 1 ORDER BY 1",
            (workspace_id,),
        ).fetchall()
        by_type = conn.execute(
            "SELECT office_type, count(*) AS offices FROM office WHERE workspace_id = %s GROUP BY 1 ORDER BY 1", (workspace_id,)
        ).fetchall()
    return {"workspace": ws, "totals": totals, "by_profile": by_profile, "by_type": by_type}

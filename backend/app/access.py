"""Who may see or change an office. Applied in every office route.

Platform administrators: everything. Office members: their own offices. Workspace viewers: every
office in the workspaces they view, read-only (the Cognito group aoc_viewer views every courts
workspace, which is how the AOC view worked before workspaces existed).

R11: this separates code paths; it is not tenant isolation. The database grants are what
hold against a compromised component."""

from typing import Any
from uuid import UUID

import psycopg
from fastapi import HTTPException, status

from app.auth import User


def office_role(conn: psycopg.Connection[Any], user: User, office_id: UUID) -> str | None:
    row = conn.execute(
        "SELECT role FROM membership WHERE email = %s AND office_id = %s", (user.email.lower(), office_id)
    ).fetchone()
    return row["role"] if row else None


def viewer_workspaces(conn: psycopg.Connection[Any], user: User) -> set[UUID]:
    """Workspaces this user may view read-only (all of them for a platform administrator)."""
    if user.is_admin:
        return {r["id"] for r in conn.execute("SELECT id FROM workspace").fetchall()}
    ids = {
        r["workspace_id"]
        for r in conn.execute("SELECT workspace_id FROM workspace_membership WHERE email = %s", (user.email.lower(),)).fetchall()
    }
    if "aoc_viewer" in user.groups:
        ids |= {r["id"] for r in conn.execute("SELECT id FROM workspace WHERE kind = 'courts'").fetchall()}
    return ids


def _workspace_of(conn: psycopg.Connection[Any], office_id: UUID) -> UUID | None:
    row = conn.execute("SELECT workspace_id FROM office WHERE id = %s", (office_id,)).fetchone()
    return row["workspace_id"] if row else None


def can_read(conn: psycopg.Connection[Any], user: User, office_id: UUID) -> None:
    if user.is_admin or office_role(conn, user, office_id):
        return
    if _workspace_of(conn, office_id) in viewer_workspaces(conn, user):
        return
    raise HTTPException(status.HTTP_404_NOT_FOUND, "office not found")


def can_write(conn: psycopg.Connection[Any], user: User, office_id: UUID) -> None:
    if user.is_admin or office_role(conn, user, office_id):
        return
    if _workspace_of(conn, office_id) in viewer_workspaces(conn, user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "the workspace view is read-only")
    raise HTTPException(status.HTTP_404_NOT_FOUND, "office not found")

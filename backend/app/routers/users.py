"""Members: who can use the portal and which office they belong to.

Platform administrators manage everyone. An office administrator can invite people to their
own office and remove them, so the right engineer can finish each onboarding step.
AOC viewers are assigned by platform administrators; platform_admin itself only via Terraform.
"""

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

from app import audit, directory
from app.access import office_role
from app.auth import CurrentUser, User, require_admin
from app.db import tx

router = APIRouter(prefix="/api", tags=["members"])


class InviteIn(BaseModel):
    email: EmailStr
    role: Literal["office_admin", "office_member", "aoc_viewer"]
    office_id: UUID | None = None


def _can_manage(conn: Any, user: User, office_id: UUID) -> None:
    if user.is_admin or office_role(conn, user, office_id) == "office_admin":
        return
    raise HTTPException(status.HTTP_403_FORBIDDEN, "only platform administrators or this office's administrator")


@router.get("/admin/users")
def users(user: Annotated[User, Depends(require_admin)]) -> list[dict[str, Any]]:
    people = directory.list_users()
    with tx() as conn:
        rows = conn.execute(
            "SELECT m.email, m.role, o.id AS office_id, o.name AS office_name "
            "FROM membership m JOIN office o ON o.id = m.office_id"
        ).fetchall()
    by_email: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_email.setdefault(r["email"], []).append({"office_id": r["office_id"], "office": r["office_name"], "role": r["role"]})
    for p in people:
        p["offices"] = by_email.pop(p["email"], [])
    # Memberships for people not yet in Cognito (should not happen; shown so it can be fixed).
    for email, offices in by_email.items():
        people.append({"email": email, "status": "NOT_IN_DIRECTORY", "enabled": False, "groups": [], "offices": offices})
    return sorted(people, key=lambda p: p["email"])


@router.post("/members", status_code=status.HTTP_201_CREATED)
def invite(body: InviteIn, user: CurrentUser) -> dict[str, str]:
    email = str(body.email).lower()
    if body.role == "aoc_viewer":
        if not user.is_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "platform administrators only")
        outcome = directory.ensure_user(email)
        directory.add_to_group(email, "aoc_viewer")
        with tx() as conn:
            audit.record(conn, user, "member.aoc_viewer", None, email=email, directory=outcome)
        return {"status": outcome}
    if body.office_id is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "office_id is required for an office role")
    with tx() as conn:
        _can_manage(conn, user, body.office_id)
        if conn.execute("SELECT 1 FROM office WHERE id = %s", (body.office_id,)).fetchone() is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "office not found")
    outcome = directory.ensure_user(email)
    with tx() as conn:
        conn.execute(
            "INSERT INTO membership (email, office_id, role, added_by) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (email, office_id) DO UPDATE SET role = EXCLUDED.role",
            (email, body.office_id, body.role, user.email),
        )
        audit.record(conn, user, "member.add", body.office_id, email=email, role=body.role, directory=outcome)
    return {"status": outcome}


@router.delete("/offices/{office_id}/members/{email}")
def remove(office_id: UUID, email: str, user: CurrentUser) -> dict[str, str]:
    email = email.lower()
    with tx() as conn:
        _can_manage(conn, user, office_id)
        if email == user.email and not user.is_admin:
            raise HTTPException(status.HTTP_409_CONFLICT, "you cannot remove yourself")
        cur = conn.execute("DELETE FROM membership WHERE office_id = %s AND email = %s", (office_id, email))
        if cur.rowcount == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not a member of this office")
        audit.record(conn, user, "member.remove", office_id, email=email)
    return {"status": "removed"}

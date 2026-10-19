"""Offices, members and step 1 (organisation and sites)."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app import audit
from app.access import can_read, can_write
from app.auth import CurrentUser, User, require_admin
from app.db import tx

router = APIRouter(prefix="/api", tags=["offices"])

OFFICE_TYPES = [
    "Superior Court Clerk",
    "State Court",
    "Probate Court",
    "Magistrate Court",
    "Juvenile Court",
    "Municipal Court",
    "Sheriff",
    "County IT",
]


class OfficeIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    office_type: str
    county: str = Field(min_length=2, max_length=80)


class Organisation(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    office_type: str
    signatory_name: str | None = Field(default=None, max_length=200)
    technical_contact: str | None = Field(default=None, max_length=200)
    site_ids: list[UUID]


class MemberIn(BaseModel):
    email: EmailStr
    role: str = Field(pattern="^(office_admin|office_member)$")


@router.get("/office-types")
def office_types() -> list[str]:
    return OFFICE_TYPES


@router.get("/sites")
def sites(user: CurrentUser, county: str | None = None) -> list[dict[str, Any]]:
    with tx() as conn:
        if county:
            return conn.execute("SELECT * FROM site WHERE county = %s ORDER BY code", (county,)).fetchall()
        return conn.execute("SELECT * FROM site ORDER BY county, code").fetchall()


@router.get("/offices")
def list_offices(user: CurrentUser) -> list[dict[str, Any]]:
    q = """
        SELECT o.id, o.name, o.office_type, o.county, ep.profile,
               COALESCE(ob.completed_steps, '{}') AS completed_steps, ob.live_at
        FROM office o
        LEFT JOIN environment_profile ep ON ep.office_id = o.id
        LEFT JOIN onboarding ob ON ob.office_id = o.id
    """
    with tx() as conn:
        if user.is_aoc:
            return conn.execute(q + " ORDER BY o.county, o.name").fetchall()
        return conn.execute(
            q + " JOIN membership m ON m.office_id = o.id AND m.email = %s ORDER BY o.county, o.name",
            (user.email.lower(),),
        ).fetchall()


@router.post("/offices", status_code=status.HTTP_201_CREATED)
def create_office(body: OfficeIn, user: Annotated[User, Depends(require_admin)]) -> dict[str, Any]:
    with tx() as conn:
        row = conn.execute(
            "INSERT INTO office (name, office_type, county, created_by) VALUES (%s, %s, %s, %s) RETURNING *",
            (body.name, body.office_type, body.county, user.email),
        ).fetchone()
        assert row is not None
        conn.execute("INSERT INTO onboarding (office_id) VALUES (%s)", (row["id"],))
        audit.record(conn, user, "office.create", row["id"], name=body.name, county=body.county)
        return row


@router.get("/offices/{office_id}")
def get_office(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        office = conn.execute("SELECT * FROM office WHERE id = %s", (office_id,)).fetchone()
        if office is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "office not found")
        office["sites"] = conn.execute(
            "SELECT s.* FROM site s JOIN office_site os ON os.site_id = s.id WHERE os.office_id = %s ORDER BY s.code",
            (office_id,),
        ).fetchall()
        office["onboarding"] = conn.execute(
            "SELECT completed_steps, live_at FROM onboarding WHERE office_id = %s", (office_id,)
        ).fetchone()
        return office


@router.put("/offices/{office_id}/organisation")
def save_organisation(office_id: UUID, body: Organisation, user: CurrentUser) -> dict[str, str]:
    with tx() as conn:
        can_write(conn, user, office_id)
        conn.execute(
            "UPDATE office SET name = %s, office_type = %s, signatory_name = %s, technical_contact = %s WHERE id = %s",
            (body.name, body.office_type, body.signatory_name, body.technical_contact, office_id),
        )
        conn.execute("DELETE FROM office_site WHERE office_id = %s", (office_id,))
        for sid in body.site_ids:
            conn.execute("INSERT INTO office_site (office_id, site_id) VALUES (%s, %s)", (office_id, sid))
        complete_step(conn, office_id, 1)
        audit.record(conn, user, "onboarding.organisation", office_id, sites=len(body.site_ids))
        return {"status": "saved"}


@router.get("/offices/{office_id}/members")
def members(office_id: UUID, user: CurrentUser) -> list[dict[str, Any]]:
    with tx() as conn:
        can_read(conn, user, office_id)
        return conn.execute(
            "SELECT email, role, added_at, added_by FROM membership WHERE office_id = %s ORDER BY email", (office_id,)
        ).fetchall()


@router.post("/offices/{office_id}/members", status_code=status.HTTP_201_CREATED)
def add_member(office_id: UUID, body: MemberIn, user: Annotated[User, Depends(require_admin)]) -> dict[str, str]:
    with tx() as conn:
        conn.execute(
            "INSERT INTO membership (email, office_id, role, added_by) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (email, office_id) DO UPDATE SET role = EXCLUDED.role",
            (body.email.lower(), office_id, body.role, user.email),
        )
        audit.record(conn, user, "office.member_add", office_id, email=body.email, role=body.role)
        return {"status": "added"}


@router.get("/offices/{office_id}/audit")
def office_audit(office_id: UUID, user: CurrentUser) -> list[dict[str, Any]]:
    with tx() as conn:
        can_read(conn, user, office_id)
        return conn.execute(
            "SELECT at, actor_email, action, detail FROM audit_log WHERE office_id = %s ORDER BY at DESC LIMIT 200",
            (office_id,),
        ).fetchall()


def complete_step(conn: Any, office_id: UUID, step: int) -> None:
    conn.execute(
        "UPDATE onboarding SET completed_steps = ARRAY(SELECT DISTINCT unnest(completed_steps || %s::smallint) "
        "ORDER BY 1), updated_at = now() WHERE office_id = %s",
        (step, office_id),
    )

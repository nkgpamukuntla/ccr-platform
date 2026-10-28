"""Offices, members and step 1 (organisation and sites)."""

from datetime import UTC, datetime, time
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app import audit, schedule
from app.access import can_read, can_write, viewer_workspaces
from app.auth import CurrentUser, User, require_admin
from app.db import tx

router = APIRouter(prefix="/api", tags=["offices"])

# Office types depend on the kind of workspace: governed court offices, or units of an organisation.
OFFICE_TYPES: dict[str, list[str]] = {
    "courts": [
        "Superior Court Clerk",
        "State Court",
        "Probate Court",
        "Magistrate Court",
        "Juvenile Court",
        "Municipal Court",
        "Accountability Court",
        "Sheriff",
        "County IT",
    ],
    "organization": ["Head office", "Business unit", "Subsidiary", "Branch office", "IT department"],
}


class OfficeIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    office_type: str
    county: str = Field(min_length=2, max_length=80)  # the county for courts; a location for organisations
    workspace_id: UUID | None = None  # default: the courts workspace
    time_zone: str = schedule.DEFAULT_TZ
    collect_at: time = schedule.DEFAULT_AT


class ScheduleIn(BaseModel):
    time_zone: str
    collect_at: time


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
def office_types(kind: Literal["courts", "organization"] = "courts") -> list[str]:
    return OFFICE_TYPES[kind]


@router.get("/time-zones")
def time_zones() -> list[str]:
    return schedule.COMMON_ZONES


def _check_type(conn: Any, workspace_id: UUID, office_type: str) -> None:
    ws = conn.execute("SELECT kind FROM workspace WHERE id = %s", (workspace_id,)).fetchone()
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    allowed = OFFICE_TYPES[ws["kind"]]
    if office_type not in allowed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"office type must be one of: {', '.join(allowed)}")


def _check_zone(tz: str) -> None:
    if not schedule.valid_zone(tz):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown time zone {tz!r} (use an IANA name such as America/New_York)"
        )


def _with_next_scan(row: dict[str, Any]) -> dict[str, Any]:
    row["next_scan"] = schedule.next_run(datetime.now(UTC), row["time_zone"], row["collect_at"])
    return row


@router.get("/sites")
def sites(user: CurrentUser, county: str | None = None) -> list[dict[str, Any]]:
    with tx() as conn:
        if county:
            return conn.execute("SELECT * FROM site WHERE county = %s ORDER BY code", (county,)).fetchall()
        return conn.execute("SELECT * FROM site ORDER BY county, code").fetchall()


@router.get("/offices")
def list_offices(user: CurrentUser) -> list[dict[str, Any]]:
    q = """
        SELECT o.id, o.name, o.office_type, o.county, o.time_zone, o.collect_at, ep.profile,
               COALESCE(ob.completed_steps, '{}') AS completed_steps, ob.live_at,
               w.id AS workspace_id, w.name AS workspace, w.kind AS workspace_kind
        FROM office o
        JOIN workspace w ON w.id = o.workspace_id
        LEFT JOIN environment_profile ep ON ep.office_id = o.id
        LEFT JOIN onboarding ob ON ob.office_id = o.id
        WHERE o.workspace_id = ANY(%s)
           OR EXISTS (SELECT 1 FROM membership m WHERE m.office_id = o.id AND m.email = %s)
        ORDER BY w.kind, w.name, o.county, o.name
    """
    with tx() as conn:
        viewable = list(viewer_workspaces(conn, user))
        return [_with_next_scan(r) for r in conn.execute(q, (viewable, user.email.lower())).fetchall()]


@router.post("/offices", status_code=status.HTTP_201_CREATED)
def create_office(body: OfficeIn, user: Annotated[User, Depends(require_admin)]) -> dict[str, Any]:
    _check_zone(body.time_zone)
    with tx() as conn:
        ws = body.workspace_id
        if ws is None:
            courts = conn.execute("SELECT id FROM workspace WHERE kind = 'courts' ORDER BY created_at LIMIT 1").fetchone()
            assert courts is not None
            ws = courts["id"]
        _check_type(conn, ws, body.office_type)
        row = conn.execute(
            "INSERT INTO office (name, office_type, county, workspace_id, time_zone, collect_at, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *",
            (body.name, body.office_type, body.county, ws, body.time_zone, body.collect_at, user.email),
        ).fetchone()
        assert row is not None
        conn.execute("INSERT INTO onboarding (office_id) VALUES (%s)", (row["id"],))
        audit.record(conn, user, "office.create", row["id"], name=body.name, county=body.county, workspace=str(ws))
        return row


@router.get("/offices/{office_id}")
def get_office(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        office = conn.execute(
            "SELECT o.*, w.name AS workspace, w.kind AS workspace_kind FROM office o JOIN workspace w ON w.id = o.workspace_id "
            "WHERE o.id = %s",
            (office_id,),
        ).fetchone()
        if office is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "office not found")
        _with_next_scan(office)
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
        ws = conn.execute("SELECT workspace_id FROM office WHERE id = %s", (office_id,)).fetchone()
        assert ws is not None
        _check_type(conn, ws["workspace_id"], body.office_type)
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


@router.put("/offices/{office_id}/schedule")
def save_schedule(office_id: UUID, body: ScheduleIn, user: CurrentUser) -> dict[str, Any]:
    """The daily scan: end of the office's business day, in its own time zone."""
    _check_zone(body.time_zone)
    with tx() as conn:
        can_write(conn, user, office_id)
        conn.execute(
            "UPDATE office SET time_zone = %s, collect_at = %s WHERE id = %s", (body.time_zone, body.collect_at, office_id)
        )
        audit.record(conn, user, "office.schedule", office_id, time_zone=body.time_zone, collect_at=body.collect_at.isoformat())
    return {"status": "saved", "next_scan": schedule.next_run(datetime.now(UTC), body.time_zone, body.collect_at)}


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

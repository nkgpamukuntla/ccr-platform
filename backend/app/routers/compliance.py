"""Compliance by country: the office's chosen frameworks, each clause backed by our checks (app/frameworks.py)."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator

from app import audit, frameworks, plain
from app.access import can_read, can_write
from app.auth import CurrentUser, User, require_admin
from app.db import tx
from app.routers.imports import office_devices
from app.routers.microsoft import _edr_from_devices

router = APIRouter(prefix="/api/offices/{office_id}", tags=["compliance"])
org_router = APIRouter(prefix="/api/workspaces", tags=["compliance"])


class CountryIn(BaseModel):
    country: str


class OrgComplianceIn(BaseModel):
    countries: list[str]
    frameworks: list[str] = []
    group_frameworks: list[str] = []

    @field_validator("countries")
    @classmethod
    def known_countries(cls, v: list[str]) -> list[str]:
        bad = [c for c in v if c not in frameworks.COUNTRIES]
        if bad:
            raise ValueError(f"unknown country: {', '.join(bad)}")
        return sorted(set(v))

    @field_validator("frameworks", "group_frameworks")
    @classmethod
    def known_frameworks(cls, v: list[str]) -> list[str]:
        bad = [k for k in v if k not in frameworks.by_key()]
        if bad:
            raise ValueError(f"unknown framework: {', '.join(bad)}")
        return sorted(set(v))


def _scuba_statuses(conn: Any, office_id: UUID) -> dict[str, str]:
    """Newest result per SCuBA policy, from collected or imported assessments."""
    rows = conn.execute(
        "SELECT DISTINCT ON (r.policy_id) r.policy_id, r.status FROM scuba_result r "
        "JOIN scuba_assessment a ON a.id = r.assessment_id WHERE a.office_id = %s "
        "ORDER BY r.policy_id, a.assessed_at DESC",
        (office_id,),
    ).fetchall()
    return {r["policy_id"]: r["status"] for r in rows}


def compliance_view(conn: Any, office_id: UUID) -> dict[str, Any]:
    office = conn.execute("SELECT country FROM office WHERE id = %s", (office_id,)).fetchone()
    run = conn.execute(
        "SELECT id, finished_at FROM collection_run WHERE office_id = %s AND status = 'evaluated' "
        "ORDER BY started_at DESC LIMIT 1",
        (office_id,),
    ).fetchone()
    devs = office_devices(conn, office_id)
    controls: list[dict[str, Any]] = []
    fx = None
    if run:
        controls = conn.execute(
            "SELECT control, name, state, method, detail FROM control_result WHERE run_id = %s ORDER BY control", (run["id"],)
        ).fetchall()
        controls = [_edr_from_devices(c, devs) if c["control"] == 5 else c for c in controls]
        controls = [{**c, "summary": plain.summary(c)} for c in controls]
        row = conn.execute("SELECT facts FROM run_facts WHERE run_id = %s", (run["id"],)).fetchone()
        fx = row["facts"] if row else None
    found = frameworks.checks(controls, fx, _scuba_statuses(conn, office_id), devs)
    org = conn.execute(
        "SELECT w.id, w.name, w.countries, w.frameworks, w.group_frameworks FROM workspace w "
        "JOIN office o ON o.workspace_id = w.id WHERE o.id = %s",
        (office_id,),
    ).fetchone()
    country = office["country"] if office else None
    keys = frameworks.applicable(country, list(org["frameworks"]), list(org["group_frameworks"])) if org else []
    return {
        "as_of": run["finished_at"] if run else None,
        "country": country,
        "countries": [{"code": k, "name": v} for k, v in frameworks.COUNTRIES.items()],
        "organisation": org,
        "catalogue": [{"key": f["key"], "country": f["country"], "name": f["name"]} for f in frameworks.FRAMEWORKS],
        "frameworks": frameworks.assess(keys, found),
        "deadlines": {country: [{"event": e, "deadline": d} for e, d in frameworks.DEADLINES[country]]} if country else {},
        "secure_score": (fx or {}).get("secure_score"),
    }


@router.get("/compliance")
def compliance(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        return compliance_view(conn, office_id)


@router.put("/country")
def save_country(office_id: UUID, body: CountryIn, user: CurrentUser) -> dict[str, str]:
    """The office's country: one of its organisation's countries."""
    with tx() as conn:
        can_write(conn, user, office_id)
        org = conn.execute(
            "SELECT w.countries FROM workspace w JOIN office o ON o.workspace_id = w.id WHERE o.id = %s", (office_id,)
        ).fetchone()
        allowed = list(org["countries"]) if org and org["countries"] else list(frameworks.COUNTRIES)
        if body.country not in allowed:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"choose one of the organisation's countries: {', '.join(allowed)}"
            )
        conn.execute("UPDATE office SET country = %s WHERE id = %s", (body.country, office_id))
        audit.record(conn, user, "office.country", office_id, country=body.country)
    return {"country": body.country}


@org_router.put("/{workspace_id}/compliance")
def save_org_compliance(
    workspace_id: UUID, body: OrgComplianceIn, user: Annotated[User, Depends(require_admin)]
) -> dict[str, Any]:
    """Where the organisation operates and which frameworks it requires."""
    with tx() as conn:
        row = conn.execute(
            "UPDATE workspace SET countries = %s, frameworks = %s, group_frameworks = %s WHERE id = %s "
            "RETURNING id, name, countries, frameworks, group_frameworks",
            (body.countries, body.frameworks, body.group_frameworks, workspace_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "organisation not found")
        audit.record(conn, user, "workspace.compliance", None, workspace=str(workspace_id), **body.model_dump())
        return row


catalogue_router = APIRouter(prefix="/api", tags=["compliance"])


@catalogue_router.get("/frameworks")
def catalogue(user: CurrentUser) -> dict[str, Any]:
    """Countries and frameworks an organisation can choose from."""
    return {
        "countries": [{"code": k, "name": v} for k, v in frameworks.COUNTRIES.items()],
        "frameworks": [
            {"key": f["key"], "country": f["country"], "name": f["name"], "applies": f["applies"]} for f in frameworks.FRAMEWORKS
        ],
    }

"""Compliance by country: the office's chosen frameworks, each clause backed by our checks (app/frameworks.py)."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel, field_validator

from app import audit, frameworks, plain
from app.access import can_read, can_write
from app.auth import CurrentUser
from app.db import tx
from app.routers.imports import office_devices
from app.routers.microsoft import _edr_from_devices

router = APIRouter(prefix="/api/offices/{office_id}", tags=["compliance"])


class JurisdictionsIn(BaseModel):
    jurisdictions: list[str]

    @field_validator("jurisdictions")
    @classmethod
    def known(cls, v: list[str]) -> list[str]:
        bad = [j for j in v if j not in frameworks.COUNTRIES]
        if bad:
            raise ValueError(f"unknown country: {', '.join(bad)}")
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
    office = conn.execute("SELECT jurisdictions FROM office WHERE id = %s", (office_id,)).fetchone()
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
    chosen = list(office["jurisdictions"]) if office else []
    return {
        "as_of": run["finished_at"] if run else None,
        "countries": [{"code": k, "name": v} for k, v in frameworks.COUNTRIES.items()],
        "jurisdictions": chosen,
        "frameworks": frameworks.assess(chosen, found),
        "deadlines": {j: [{"event": e, "deadline": d} for e, d in frameworks.DEADLINES[j]] for j in chosen},
        "secure_score": (fx or {}).get("secure_score"),
    }


@router.get("/compliance")
def compliance(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        return compliance_view(conn, office_id)


@router.put("/jurisdictions")
def save_jurisdictions(office_id: UUID, body: JurisdictionsIn, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_write(conn, user, office_id)
        conn.execute("UPDATE office SET jurisdictions = %s WHERE id = %s", (body.jurisdictions, office_id))
        audit.record(conn, user, "office.jurisdictions", office_id, jurisdictions=body.jurisdictions)
    return {"jurisdictions": body.jurisdictions}

"""AOC aggregate view: counts across offices, never one county's detail beyond its status."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.auth import User, require_aoc
from app.db import tx

router = APIRouter(prefix="/api/aoc", tags=["aoc"])


@router.get("/summary")
def summary(user: Annotated[User, Depends(require_aoc)]) -> dict[str, Any]:
    with tx() as conn:
        totals = conn.execute(
            "SELECT count(*) AS offices, count(ob.live_at) AS live, "
            "(SELECT count(*) FROM site) AS sites_in_register, "
            "(SELECT count(DISTINCT site_id) FROM office_site) AS sites_covered "
            "FROM office o LEFT JOIN onboarding ob ON ob.office_id = o.id"
        ).fetchone()
        by_profile = conn.execute(
            "SELECT COALESCE(ep.profile, '-') AS profile, count(*) AS offices FROM office o "
            "LEFT JOIN environment_profile ep ON ep.office_id = o.id GROUP BY 1 ORDER BY 1"
        ).fetchall()
    return {"totals": totals, "by_profile": by_profile}

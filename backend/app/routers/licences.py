"""Microsoft 365 licences: seats, people to review, security already paid for (app/licences.py)."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from app import audit, licences
from app.access import can_read, can_write
from app.auth import CurrentUser
from app.db import tx
from app.routers.imports import office_devices

router = APIRouter(prefix="/api/offices/{office_id}", tags=["licences"])


class PricesIn(BaseModel):
    prices: dict[str, float | None] = Field(max_length=200)  # SKU part number -> price per user per month; null resets


def licence_view(conn: Any, office_id: UUID) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT r.finished_at, f.facts->'licence_data' AS data, f.facts->'intune' AS intune, o.licence_prices "
        "FROM collection_run r JOIN run_facts f ON f.run_id = r.id JOIN office o ON o.id = r.office_id "
        "WHERE r.office_id = %s AND r.status = 'evaluated' ORDER BY r.started_at DESC LIMIT 1",
        (office_id,),
    ).fetchone()
    if row is None or not row["data"]:
        return None
    # Computers protected by an EDR other than Microsoft's, from the device register.
    other = sum(1 for d in office_devices(conn, office_id) if d["edr"] == "active")
    intune = row["intune"]["total"] if row["intune"] else None
    return {"as_of": row["finished_at"], **licences.model(row["data"], row["finished_at"], row["licence_prices"], intune, other)}


@router.get("/licences")
def licence_page(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        out = licence_view(conn, office_id)
    if out is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No licence data yet: it arrives with the next scan")
    return out


@router.put("/licence-prices")
def save_prices(office_id: UUID, body: PricesIn, user: CurrentUser) -> dict[str, float]:
    if any(v is not None and not 0 <= v <= 10000 for v in body.prices.values()):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "prices must be between 0 and 10000")
    with tx() as conn:
        can_write(conn, user, office_id)
        row = conn.execute("SELECT licence_prices FROM office WHERE id = %s", (office_id,)).fetchone()
        prices = {**(row["licence_prices"] if row else {}), **body.prices}
        prices = {k: v for k, v in prices.items() if v is not None}
        conn.execute("UPDATE office SET licence_prices = %s WHERE id = %s", (Jsonb(prices), office_id))
        audit.record(conn, user, "office.licence_prices", office_id, changed=sorted(body.prices))
    return prices

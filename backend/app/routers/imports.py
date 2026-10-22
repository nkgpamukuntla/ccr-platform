"""Import service (step 5) and the reconciled device register."""

import hashlib
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from psycopg.types.json import Jsonb

from app import audit, imports
from app.access import can_read, can_write
from app.auth import CurrentUser
from app.db import tx

router = APIRouter(prefix="/api", tags=["imports"])
MAX_BYTES = 10 * 1024 * 1024


@router.get("/import-templates")
def templates(user: CurrentUser) -> list[dict[str, Any]]:
    return [
        {
            "key": t.key,
            "label": t.label,
            "source": t.source_hint,
            "required": list(t.required),
            "one_of": list(t.one_of),
            "optional": list(t.optional),
        }
        for t in imports.TEMPLATES.values()
    ]


@router.get("/import-templates/{key}.csv", response_class=PlainTextResponse)
def template_file(key: str, user: CurrentUser) -> PlainTextResponse:
    if key not in imports.TEMPLATES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown template")
    return PlainTextResponse(
        imports.template_csv(key),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="ccr-{key}-template.csv"'},
    )


async def _text(request: Request) -> tuple[bytes, str]:
    body = await request.body()
    if len(body) > MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file over 10 MB; split the export")
    try:
        return body, body.decode("utf-8-sig")
    except UnicodeDecodeError:
        return body, body.decode("cp1252")


@router.post("/offices/{office_id}/imports/preview")
async def preview(office_id: UUID, template: str, request: Request, user: CurrentUser) -> dict[str, Any]:
    """Validate only. Nothing is stored."""
    with tx() as conn:
        can_write(conn, user, office_id)
    _, text = await _text(request)
    try:
        v = imports.validate(template, text)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e
    out = v.model_dump(exclude={"devices"})
    out["sample"] = v.devices[:5]
    return out


@router.post("/offices/{office_id}/imports", status_code=status.HTTP_201_CREATED)
async def load(
    office_id: UUID, template: str, filename: str, request: Request, user: CurrentUser, export_date: str | None = None
) -> dict[str, Any]:
    body, text = await _text(request)
    try:
        v = imports.validate(template, text)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e
    if not v.accepted:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, {"message": "file rejected", "issues": [i.model_dump() for i in v.issues[:20]]}
        )
    sha = hashlib.sha256(body).hexdigest()
    with tx() as conn:
        can_write(conn, user, office_id)
        if conn.execute("SELECT 1 FROM import_file WHERE office_id = %s AND sha256 = %s", (office_id, sha)).fetchone():
            raise HTTPException(status.HTTP_409_CONFLICT, "this exact file was already imported")
        f = conn.execute(
            "INSERT INTO import_file (office_id, template, filename, sha256, content, export_date, uploaded_by, rows_total, rows_loaded, "
            "rows_rejected, issues) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (
                office_id,
                template,
                filename[:200],
                sha,
                body,
                imports.export_date(export_date),
                user.email,
                v.rows_total,
                v.rows_ok,
                v.rows_rejected,
                Jsonb([i.model_dump() for i in v.issues]),
            ),
        ).fetchone()
        assert f is not None
        for d in v.devices:
            conn.execute(
                "INSERT INTO device_observation (office_id, source, import_id, hostname, serial, mac, os, os_build, last_seen, "
                "edr_product, edr_status, managed, site, attributes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    office_id,
                    f"import:{template}",
                    f["id"],
                    d["hostname"],
                    d["serial"],
                    d["mac"],
                    d["os"],
                    d["os_build"],
                    d["last_seen"],
                    d["edr_product"],
                    d["edr_status"],
                    d["managed"],
                    d["site"],
                    Jsonb(d["attributes"]),
                ),
            )
        audit.record(
            conn,
            user,
            "import.load",
            office_id,
            template=template,
            filename=filename,
            sha256=sha,
            rows=v.rows_ok,
            rejected=v.rows_rejected,
        )
    return {
        "status": "imported",
        "id": str(f["id"]),
        "rows_loaded": v.rows_ok,
        "rows_rejected": v.rows_rejected,
        "warnings": sum(1 for i in v.issues if i.level == "warning"),
    }


@router.get("/offices/{office_id}/imports")
def history(office_id: UUID, user: CurrentUser) -> list[dict[str, Any]]:
    with tx() as conn:
        can_read(conn, user, office_id)
        return conn.execute(
            "SELECT id, template, filename, sha256, export_date, uploaded_by, uploaded_at, rows_total, rows_loaded, rows_rejected, issues "
            "FROM import_file WHERE office_id = %s ORDER BY uploaded_at DESC",
            (office_id,),
        ).fetchall()


def office_devices(conn: Any, office_id: UUID) -> list[dict[str, Any]]:
    obs = conn.execute(
        "SELECT source, hostname, serial, os, last_seen, edr_status, managed, site FROM device_observation WHERE office_id = %s ORDER BY id",
        (office_id,),
    ).fetchall()
    return imports.reconcile(obs)


@router.get("/offices/{office_id}/devices")
def devices(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    """Devices matched across sources; unmatched ones are listed, never dropped."""
    with tx() as conn:
        can_read(conn, user, office_id)
        devs = office_devices(conn, office_id)
    return {
        "coverage": imports.edr_coverage(devs),
        "matched": sum(1 for d in devs if d["matched"]),
        "unmatched": sum(1 for d in devs if not d["matched"]),
        "devices": devs,
    }

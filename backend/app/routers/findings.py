"""Findings by SCuBA baseline policy: our collection scored with ScubaGear's rules, and
ScubaGear reports an office uploaded. Every row says how it was established and when."""

import hashlib
import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from psycopg.types.json import Jsonb

from app import audit
from app.access import can_read, can_write
from app.auth import CurrentUser
from app.db import tx
from app.scuba import importer

router = APIRouter(prefix="/api/offices/{office_id}", tags=["findings"])
MAX_IMPORT_BYTES = 8 * 1024 * 1024


@router.post("/scuba-import", status_code=status.HTTP_201_CREATED)
async def scuba_import(office_id: UUID, request: Request, user: CurrentUser) -> dict[str, Any]:
    body = await request.body()
    if len(body) > MAX_IMPORT_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file too large; upload ScubaResults_*.json without its Raw section"
        )
    try:
        report = importer.parse(json.loads(body))
    except (ValueError, json.JSONDecodeError) as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e
    with tx() as conn:
        can_write(conn, user, office_id)
        consent = conn.execute(
            "SELECT tenant_ref FROM consent WHERE office_id = %s AND source = 'microsoft365' AND status = 'granted' "
            "ORDER BY granted_at DESC LIMIT 1",
            (office_id,),
        ).fetchone()
        if consent and consent["tenant_ref"] and consent["tenant_ref"].lower() != report.tenant_id:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"this report is for tenant {report.tenant_id}, but the office consented with tenant {consent['tenant_ref']}",
            )
        summary: dict[str, int] = {}
        for r in report.results:
            summary[r.status] = summary.get(r.status, 0) + 1
        a = conn.execute(
            "INSERT INTO scuba_assessment (office_id, source, baseline, tenant_id, assessed_at, products, summary, "
            "imported_by, file_sha256) "
            "VALUES (%s, 'imported', %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (
                office_id,
                f"v{report.tool_version}",
                report.tenant_id,
                report.assessed_at,
                report.products,
                Jsonb(summary),
                user.email,
                hashlib.sha256(body).hexdigest(),
            ),
        ).fetchone()
        assert a is not None
        for r in report.results:
            conn.execute(
                "INSERT INTO scuba_result (assessment_id, product, policy_id, requirement, criticality, status, details) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (a["id"], r.product, r.policy_id, r.requirement, r.criticality, r.status, r.details),
            )
        audit.record(
            conn,
            user,
            "scuba.import",
            office_id,
            tool_version=report.tool_version,
            results=len(report.results),
            products=report.products,
            sha256=hashlib.sha256(body).hexdigest(),
        )
    return {"status": "imported", "results": len(report.results), "products": report.products, "summary": summary}


@router.get("/findings")
def findings(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    """The latest assessment per product: the newer of our collection and an uploaded report."""
    with tx() as conn:
        can_read(conn, user, office_id)
        assessments = conn.execute(
            "SELECT id, source, baseline, tenant_id, assessed_at, products, imported_by FROM scuba_assessment "
            "WHERE office_id = %s ORDER BY assessed_at DESC",
            (office_id,),
        ).fetchall()
        chosen: dict[str, dict[str, Any]] = {}
        for a in assessments:
            for p in a["products"]:
                key = p.lower()
                if key not in chosen:
                    chosen[key] = a
        rows: list[dict[str, Any]] = []
        for product, a in chosen.items():
            for r in conn.execute(
                "SELECT product, policy_id, requirement, criticality, status, details FROM scuba_result "
                "WHERE assessment_id = %s AND lower(product) = %s",
                (a["id"], product),
            ).fetchall():
                rows.append(
                    {
                        **r,
                        "source": a["source"],
                        "baseline": a["baseline"],
                        "assessed_at": a["assessed_at"],
                        "imported_by": a["imported_by"],
                    }
                )
    summary: dict[str, dict[str, int]] = {}
    for r in rows:
        s = summary.setdefault(r["product"].upper(), {})
        s[r["status"]] = s.get(r["status"], 0) + 1
    return {"summary": summary, "results": rows, "assessments": assessments[:10]}

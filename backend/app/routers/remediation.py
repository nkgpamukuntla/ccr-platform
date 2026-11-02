"""Phase 5: findings register, remediation tracker, evidence pack, exports and notification
recipients (walkthrough slides 23-25). Read-only towards the customer (R7): items are tracked
here and fixed in the customer's own tools; an item closes only on fresh evidence.
"""

import hashlib
from datetime import UTC, date, datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, EmailStr, Field

from app import audit, exports, findings_engine, notify, remediation
from app.access import can_read, can_write
from app.auth import CurrentUser
from app.config import get_settings
from app.db import tx
from app.routers.imports import office_devices
from app.routers.microsoft import _edr_from_devices

router = APIRouter(prefix="/api/offices/{office_id}", tags=["remediation"])

DESTINATIONS = {
    "irma": "ACCG-IRMA renewal",
    "aoc": "AOC connection agreement",
    "management": "Management report",
}
ANSWER = {
    "met": "Yes",
    "gap": "No",
    "weak": "Partial (weak method)",
    "not_observed": "Not observed",
    "pending": "Pending attestation",
}


def _office(conn: Any, office_id: UUID) -> dict[str, Any]:
    o = conn.execute(
        "SELECT o.id, o.name, o.county, o.office_type, o.time_zone, w.name AS workspace, w.kind AS workspace_kind "
        "FROM office o JOIN workspace w ON w.id = o.workspace_id WHERE o.id = %s",
        (office_id,),
    ).fetchone()
    if o is None:
        raise HTTPException(404, "office not found")
    return dict(o)


def _register(conn: Any, office_id: UUID) -> list[dict[str, Any]]:
    """Current findings, each with its live remediation item (if tracked). Syncs closures first."""
    found = findings_engine.build(conn, office_id)
    remediation.sync(conn, office_id, found)
    live = {
        r["finding_key"]: r
        for r in conn.execute(
            "SELECT id, finding_key, status, owner, target_date FROM remediation_item WHERE office_id = %s AND status <> 'closed'",
            (office_id,),
        ).fetchall()
    }
    order = {"Mandatory": 0, "High": 1, "Medium": 2}
    rows = [{**f.model_dump(), "item": live.get(f.key)} for f in found]
    return sorted(rows, key=lambda r: (order.get(r["severity"], 9), r["area"], r["key"]))


def _items(conn: Any, office_id: UUID) -> list[dict[str, Any]]:
    today = datetime.now(UTC).date()
    rows = conn.execute(
        "SELECT id, finding_key, title, recommendation, control, owner, target_date, status, created_by, created_at, "
        "updated_at, closed_at, closed_reason FROM remediation_item WHERE office_id = %s ORDER BY created_at",
        (office_id,),
    ).fetchall()
    events = conn.execute(
        "SELECT e.item_id, e.at, e.actor, e.from_status, e.to_status, e.note FROM remediation_event e "
        "JOIN remediation_item i ON i.id = e.item_id WHERE i.office_id = %s ORDER BY e.at",
        (office_id,),
    ).fetchall()
    by: dict[Any, list[dict[str, Any]]] = {}
    for e in events:
        by.setdefault(e["item_id"], []).append(e)
    return [{**r, "overdue": remediation.overdue(r, today), "events": by.get(r["id"], [])} for r in rows]


@router.get("/register")
def register(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        rows = _register(conn, office_id)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return {"findings": rows, "counts": counts, "tracked": sum(1 for r in rows if r["item"])}


class NewItem(BaseModel):
    finding_key: str = Field(max_length=200)
    owner: str = Field(min_length=2, max_length=120)
    target_date: date | None = None
    note: str | None = Field(default=None, max_length=1000)


@router.post("/remediation", status_code=201)
def track(office_id: UUID, body: NewItem, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_write(conn, user, office_id)
        f = next((f for f in findings_engine.build(conn, office_id) if f.key == body.finding_key), None)
        if f is None:
            raise HTTPException(404, "that finding is not present in the current evidence")
        row = conn.execute(
            "INSERT INTO remediation_item (office_id, finding_key, title, recommendation, control, owner, target_date, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (office_id, finding_key) WHERE status <> 'closed' DO NOTHING "
            "RETURNING id",
            (office_id, f.key, f.title, f.recommendation, f.control, body.owner, body.target_date, user.email),
        ).fetchone()
        if row is None:
            raise HTTPException(409, "this finding is already being tracked")
        conn.execute(
            "INSERT INTO remediation_event (item_id, actor, from_status, to_status, note) VALUES (%s, %s, NULL, 'open', %s)",
            (row["id"], user.email, body.note),
        )
        audit.record(conn, user, "remediation.tracked", office_id, item=str(row["id"]), finding=f.key, owner=body.owner)
    return {"id": row["id"]}


class Move(BaseModel):
    status: Literal["open", "in_progress", "awaiting_evidence"] | None = None
    owner: str | None = Field(default=None, min_length=2, max_length=120)
    target_date: date | None = None
    note: str | None = Field(default=None, max_length=1000)


@router.get("/remediation")
def items(office_id: UUID, user: CurrentUser) -> list[dict[str, Any]]:
    with tx() as conn:
        can_read(conn, user, office_id)
        _register(conn, office_id)  # closes what fresh evidence has cleared
        return _items(conn, office_id)


@router.patch("/remediation/{item_id}")
def move(office_id: UUID, item_id: UUID, body: Move, user: CurrentUser) -> dict[str, Any]:
    """Moves between open, in progress and awaiting evidence. Closing is never manual."""
    with tx() as conn:
        can_write(conn, user, office_id)
        it = conn.execute(
            "SELECT status, owner, target_date FROM remediation_item WHERE id = %s AND office_id = %s FOR UPDATE",
            (item_id, office_id),
        ).fetchone()
        if it is None:
            raise HTTPException(404, "item not found")
        if it["status"] == "closed":
            raise HTTPException(409, "closed items are history; a returning finding opens a new item")
        new_status = body.status or it["status"]
        conn.execute(
            "UPDATE remediation_item SET status = %s, owner = %s, target_date = %s, updated_at = now() WHERE id = %s",
            (
                new_status,
                body.owner or it["owner"],
                body.target_date if "target_date" in body.model_fields_set else it["target_date"],
                item_id,
            ),
        )
        conn.execute(
            "INSERT INTO remediation_event (item_id, actor, from_status, to_status, note) VALUES (%s, %s, %s, %s, %s)",
            (item_id, user.email, it["status"], new_status, body.note),
        )
        audit.record(conn, user, "remediation.moved", office_id, item=str(item_id), to=new_status)
    return {"status": new_status}


# ---------- evidence pack (slide 25) ----------


def _evidence_text(c: dict[str, Any]) -> str:
    d = c.get("detail") or {}
    if c["control"] == 5 and "devices" in d:
        return f"{d['covered']} of {d['devices']} devices with an active EDR agent"
    if c["control"] == 3 and "admins" in d:
        return (
            f"{d['admins']} admins; {len(d.get('not_registered', []))} without MFA, "
            f"{len(d.get('phone_only', []))} phone-only, {d.get('phishing_resistant', 0)} phishing-resistant"
        )
    return str(d.get("note") or d.get("reason") or d.get("summary") or c["method"])


def _pack(conn: Any, office_id: UUID, destination: str, user_email: str) -> dict[str, Any]:
    office = _office(conn, office_id)
    run = conn.execute(
        "SELECT id, finished_at, started_at FROM collection_run WHERE office_id = %s AND status = 'evaluated' ORDER BY started_at DESC LIMIT 1",
        (office_id,),
    ).fetchone()
    devs = office_devices(conn, office_id)
    controls: list[dict[str, Any]] = []
    if run:
        for c in conn.execute(
            "SELECT control, name, state, method, detail, as_of FROM control_result WHERE run_id = %s ORDER BY control",
            (run["id"],),
        ).fetchall():
            c = _edr_from_devices(c, devs) if c["control"] == 5 else c
            answer = ANSWER.get(c["state"], c["state"])
            d = c.get("detail") or {}
            if c["control"] == 5 and d.get("devices") and 0 < d["covered"] < d["devices"]:
                answer = "Partial"
            controls.append(
                {
                    "control": c["control"],
                    "name": c["name"],
                    "answer": answer,
                    "state": c["state"],
                    "evidence": _evidence_text(c),
                    "method": c["method"],
                    "as_of": c.get("as_of") or run["finished_at"],
                }
            )
    reg = _register(conn, office_id)
    its = _items(conn, office_id)
    today = datetime.now(UTC).date()
    submitter = (
        "The county remains the submitter"
        if office["workspace_kind"] == "courts"
        else f"{office['workspace']} remains responsible for any submission"
    )
    return {
        "destination": destination,
        "label": DESTINATIONS[destination],
        "office": office,
        "as_of": run["finished_at"] if run else None,
        "generated_at": datetime.now(UTC),
        "generated_by": user_email,
        "controls": controls,
        "findings": [{k: r[k] for k in ("key", "title", "area", "severity", "source", "recommendation", "as_of")} for r in reg],
        "remediation": {
            "open": sum(1 for i in its if i["status"] != "closed"),
            "overdue": sum(1 for i in its if remediation.overdue(i, today)),
            "closed": sum(1 for i in its if i["status"] == "closed"),
            "items": [{k: i[k] for k in ("title", "owner", "status", "target_date", "closed_reason")} for i in its],
        },
        "devices": {"total": len(devs), "edr_active": sum(1 for d in devs if d["edr"] == "active")},
        "statement": f"Prepared from read-only evidence; each answer keeps its source and date. {submitter}; "
        "the platform never files on anyone's behalf.",
    }


@router.get("/evidence-pack")
def evidence_pack(office_id: UUID, user: CurrentUser, destination: str = "management") -> dict[str, Any]:
    if destination not in DESTINATIONS:
        raise HTTPException(400, f"destination must be one of {', '.join(DESTINATIONS)}")
    with tx() as conn:
        can_read(conn, user, office_id)
        pack = _pack(conn, office_id, destination, user.email)
        audit.record(conn, user, "evidence_pack.viewed", office_id, destination=destination)
    return pack


# ---------- exports ----------

EXPORTS = ("findings", "remediation", "devices", "posture", "audit", "evidence-pack")


def _sheets(
    conn: Any, office_id: UUID, what: str, user_email: str, destination: str
) -> dict[str, tuple[list[str], list[list[Any]]]]:
    if what == "findings":
        rows = _register(conn, office_id)
        return {
            "Findings": (
                [
                    "Severity",
                    "Area",
                    "Control",
                    "Finding",
                    "Recommendation",
                    "Source",
                    "As of",
                    "Tracked",
                    "Owner",
                    "Status",
                    "Evidence",
                ],
                [
                    [
                        r["severity"],
                        r["area"],
                        r["control"],
                        r["title"],
                        r["recommendation"],
                        r["source"],
                        r["as_of"],
                        "yes" if r["item"] else "no",
                        (r["item"] or {}).get("owner"),
                        (r["item"] or {}).get("status"),
                        r["evidence"],
                    ]
                    for r in rows
                ],
            )
        }
    if what == "remediation":
        its = _items(conn, office_id)
        return {
            "Remediation": (
                [
                    "Item",
                    "Owner",
                    "Target date",
                    "Status",
                    "Overdue",
                    "Created by",
                    "Created",
                    "Closed",
                    "Closed because",
                    "Recommendation",
                ],
                [
                    [
                        i["title"],
                        i["owner"],
                        i["target_date"],
                        i["status"],
                        "yes" if i["overdue"] else "",
                        i["created_by"],
                        i["created_at"],
                        i["closed_at"],
                        i["closed_reason"],
                        i["recommendation"],
                    ]
                    for i in its
                ],
            ),
            "History": (
                ["Item", "At", "By", "From", "To", "Note"],
                [
                    [i["title"], e["at"], e["actor"], e["from_status"], e["to_status"], e["note"]]
                    for i in its
                    for e in i["events"]
                ],
            ),
        }
    if what == "devices":
        devs = office_devices(conn, office_id)
        return {
            "Devices": (
                ["Hostname", "Serial", "OS", "EDR", "Antivirus", "Managed", "Last seen", "Site", "Sources", "Matched"],
                [
                    [
                        d["hostname"],
                        d["serial"],
                        d["os"],
                        d["edr"],
                        d["av"],
                        d["managed"],
                        d["last_seen"],
                        d["site"],
                        d["sources"],
                        d["matched"],
                    ]
                    for d in devs
                ],
            )
        }
    if what == "audit":
        rows = conn.execute(
            "SELECT at, actor_email, action, detail FROM audit_log WHERE office_id = %s ORDER BY at DESC LIMIT 5000", (office_id,)
        ).fetchall()
        return {
            "Audit": (["At", "By", "Action", "Detail"], [[r["at"], r["actor_email"], r["action"], r["detail"]] for r in rows])
        }
    pack = _pack(conn, office_id, destination, user_email)
    controls = (
        ["Control", "Name", "Answer", "Evidence", "How established", "As of"],
        [[c["control"], c["name"], c["answer"], c["evidence"], c["method"], c["as_of"]] for c in pack["controls"]],
    )
    if what == "posture":
        return {"Posture": controls}
    o = pack["office"]
    return {
        "Evidence pack": controls,
        "Findings": (
            ["Severity", "Area", "Finding", "Recommendation", "Source", "As of"],
            [[f["severity"], f["area"], f["title"], f["recommendation"], f["source"], f["as_of"]] for f in pack["findings"]],
        ),
        "Remediation": (
            ["Item", "Owner", "Status", "Target date", "Closed because"],
            [[i["title"], i["owner"], i["status"], i["target_date"], i["closed_reason"]] for i in pack["remediation"]["items"]],
        ),
        "About": (
            ["Field", "Value"],
            [
                ["Destination", pack["label"]],
                ["Office", o["name"]],
                ["Workspace", o["workspace"]],
                ["Evidence as of", pack["as_of"]],
                ["Generated", pack["generated_at"]],
                ["Generated by", user_email],
                ["Statement", pack["statement"]],
            ],
        ),
    }


@router.get("/export/{what}.{fmt}")
def export(office_id: UUID, what: str, fmt: str, user: CurrentUser, destination: str = "management") -> Response:
    if what not in EXPORTS or fmt not in exports.FORMATS or destination not in DESTINATIONS:
        raise HTTPException(404, "unknown export")
    with tx() as conn:
        can_read(conn, user, office_id)
        office = _office(conn, office_id)
        data = exports.render(fmt, _sheets(conn, office_id, what, user.email, destination), title=f"{office['name']} - {what}")
        audit.record(
            conn,
            user,
            "export.downloaded",
            office_id,
            what=what,
            format=fmt,
            sha256=hashlib.sha256(data).hexdigest(),
            bytes=len(data),
        )
    safe = "".join(ch if ch.isalnum() else "-" for ch in office["name"]).strip("-")[:60]
    name = f"{safe}_{what}_{datetime.now(UTC):%Y%m%d}.{fmt}"
    return Response(data, media_type=exports.FORMATS[fmt], headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---------- notification recipients ----------


class Recipient(BaseModel):
    email: EmailStr
    events: list[Literal["scan_report", "scan_failed"]] = ["scan_report", "scan_failed"]


@router.get("/notifications")
def recipients(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    with tx() as conn:
        can_read(conn, user, office_id)
        rows = conn.execute(
            "SELECT id, email, events, added_by, added_at FROM notification_recipient WHERE office_id = %s ORDER BY email",
            (office_id,),
        ).fetchall()
        recent = conn.execute(
            "SELECT event, recipient, subject, queued_at, sent_at, last_error FROM notification_outbox WHERE office_id = %s "
            "ORDER BY queued_at DESC LIMIT 20",
            (office_id,),
        ).fetchall()
    return {"recipients": rows, "recent": recent, "sending_enabled": bool(get_settings().ses_from)}


@router.post("/notifications", status_code=201)
def add_recipient(office_id: UUID, body: Recipient, user: CurrentUser) -> dict[str, str]:
    with tx() as conn:
        can_write(conn, user, office_id)
        conn.execute(
            "INSERT INTO notification_recipient (office_id, email, events, added_by) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (office_id, lower(email)) WHERE office_id IS NOT NULL DO UPDATE SET events = EXCLUDED.events",
            (office_id, body.email.lower(), sorted(set(body.events)), user.email),
        )
        audit.record(
            conn, user, "notifications.recipient_added", office_id, email=body.email.lower(), events=sorted(set(body.events))
        )
    return {"status": "added"}


@router.delete("/notifications/{recipient_id}")
def remove_recipient(office_id: UUID, recipient_id: UUID, user: CurrentUser) -> dict[str, str]:
    with tx() as conn:
        can_write(conn, user, office_id)
        row = conn.execute(
            "DELETE FROM notification_recipient WHERE id = %s AND office_id = %s RETURNING email", (recipient_id, office_id)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "recipient not found")
        audit.record(conn, user, "notifications.recipient_removed", office_id, email=row["email"])
    return {"status": "removed"}


@router.post("/notifications/send-latest")
def send_latest(office_id: UUID, user: CurrentUser) -> dict[str, Any]:
    """Email the latest scan's report to the recipients now (a test, or a resend)."""
    with tx() as conn:
        can_write(conn, user, office_id)
        run = conn.execute(
            "SELECT id, office_id, finished_at FROM collection_run WHERE office_id = %s AND status = 'evaluated' "
            "ORDER BY started_at DESC LIMIT 1",
            (office_id,),
        ).fetchone()
        if run is None:
            raise HTTPException(409, "no scored scan yet")
        to = notify.recipients(conn, office_id, "scan_report")
        if not to:
            raise HTTPException(409, "add a recipient first")
        notify.report_run(conn, run)  # snapshot the run if the worker has not reported it yet
        snaps = conn.execute(
            "SELECT taken_at, headline, findings FROM finding_snapshot WHERE office_id = %s "
            "AND taken_at <= (SELECT taken_at FROM finding_snapshot WHERE run_id = %s) ORDER BY taken_at DESC LIMIT 2",
            (office_id, run["id"]),
        ).fetchall()
        snap, before = snaps[0], (snaps[1] if len(snaps) > 1 else None)
        office = _office(conn, office_id)
        prev = {"taken_at": before["taken_at"], "headline": before["headline"]} if before else None
        today = datetime.now(UTC).date()
        its = _items(conn, office_id)
        rem = {
            "open": sum(1 for i in its if i["status"] != "closed"),
            "overdue": sum(1 for i in its if remediation.overdue(i, today)),
            "closed_now": 0,
        }
        subject, body = notify.render_report(
            office,
            run["finished_at"],
            snap["headline"],
            prev,
            notify.diff(before["findings"] if before else None, snap["findings"]),
            rem,
        )
        ref = f"manual:{run['id']}:{datetime.now(UTC):%Y%m%dT%H%M%S}"
        queued = notify.queue(conn, office_id, "scan_report", ref, subject, body, to)
        audit.record(conn, user, "notifications.sent_latest", office_id, recipients=to)
    with tx() as conn:
        result = notify.send_pending(conn)
    return {"queued": queued, **result, "subject": subject}

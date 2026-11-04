"""Email notifications: quiet by design. One email per scan, sent once the scan has been scored:
the findings summary and what changed since the previous scan. A scan that fails all its
retries for the day sends one notice instead. Emails carry counts and titles and a link;
the evidence itself stays behind sign-in.

The portal and the worker queue into notification_outbox; send_pending() delivers through SES
when SES_FROM is set (otherwise mail stays queued and nothing leaves the platform).
"""

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

import boto3

from app import findings_engine, plain, remediation
from app.config import get_settings
from app.routers.imports import office_devices

log = logging.getLogger("notify")
EVENTS = ("scan_report", "scan_failed")
STATE_LABEL = {"met": "Met", "gap": "Gap", "weak": "Weak method", "not_observed": "Not observed", "pending": "Pending"}
MAX_LIST = 15


def recipients(conn: Any, office_id: UUID, event: str) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT lower(r.email) AS email FROM notification_recipient r JOIN office o "
        "ON r.office_id = o.id OR r.workspace_id = o.workspace_id "
        "WHERE o.id = %s AND %s = ANY(r.events) ORDER BY 1",
        (office_id, event),
    ).fetchall()
    return [r["email"] for r in rows]


def queue(conn: Any, office_id: UUID | None, event: str, ref: str, subject: str, body: str, to: list[str]) -> int:
    n = 0
    for email in to:
        n += conn.execute(
            "INSERT INTO notification_outbox (office_id, event, ref, recipient, subject, body) VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (event, ref, recipient) DO NOTHING",
            (office_id, event, ref, email, subject, body),
        ).rowcount
    return n


def send_pending(conn: Any, limit: int = 50) -> dict[str, int]:
    s = get_settings()
    if not s.ses_from:
        return {"held": conn.execute("SELECT count(*) AS n FROM notification_outbox WHERE sent_at IS NULL").fetchone()["n"]}
    ses = boto3.client("sesv2", region_name=s.aws_region)
    done = {"sent": 0, "failed": 0}
    for m in conn.execute(
        "SELECT id, recipient, subject, body FROM notification_outbox WHERE sent_at IS NULL AND attempts < 5 "
        "ORDER BY queued_at LIMIT %s FOR UPDATE SKIP LOCKED",
        (limit,),
    ).fetchall():
        try:
            r = ses.send_email(
                FromEmailAddress=s.ses_from,
                Destination={"ToAddresses": [m["recipient"]]},
                Content={"Simple": {"Subject": {"Data": m["subject"][:200]}, "Body": {"Text": {"Data": m["body"]}}}},
            )
            conn.execute(
                "UPDATE notification_outbox SET sent_at = now(), attempts = attempts + 1, message_id = %s, last_error = NULL WHERE id = %s",
                (r.get("MessageId"), m["id"]),
            )
            done["sent"] += 1
        except Exception as e:  # noqa: BLE001 (one bad address must not stop the rest)
            conn.execute(
                "UPDATE notification_outbox SET attempts = attempts + 1, last_error = %s WHERE id = %s",
                (f"{type(e).__name__}: {str(e)[:300]}", m["id"]),
            )
            done["failed"] += 1
    return done


# ---------- the scan report ----------


def headline(conn: Any, office_id: UUID, run_id: UUID, findings: list[findings_engine.Finding]) -> dict[str, Any]:
    controls = {
        str(c["control"]): {"name": c["name"], "state": c["state"]}
        for c in conn.execute("SELECT control, name, state FROM control_result WHERE run_id = %s ORDER BY control", (run_id,))
    }
    devs = office_devices(conn, office_id)
    if devs:
        covered = sum(1 for d in devs if d["edr"] == "active")
        controls["5"] = {
            "name": controls.get("5", {}).get("name", "EDR on endpoints"),
            "state": "met" if covered == len(devs) else "gap",
        }
    sev: dict[str, int] = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return {
        "controls": controls,
        "devices": len(devs),
        "edr_active": sum(1 for d in devs if d["edr"] == "active"),
        "findings": len(findings),
        "by_severity": sev,
    }


def diff(prev: list[dict[str, Any]] | None, cur: list[dict[str, Any]]) -> dict[str, list[Any]]:
    if prev is None:
        return {"new": [], "resolved": [], "changed": []}
    p = {f["key"]: f for f in prev}
    c = {f["key"]: f for f in cur}
    return {
        "new": [c[k] for k in c if k not in p],
        "resolved": [p[k] for k in p if k not in c],
        # Snapshots from before plain wording ("plain" absent) only differ in words, not in substance.
        "changed": [
            (p[k], c[k]) for k in c if k in p and p[k]["title"] != c[k]["title"] and p[k].get("plain") == c[k].get("plain")
        ],
    }


def _lines(title: str, items: list[str]) -> list[str]:
    if not items:
        return []
    out = [f"{title} ({len(items)}):"] + [f"  - {i}" for i in items[:MAX_LIST]]
    if len(items) > MAX_LIST:
        out.append(f"  ... and {len(items) - MAX_LIST} more in the portal")
    return out


def render_report(
    office: dict[str, Any],
    at: datetime,
    head: dict[str, Any],
    prev: dict[str, Any] | None,
    changes: dict[str, list[Any]],
    rem: dict[str, int],
) -> tuple[str, str]:
    tz = ZoneInfo(office["time_zone"])
    local = at.astimezone(tz)
    when = f"{local:%d %b %Y %H:%M} {local.tzname()}"
    gaps = sum(1 for c in head["controls"].values() if c["state"] in ("gap", "weak"))
    subject = f"[D-Biz Assure] {office['name']}: scan {local:%d %b} - {head['findings']} findings"
    if prev is not None:
        subject += f", {len(changes['new'])} new, {len(changes['resolved'])} resolved"
    body = [
        f"Scan completed {when} for {office['name']} ({office['workspace']}).",
        "",
        "Controls:",
    ]
    prev_controls = (prev or {}).get("headline", {}).get("controls", {})
    for n, c in sorted(head["controls"].items(), key=lambda kv: int(kv[0])):
        was = prev_controls.get(n, {}).get("state")
        moved = f"  (was {STATE_LABEL.get(was, was)})" if was and was != c["state"] else ""
        body.append(f"  {n} {c['name']}: {STATE_LABEL.get(c['state'], c['state'])}{moved}")
    body.append(f"  {gaps} control(s) with a gap or weak method.")
    if head["devices"]:
        pct = round(100 * head["edr_active"] / head["devices"])
        line = f"Devices: {head['devices']}, EDR active on {head['edr_active']} ({pct}%)"
        ph = (prev or {}).get("headline", {})
        if ph.get("devices"):
            line += f"; previous scan {ph['devices']} devices, {ph['edr_active']} active"
        body += ["", line]
    sev = ", ".join(f"{v} {plain.SEVERITY.get(k, k).lower()}" for k, v in sorted(head["by_severity"].items()))
    body += ["", f"Findings: {head['findings']}" + (f" ({sev})" if sev else "")]
    if prev is None:
        body.append("This is the first reported scan; later emails list what changed.")
    else:
        since = prev["taken_at"].astimezone(tz)
        body += ["", f"Changes since the previous scan ({since:%d %b %Y %H:%M}):"]
        block = (
            _lines("New", [f"[{plain.SEVERITY.get(f['severity'], f['severity'])}] {f['title']}" for f in changes["new"]])
            + _lines("Resolved", [f["title"] for f in changes["resolved"]])
            + _lines("Changed", [f"{a['title']}  ->  {b['title']}" for a, b in changes["changed"]])
        )
        body += block or ["  No change."]
    body += [
        "",
        f"Remediation: {rem['open']} open, {rem['overdue']} past target date, {rem['closed_now']} closed by this scan.",
        "",
        f"Details (sign-in required): {get_settings().public_url}/offices/{office['id']}/remediation",
        "",
        "You receive one email per scan because you are a notification recipient for this office.",
        "Change this in the portal: the office's Remediation page > Notifications.",
    ]
    return subject, "\n".join(body)


def report_run(conn: Any, run: dict[str, Any]) -> int:
    """Snapshot the findings for an evaluated run and queue its report. Idempotent per run."""
    office = conn.execute(
        "SELECT o.id, o.name, o.time_zone, w.name AS workspace FROM office o JOIN workspace w ON w.id = o.workspace_id WHERE o.id = %s",
        (run["office_id"],),
    ).fetchone()
    findings = findings_engine.build(conn, office["id"])
    cur = [{"key": f.key, "title": f.title, "severity": f.severity, "plain": True} for f in findings]
    head = headline(conn, office["id"], run["id"], findings)
    prev = conn.execute(
        "SELECT taken_at, headline, findings FROM finding_snapshot WHERE office_id = %s ORDER BY taken_at DESC LIMIT 1",
        (office["id"],),
    ).fetchone()
    inserted = conn.execute(
        "INSERT INTO finding_snapshot (office_id, run_id, headline, findings) VALUES (%s, %s, %s, %s) ON CONFLICT (run_id) DO NOTHING",
        (office["id"], run["id"], json.dumps(head), json.dumps(cur)),
    ).rowcount
    if not inserted:
        return 0
    remediation.sync(conn, office["id"], findings)
    items = conn.execute(
        "SELECT status, target_date, closed_at FROM remediation_item WHERE office_id = %s", (office["id"],)
    ).fetchall()
    today = datetime.now(UTC).date()
    since = prev["taken_at"] if prev else run["finished_at"]
    rem = {
        "open": sum(1 for i in items if i["status"] != "closed"),
        "overdue": sum(1 for i in items if remediation.overdue(i, today)),
        "closed_now": sum(1 for i in items if i["closed_at"] and i["closed_at"] >= since),
    }
    prev_d = {"taken_at": prev["taken_at"], "headline": prev["headline"]} if prev else None
    subject, body = render_report(office, run["finished_at"], head, prev_d, diff(prev["findings"] if prev else None, cur), rem)
    return queue(conn, office["id"], "scan_report", str(run["id"]), subject, body, recipients(conn, office["id"], "scan_report"))


def report_new_runs(conn: Any, within: timedelta = timedelta(days=2)) -> int:
    """Every evaluated run without a snapshot yet (the evaluator scores; the next worker run reports)."""
    runs = conn.execute(
        "SELECT r.id, r.office_id, r.finished_at FROM collection_run r "
        "WHERE r.status = 'evaluated' AND r.finished_at > now() - %s "
        "AND NOT EXISTS (SELECT 1 FROM finding_snapshot s WHERE s.run_id = r.id) ORDER BY r.finished_at",
        (within,),
    ).fetchall()
    return sum(report_run(conn, r) for r in runs)


def report_failure(conn: Any, office_id: UUID, error: str) -> int:
    office = conn.execute("SELECT name, time_zone FROM office WHERE id = %s", (office_id,)).fetchone()
    local = datetime.now(UTC).astimezone(ZoneInfo(office["time_zone"]))
    subject = f"[D-Biz Assure] {office['name']}: today's scan failed"
    body = (
        f"The scheduled scan for {office['name']} failed after all retries on {local:%d %b %Y} ({error[:200]}).\n\n"
        "Posture and findings still show the last successful scan. The usual causes are a revoked consent or an\n"
        "expired permission in the tenant; the platform team has the full error.\n\n"
        f"Details (sign-in required): {get_settings().public_url}/offices/{office_id}/posture"
    )
    ref = f"{office_id}:{local:%Y-%m-%d}"
    return queue(conn, office_id, "scan_failed", ref, subject, body, recipients(conn, office_id, "scan_failed"))

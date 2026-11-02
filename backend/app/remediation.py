"""Remediation tracker (walkthrough slide 24): work moves across the board and closes only on
fresh evidence. Nobody closes an item by hand; it closes when a scan, import or collector run
newer than the item's last move no longer shows the finding. The platform tracks the work; the
county or company does it in its own tools (R7).
"""

from datetime import date
from typing import Any
from uuid import UUID

from app.findings_engine import Finding

STATUSES = ("open", "in_progress", "awaiting_evidence", "closed")
MOVABLE = ("open", "in_progress", "awaiting_evidence")


def sync(conn: Any, office_id: UUID, findings: list[Finding]) -> int:
    """Close live items whose finding is gone in evidence newer than the item's last move."""
    current = {f.key for f in findings}
    newest = max((f.as_of for f in findings if f.as_of), default=None)
    latest = conn.execute(
        "SELECT greatest("
        " (SELECT max(finished_at) FROM collection_run WHERE office_id = %(o)s AND status = 'evaluated'),"
        " (SELECT max(assessed_at) FROM scuba_assessment WHERE office_id = %(o)s),"
        " (SELECT max(observed_at) FROM device_observation WHERE office_id = %(o)s)) AS at",
        {"o": office_id},
    ).fetchone()["at"]
    evidence_at = max(x for x in (newest, latest) if x is not None) if (newest or latest) else None
    closed = 0
    for item in conn.execute(
        "SELECT id, finding_key, status, updated_at FROM remediation_item WHERE office_id = %s AND status <> 'closed'",
        (office_id,),
    ).fetchall():
        if item["finding_key"] in current or evidence_at is None or evidence_at <= item["updated_at"]:
            continue
        reason = f"Closed by re-read {evidence_at:%d %b %Y}: the finding is no longer present"
        conn.execute(
            "UPDATE remediation_item SET status = 'closed', closed_at = now(), closed_reason = %s, updated_at = now() WHERE id = %s",
            (reason, item["id"]),
        )
        conn.execute(
            "INSERT INTO remediation_event (item_id, actor, from_status, to_status, note) VALUES (%s, 'evidence', %s, 'closed', %s)",
            (item["id"], item["status"], reason),
        )
        closed += 1
    return closed


def overdue(item: dict[str, Any], today: date) -> bool:
    return item["status"] != "closed" and item["target_date"] is not None and item["target_date"] < today

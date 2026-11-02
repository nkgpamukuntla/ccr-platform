"""The findings register (walkthrough slide 23): every gap becomes a finding with a recommendation.

Built on read from what is already stored, so it is deterministic and always current:
- control gaps and weak methods from the latest evaluated Microsoft run;
- SCuBA SHALL policies that fail, from the newest assessment per product;
- device issues from the reconciled register (no EDR agent, EDR stale, Windows out of support).

Each finding has a stable key so remediation items can follow it across runs, and `as_of`, the
date of the evidence behind it: an item closes only on evidence newer than the item.
Recommendations are worded as outcomes, never products.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.routers.imports import office_devices
from app.routers.microsoft import _edr_from_devices

RECOMMEND: dict[tuple[int, str], str] = {
    (1, "gap"): "Require MFA for all users on remote and cloud access with a Conditional Access policy that is On.",
    (1, "weak"): "Turn the report-only MFA policy On after testing, so MFA is enforced rather than reported.",
    (2, "gap"): "Include guests and external users in a Conditional Access policy that requires MFA.",
    (2, "weak"): "Enforce, rather than report, MFA for guests and external users.",
    (3, "gap"): "Register MFA for every account holding an administrator role, or remove the role.",
    (
        3,
        "weak",
    ): "Move administrators to phishing-resistant MFA (security key, Windows Hello or passkey) and remove SMS and voice.",
    (4, "gap"): "Require MFA for access to backup consoles and storage.",
}
SEVERITY = {"gap": "Mandatory", "weak": "High"}


class Finding(BaseModel):
    key: str
    title: str
    area: str  # Identity | Devices
    control: int | None
    severity: str  # Mandatory | High | Medium
    source: str  # how the evidence was established
    recommendation: str
    as_of: datetime | None
    evidence: dict[str, Any]


def _source_label(sources: set[str]) -> str:
    labels = sorted(
        {"Collected" if s.startswith("collector") else "Imported" if s.startswith("import") else "Connected" for s in sources}
    )
    return " + ".join(labels) or "Imported"


def _control_title(c: dict[str, Any]) -> str:
    d = c.get("detail") or {}
    if c["control"] == 3 and c["state"] == "weak" and d.get("phone_only"):
        return f"{len(d['phone_only'])} admin(s) with phone-only MFA"
    if c["control"] == 3 and d.get("not_registered"):
        return f"{len(d['not_registered'])} admin(s) without MFA registered"
    return f"{c['name']}: {'weak method' if c['state'] == 'weak' else 'gap'}"


def build(conn: Any, office_id: UUID) -> list[Finding]:
    out: list[Finding] = []
    run = conn.execute(
        "SELECT id, finished_at, started_at FROM collection_run WHERE office_id = %s AND status = 'evaluated' "
        "ORDER BY started_at DESC LIMIT 1",
        (office_id,),
    ).fetchone()
    devs = office_devices(conn, office_id)
    if run:
        for c in conn.execute(
            "SELECT control, name, state, method, detail FROM control_result WHERE run_id = %s ORDER BY control", (run["id"],)
        ).fetchall():
            if c["control"] == 5:
                c = _edr_from_devices(c, devs)
                continue  # EDR is reported per device issue below
            if c["state"] not in SEVERITY:
                continue
            out.append(
                Finding(
                    key=f"control:{c['control']}",
                    title=_control_title(c),
                    area="Identity",
                    control=c["control"],
                    severity=SEVERITY[c["state"]],
                    source=c["method"],
                    recommendation=RECOMMEND.get((c["control"], c["state"]), "Close the gap shown in the evidence."),
                    as_of=run["finished_at"] or run["started_at"],
                    evidence=c["detail"] or {},
                )
            )

    # SCuBA: the newest assessment per product, SHALL policies that fail.
    seen: set[str] = set()
    for a in conn.execute(
        "SELECT id, source, assessed_at, products FROM scuba_assessment WHERE office_id = %s ORDER BY assessed_at DESC",
        (office_id,),
    ).fetchall():
        fresh = [p.lower() for p in a["products"] if p.lower() not in seen]
        seen.update(fresh)
        if not fresh:
            continue
        for r in conn.execute(
            "SELECT product, policy_id, requirement, details FROM scuba_result "
            "WHERE assessment_id = %s AND status = 'fail' AND lower(product) = ANY(%s) ORDER BY policy_id",
            (a["id"], fresh),
        ).fetchall():
            req = (r["requirement"] or r["policy_id"]).strip()
            out.append(
                Finding(
                    key=f"scuba:{r['policy_id']}",
                    title=f"{r['policy_id']}: {req[:140]}",
                    area="Identity" if r["product"].lower() == "aad" else r["product"].upper(),
                    control=None,
                    severity="High",
                    source="Connected · SCuBA" if a["source"] == "collected" else "Imported · ScubaGear report",
                    recommendation=req,
                    as_of=a["assessed_at"],
                    evidence={"details": r["details"][:500]},
                )
            )

    if devs:
        newest = conn.execute(
            "SELECT max(observed_at) AS at, array_agg(DISTINCT source) AS sources FROM device_observation WHERE office_id = %s",
            (office_id,),
        ).fetchone()
        src = _source_label(set(newest["sources"] or []))

        def device_finding(key: str, title: str, severity: str, rec: str, hit: list[dict[str, Any]]) -> None:
            if hit:
                names = sorted(d["hostname"] or d["serial"] or "?" for d in hit)
                out.append(
                    Finding(
                        key=key,
                        title=title.format(n=len(hit), total=len(devs)),
                        area="Devices",
                        control=5 if key.startswith("device:edr") else None,
                        severity=severity,
                        source=src,
                        recommendation=rec,
                        as_of=newest["at"],
                        evidence={"devices": len(hit), "of": len(devs), "sample": names[:25]},
                    )
                )

        device_finding(
            "device:edr_missing",
            "{n} of {total} devices with no EDR agent",
            "Mandatory",
            "Deploy EDR to every device that processes court or company data, or record why a device is out of scope.",
            [d for d in devs if d["edr"] == "none"],
        )
        device_finding(
            "device:edr_stale",
            "{n} devices whose EDR agent has not reported recently",
            "High",
            "Bring stale sensors back online, or retire the devices and remove them from the console.",
            [d for d in devs if d["edr"] == "inactive"],
        )
        device_finding(
            "device:windows10",
            "{n} devices on Windows 10 (out of support)",
            "High",
            "Upgrade to a supported Windows version or replace the device.",
            [d for d in devs if "windows 10" in (d["os"] or "").lower()],
        )
    return out

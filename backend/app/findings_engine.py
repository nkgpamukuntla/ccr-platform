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

from app import licences, plain
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
    why: str = ""  # why it matters, in plain words
    theme: str = ""  # the recommendation it belongs to (plain.THEMES)
    technical: str = ""  # the official wording, shown on request


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
    fx: dict[str, Any] = {}
    if run:
        row = conn.execute("SELECT facts FROM run_facts WHERE run_id = %s", (run["id"],)).fetchone()
        fx = row["facts"] if row else {}
        for c in conn.execute(
            "SELECT control, name, state, method, detail FROM control_result WHERE run_id = %s ORDER BY control", (run["id"],)
        ).fetchall():
            if c["control"] == 5:
                c = _edr_from_devices(c, devs)
                continue  # EDR is reported per device issue below
            if c["state"] not in SEVERITY:
                continue
            words = plain.control(c["control"], c["state"])
            title = _control_title(c)
            out.append(
                Finding(
                    key=f"control:{c['control']}",
                    title=title if title[0].isdigit() or not words else words[0],
                    why=words[1] if words else "",
                    technical=f"Control {c['control']} ({c['name']}): {c['state']}. {plain.answer(c)}".strip(),
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
            sw = plain.scuba(r["policy_id"])
            out.append(
                Finding(
                    key=f"scuba:{r['policy_id']}",
                    title=sw[0] if sw else f"{r['policy_id']}: {req[:140]}",
                    why=sw[1] if sw else "",
                    technical=f"CISA SCuBA {r['policy_id']}: {req}",
                    area="Identity" if r["product"].lower() == "aad" else r["product"].upper(),
                    control=None,
                    severity="High",
                    source="Connected · SCuBA" if a["source"] == "collected" else "Imported · ScubaGear report",
                    recommendation=sw[2] if sw else req,
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
                        why=plain.DEVICE.get(key, ""),
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
    if run:
        out += _tenant_findings(fx, devs, run["finished_at"] or run["started_at"])
    for f in out:
        f.theme = plain.theme(f.key)
    return out


def _tenant_findings(fx: dict[str, Any], devs: list[dict[str, Any]], as_of: datetime) -> list[Finding]:
    """Intune and email-authentication findings from the latest scan's facts."""
    out: list[Finding] = []

    def add(key: str, title: str, severity: str, source: str, rec: str, technical: str, evidence: dict[str, Any]) -> None:
        out.append(
            Finding(
                key=key,
                title=title,
                area="Email" if key.startswith("email:") else "Devices",
                control=None,
                severity=severity,
                source=source,
                recommendation=rec,
                why=plain.DEVICE.get(key, ""),
                technical=technical,
                as_of=as_of,
                evidence=evidence,
            )
        )

    it = fx.get("intune")
    if it:
        src = "Connected · Intune"
        if it["unencrypted"]:
            add(
                "intune:unencrypted",
                f"{it['unencrypted']} of {it['computers']} computers without disk encryption",
                "High",
                src,
                "Turn on BitLocker (Windows) or FileVault (Mac) with an Intune policy, keeping the recovery keys in Entra ID.",
                "Intune managedDevices isEncrypted = false",
                {"devices": it["unencrypted"], "of": it["computers"], "sample": it["sample"]["unencrypted"]},
            )
        if it["noncompliant"]:
            add(
                "intune:noncompliant",
                f"{it['noncompliant']} of {it['total']} devices fail your Intune compliance rules",
                "Medium",
                src,
                "Fix or retire the non-compliant devices, and block them from company data with Conditional Access.",
                "Intune managedDevices complianceState = noncompliant",
                {"devices": it["noncompliant"], "of": it["total"], "sample": it["sample"]["noncompliant"]},
            )
        if it["stale"]:
            add(
                "intune:stale",
                f"{it['stale']} devices have not checked in with Intune for over 30 days",
                "Medium",
                src,
                "Find these devices and bring them back online, or retire and remove them from Intune.",
                "Intune managedDevices lastSyncDateTime older than 30 days",
                {"devices": it["stale"], "of": it["total"], "sample": it["sample"]["stale"]},
            )
        if it["windows10"] and not devs:  # the device register reports Windows 10 when it has devices
            add(
                "device:windows10",
                f"{it['windows10']} devices on Windows 10 (out of support)",
                "High",
                src,
                "Upgrade to a supported Windows version or replace the device.",
                "Intune managedDevices osVersion 10.0 build below 22000",
                {"devices": it["windows10"], "of": it["total"], "sample": it["sample"]["windows10"]},
            )

    ld = fx.get("licence_data")
    if ld:
        it_total = it["total"] if it else None
        idle = [x for x in licences.model(ld, as_of, {}, it_total, 0)["security"] if x["in_use"] is False]
        if idle:
            add(
                "licence:security_unused",
                f"{len(idle)} security feature(s) paid for but not switched on",
                "Medium",
                "Connected · Graph",
                "Switch on: " + "; ".join(x["feature"] for x in idle) + ".",
                "Licence service plans vs configuration: " + "; ".join(f"{x['feature']} ({x['note']})" for x in idle),
                {"features": [{"feature": x["feature"], "included_in": x["included_in"], "note": x["note"]} for x in idle]},
            )

    em = fx.get("email")
    if em:
        rows = {d["domain"]: d for d in em["domains"]}
        if em["unsafe"]:
            add(
                "email:spoofable",
                f"{len(em['unsafe'])} email domain(s) can be faked (no SPF or DMARC)",
                "High",
                "Public DNS",
                "Publish an SPF record ending in -all and a DMARC record for each domain, then move DMARC to quarantine or reject.",
                "RFC 7208 SPF / RFC 7489 DMARC record missing or invalid",
                {"domains": [rows[d] for d in em["unsafe"]]},
            )
        if em["loose"]:
            add(
                "email:dmarc_monitor",
                f"{len(em['loose'])} email domain(s) only monitor fake email (DMARC p=none or SPF ?all)",
                "Medium",
                "Public DNS",
                "After checking the DMARC reports, change the policy to p=quarantine, then p=reject.",
                "DMARC p=none, or SPF without -all/~all",
                {"domains": [rows[d] for d in em["loose"]]},
            )
    return out

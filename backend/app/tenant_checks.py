"""Intune managed devices and Microsoft Secure Score, from the recorded Graph reads.

Pure, like app/controls.py: a read Microsoft did not answer (no consent for the permission yet,
or no Intune licence) gives None, which every page shows as "Not checked yet".
"""

from datetime import datetime, timedelta
from typing import Any

from app.microsoft.graph import items

STALE = timedelta(days=30)  # Intune expects a check-in at least every few days
SAMPLE = 25


def _when(s: str | None) -> datetime | None:
    if not s or s.startswith("0001-"):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def windows10(os_name: str | None, version: str | None) -> bool:
    """Windows 10 reports 10.0.<build> with a build below 22000 (Windows 11 starts at 22000)."""
    if "windows" not in (os_name or "").lower():
        return False
    parts = (version or "").split(".")
    return len(parts) >= 3 and parts[0] == "10" and parts[2].isdigit() and int(parts[2]) < 22000


def intune_rows(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": d.get("deviceName"),
            "serial": d.get("serialNumber") or None,
            "os": d.get("operatingSystem"),
            "os_version": d.get("osVersion"),
            "compliance": d.get("complianceState"),
            "encrypted": d.get("isEncrypted"),
            "last_sync": d.get("lastSyncDateTime"),
            "ownership": d.get("managedDeviceOwnerType"),
        }
        for d in devices
    ]


def intune(reads: dict[str, dict[str, Any]], at: datetime) -> dict[str, Any] | None:
    r = reads.get("managed_devices", {})
    if r.get("status") != 200:
        return None
    rows = intune_rows(items(r))

    def names(hit: list[dict[str, Any]]) -> list[str]:
        return sorted(x["name"] or x["serial"] or "?" for x in hit)[:SAMPLE]

    noncompliant = [x for x in rows if x["compliance"] == "noncompliant"]
    unencrypted = [x for x in rows if x["encrypted"] is False and (x["os"] or "").lower() in ("windows", "macos")]
    win10 = [x for x in rows if windows10(x["os"], x["os_version"])]
    stale = [x for x in rows if (t := _when(x["last_sync"])) is not None and at - t > STALE]
    by_os: dict[str, int] = {}
    for x in rows:
        by_os[x["os"] or "Unknown"] = by_os.get(x["os"] or "Unknown", 0) + 1
    pol = reads.get("compliance_policies", {})
    return {
        "total": len(rows),
        "compliant": sum(1 for x in rows if x["compliance"] == "compliant"),
        "noncompliant": len(noncompliant),
        "computers": sum(1 for x in rows if (x["os"] or "").lower() in ("windows", "macos")),
        "encrypted": sum(1 for x in rows if x["encrypted"] is True and (x["os"] or "").lower() in ("windows", "macos")),
        "unencrypted": len(unencrypted),
        "windows10": len(win10),
        "stale": len(stale),
        "personal": sum(1 for x in rows if x["ownership"] == "personal"),
        "by_os": by_os,
        "policies": len(items(pol)) if pol.get("status") == 200 else None,
        "sample": {
            "noncompliant": names(noncompliant),
            "unencrypted": names(unencrypted),
            "windows10": names(win10),
            "stale": names(stale),
        },
    }


def secure_score(reads: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """Microsoft's own score (context, not ours), with the biggest open improvement actions."""
    r = reads.get("secure_scores", {})
    latest = items(r)[:1] if r.get("status") == 200 else []
    if not latest:
        return None
    s = latest[0]
    current, top = s.get("currentScore") or 0, s.get("maxScore") or 0
    scored = {c.get("controlName"): c.get("score") or 0 for c in s.get("controlScores") or []}
    profiles = items(reads.get("secure_score_profiles", {}))
    gaps: list[dict[str, Any]] = [
        {
            "title": p.get("title") or p.get("id"),
            "category": p.get("controlCategory"),
            "gain": round((p.get("maxScore") or 0) - scored[p["id"]], 1),
            "impact": p.get("userImpact"),
        }
        for p in profiles
        if p.get("id") in scored and not p.get("deprecated") and (p.get("maxScore") or 0) - scored[p["id"]] > 0
    ]
    gaps.sort(key=lambda g: -g["gain"])
    peers = [c for c in s.get("averageComparativeScores") or [] if c.get("basis") == "AllTenants"]
    return {
        "current": round(current, 1),
        "max": round(top, 1),
        "percent": round(100 * current / top) if top else None,
        "as_of": s.get("createdDateTime"),
        "all_tenants_average": round(peers[0]["averageScore"], 1) if peers and peers[0].get("averageScore") is not None else None,
        "top_actions": gaps[:8],
    }

"""Entra ID device records (Graph /devices): why the count is what it is.

Entra keeps a record for every device that ever joined or registered and never removes one on
its own, so the raw count runs well above the machines in use. This reads the records into
activity, join type and repeated names, explains each repeat, and checks the active company
computers against the EDR register. Read-only: nothing here changes the tenant (R7).
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

ACTIVE = timedelta(days=30)  # approximateLastSignInDateTime is refreshed about every 14 days
STALE = timedelta(days=90)  # Microsoft's own stale-device guidance
JOIN = {"AzureAd": "Entra joined", "ServerAd": "Hybrid joined", "Workplace": "Registered"}
COMPANY_JOINS = {"Entra joined", "Hybrid joined"}
GENERIC = re.compile(r"^(iphone|ipad|android|galaxy|pixel|sm-|moto|redmi|oneplus)", re.I)


def _when(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def _family(os: str | None) -> str:
    o = (os or "").lower()
    if o.startswith("windows"):
        return "Windows"
    if o in ("macos", "mac os x", "macmdm") or o.startswith("mac"):
        return "macOS"
    if o in ("ios", "ipados"):
        return "iOS/iPadOS"
    if o.startswith("android"):
        return "Android"
    if o.startswith("linux"):
        return "Linux"
    return os or "Unknown"


def host(name: str | None) -> str:
    """Comparable host name: lower case, no domain suffix."""
    return (name or "").strip().lower().split(".")[0]


def rows(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The fields kept per record (no ids, no owners)."""
    return [
        {
            "name": d.get("displayName"),
            "os": _family(d.get("operatingSystem")),
            "os_version": d.get("operatingSystemVersion"),
            "join": JOIN.get(d.get("trustType") or "", "Unknown"),
            "ownership": d.get("deviceOwnership"),
            "managed": bool(d.get("isManaged")),
            "compliant": bool(d.get("isCompliant")),
            "last_sign_in": d.get("approximateLastSignInDateTime"),
            "registered": d.get("registrationDateTime"),
        }
        for d in devices
    ]


def _activity(r: dict[str, Any], at: datetime) -> str:
    seen = _when(r["last_sign_in"])
    if seen is None:
        return "never"
    age = at - seen
    return "active" if age <= ACTIVE else "recent" if age <= STALE else "stale"


def _count(values: list[str]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for v in values:
        out[v] += 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _reason(group: list[dict[str, Any]]) -> str:
    joins = {r["join"] for r in group}
    acts = [r["activity"] for r in group]
    live = sum(1 for a in acts if a in ("active", "recent"))
    if group[0]["os"] in ("iOS/iPadOS", "Android") and GENERIC.match(group[0]["name"] or ""):
        return "Default phone or tablet name: these are most likely different devices, not repeats"
    if "Registered" in joins and joins & COMPANY_JOINS:
        return "Registered by a user and also joined: one machine with two records"
    if {"Entra joined", "Hybrid joined"} <= joins:
        return "Hybrid joined and Entra joined: the machine changed join type and kept the old record"
    if live == 1:
        return "Reimaged or re-joined: one record is in use, the older ones were left behind"
    if live == 0:
        return "Retired: no record has signed in for 90 days"
    return "More than one record in use: two machines may share this name"


def summarize(devices: list[dict[str, Any]], at: datetime) -> dict[str, Any]:
    """Counts for the posture page, as of the scan."""
    rs = [{**r, "activity": _activity(r, at)} for r in rows(devices)]
    groups = _repeats(rs)
    company = [r for r in rs if r["join"] in COMPANY_JOINS and r["os"] in ("Windows", "macOS")]
    return {
        "total": len(rs),
        "managed": sum(1 for r in rs if r["managed"]),
        "compliant": sum(1 for r in rs if r["compliant"]),
        "activity": {k: sum(1 for r in rs if r["activity"] == k) for k in ("active", "recent", "stale", "never")},
        "join": _count([r["join"] for r in rs]),
        "os": _count([r["os"] for r in rs]),
        "repeated_names": len(groups),
        "extra_records": sum(len(g) - 1 for g in groups),
        "company_computers_active": sum(1 for r in company if r["activity"] == "active"),
    }


def _repeats(rs: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    by: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rs:
        if r["name"]:
            by[host(r["name"])].append(r)
    groups = [sorted(g, key=lambda r: r["last_sign_in"] or "", reverse=True) for g in by.values() if len(g) > 1]
    return sorted(groups, key=lambda g: (-len(g), host(g[0]["name"])))


def explain(stored: list[dict[str, Any]], at: datetime, edr_hosts: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Repeated names with a reason each, and the active company computers checked against the EDR register."""
    rs = [{**r, "activity": _activity(r, at)} for r in stored]
    repeats = [
        {"name": g[0]["name"], "records": len(g), "reason": _reason(g), "keep": g[0]["last_sign_in"], "items": g}
        for g in _repeats(rs)
    ]
    out: dict[str, Any] = {"repeats": repeats, "records": rs, "edr": None}
    if edr_hosts:
        edr = {host(d["hostname"]): d for d in edr_hosts if d.get("hostname")}
        company = {
            host(r["name"]): r
            for r in rs
            if r["join"] in COMPANY_JOINS and r["os"] in ("Windows", "macOS") and r["activity"] == "active" and r["name"]
        }
        missing = sorted((r for h, r in company.items() if h not in edr), key=lambda r: host(r["name"]))
        out["edr"] = {
            "company_computers_active": len(company),
            "with_edr": sum(1 for h in company if h in edr),
            "without_edr": missing,
            "edr_only": sorted(d["hostname"] for h, d in edr.items() if h not in company),
        }
    return out

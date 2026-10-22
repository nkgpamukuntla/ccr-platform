"""CSV imports from the county's own tools (walkthrough slide 9).

Each template names the columns it needs; common vendor header names are accepted as aliases so a
console export can be uploaded as it comes. A file is validated before anything is stored: missing
required columns reject it; bad rows are rejected individually and listed; duplicates and odd values
are warned. Nothing is loaded silently.
"""

import csv
import io
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from pydantic import BaseModel


@dataclass(frozen=True)
class Template:
    key: str
    label: str
    source_hint: str
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()
    one_of: tuple[str, ...] = ()  # at least one of these must be present in each row
    aliases: dict[str, tuple[str, ...]] = field(default_factory=dict)


# Canonical columns: hostname, serial, mac, os, os_build, last_seen, edr_product, edr_status,
# agent_id, agent_version, managed, compliance, last_patch, av_state, model, site, role, entra_device_id
ALIASES: dict[str, tuple[str, ...]] = {
    "hostname": ("hostname", "host name", "device name", "devicename", "computer name", "computername", "name", "machine name"),
    "serial": ("serial", "serial number", "serialnumber", "serial no", "system serial number"),
    "mac": ("mac", "mac address", "macaddress", "local ip mac"),
    "os": ("os", "operating system", "os version", "platform", "os name"),
    "os_build": ("os build", "osbuild", "build", "os build number", "kernel version"),
    "last_seen": ("last seen", "lastseen", "last check-in", "last check in", "last contact", "last sync", "last sync date time"),
    "agent_id": ("agent id", "agentid", "aid", "sensor id", "device id", "uuid"),
    "agent_version": ("agent version", "agentversion", "sensor version", "version"),
    "edr_status": ("status", "agent status", "sensor status", "health status", "health state"),
    "edr_product": ("edr product", "edr", "security product", "antivirus"),
    "managed": ("managed", "is managed", "managed by"),
    "compliance": ("compliance", "compliance state", "compliant"),
    "last_patch": ("last patch", "last patch date", "last patched", "patch date"),
    "av_state": ("av state", "antivirus state", "av status", "defender status"),
    "model": ("model", "device model", "make/model"),
    "site": ("site", "site code", "location"),
    "role": ("role", "device role", "usage"),
    "entra_device_id": ("entra id", "azure ad device id", "aad device id", "entra device id"),
}

TEMPLATES: dict[str, Template] = {
    t.key: t
    for t in [
        Template(
            "edr_hosts",
            "EDR console host list",
            "CrowdStrike, Defender, SentinelOne, Cortex",
            required=("hostname", "agent_id", "agent_version", "edr_status", "last_seen"),
            optional=("serial", "mac", "os", "edr_product"),
        ),
        Template(
            "rmm_inventory",
            "RMM device inventory",
            "The county's or MSP's RMM tool",
            required=("hostname", "serial", "os_build", "last_patch", "av_state"),
            optional=("os", "mac", "model", "last_seen", "site"),
        ),
        Template(
            "intune_devices",
            "Intune devices export",
            "Intune admin centre, Devices > Export",
            required=("serial", "model", "os", "compliance", "entra_device_id"),
            optional=("hostname", "os_build", "last_seen"),
        ),
        Template(
            "asset_register",
            "County asset register",
            "The county's own spreadsheet",
            required=("site", "role"),
            one_of=("hostname", "serial"),
            optional=("model", "os"),
        ),
        Template(
            "generic_v1",
            "CCR template v1",
            "Any source, in our columns",
            required=(),
            one_of=("hostname", "serial"),
            optional=("mac", "os", "os_build", "last_seen", "edr_product", "edr_status", "managed", "site"),
        ),
    ]
}

KNOWN_OS = re.compile(r"windows|macos|mac os|os x|linux|ubuntu|ios|android|chrome", re.IGNORECASE)
ACTIVE = {"online", "active", "normal", "healthy", "running", "protected", "enabled", "connected", "ok"}
INACTIVE = {"offline", "inactive", "disabled", "unhealthy", "stopped", "degraded", "not running", "uninstalled"}


class Issue(BaseModel):
    row: int | None
    level: str  # error | warning
    message: str


class Validation(BaseModel):
    template: str
    columns: dict[str, str]  # canonical -> header in file
    rows_total: int
    rows_ok: int
    rows_rejected: int
    accepted: bool
    issues: list[Issue]
    devices: list[dict[str, Any]]


def norm(h: str) -> str:
    return re.sub(r"\s+", " ", h.strip().lower().replace("_", " "))


def parse_date(v: str) -> datetime | None:
    v = (v or "").strip()
    if not v:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y",
    ):
        try:
            d = datetime.strptime(v.replace(".000Z", "Z"), fmt)
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def edr_state(v: str) -> str | None:
    s = (v or "").strip().lower()
    if not s:
        return None
    if s in ACTIVE:
        return "active"
    if s in INACTIVE:
        return "inactive"
    return "unknown"


def _getter(raw: list[str], columns: dict[str, int]) -> Callable[[str], str]:
    def get(c: str) -> str:
        i = columns.get(c)
        return raw[i].strip() if i is not None and i < len(raw) else ""

    return get


def validate(template_key: str, text: str, max_issues: int = 100) -> Validation:
    t = TEMPLATES.get(template_key)
    if t is None:
        raise ValueError(f"unknown template {template_key}")
    text = text.lstrip("﻿")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    rows = list(reader)
    issues: list[Issue] = []
    if not rows:
        return Validation(
            template=t.key,
            columns={},
            rows_total=0,
            rows_ok=0,
            rows_rejected=0,
            accepted=False,
            issues=[Issue(row=None, level="error", message="the file is empty")],
            devices=[],
        )
    header = [norm(h) for h in rows[0]]
    columns: dict[str, int] = {}
    for canon, names in ALIASES.items():
        for i, h in enumerate(header):
            if h in names and canon not in columns:
                columns[canon] = i
    missing = [c for c in t.required if c not in columns]
    if t.one_of and not any(c in columns for c in t.one_of):
        missing.append(" or ".join(t.one_of))
    if missing:
        issues.append(Issue(row=None, level="error", message=f"missing required column(s): {', '.join(missing)}"))
        return Validation(
            template=t.key,
            columns={c: rows[0][i] for c, i in columns.items()},
            rows_total=len(rows) - 1,
            rows_ok=0,
            rows_rejected=len(rows) - 1,
            accepted=False,
            issues=issues,
            devices=[],
        )

    devices: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    rejected = 0
    for n, raw in enumerate(rows[1:], start=2):  # row numbers as a spreadsheet shows them
        if not any(c.strip() for c in raw):
            continue
        get = _getter(raw, columns)
        problems = [f"empty {c}" for c in t.required if not get(c)]
        if t.one_of and not any(get(c) for c in t.one_of):
            problems.append(f"needs {' or '.join(t.one_of)}")
        last_seen = parse_date(get("last_seen")) if "last_seen" in columns else None
        if "last_seen" in t.required and get("last_seen") and last_seen is None:
            problems.append(f"last_seen '{get('last_seen')}' is not a date")
        if problems:
            rejected += 1
            if len(issues) < max_issues:
                issues.append(Issue(row=n, level="error", message="; ".join(problems)))
            continue
        key = (get("serial") or get("hostname")).upper()
        if key in seen:
            if len(issues) < max_issues:
                issues.append(Issue(row=n, level="warning", message=f"duplicate of row {seen[key]} ({key}); both kept"))
        else:
            seen[key] = n
        os_val = get("os")
        if os_val and not KNOWN_OS.search(os_val) and len(issues) < max_issues:
            issues.append(Issue(row=n, level="warning", message=f"unrecognised OS value '{os_val}'"))
        status = edr_state(get("edr_status")) if "edr_status" in columns else None
        if template_key == "rmm_inventory":
            status = edr_state(get("av_state"))
        managed = get("managed").lower() in ("yes", "true", "1", "y") if "managed" in columns and get("managed") else None
        if template_key in ("rmm_inventory", "intune_devices"):
            managed = True
        devices.append(
            {
                "hostname": get("hostname").upper() or None,
                "serial": get("serial").upper() or None,
                "mac": get("mac") or None,
                "os": os_val or None,
                "os_build": get("os_build") or None,
                "last_seen": last_seen,
                "edr_product": get("edr_product") or (None if template_key != "edr_hosts" else "EDR console"),
                "edr_status": status,
                "managed": managed,
                "site": get("site") or None,
                "attributes": {
                    c: get(c)
                    for c in ("agent_id", "agent_version", "compliance", "last_patch", "model", "role", "entra_device_id")
                    if get(c)
                },
            }
        )
    total = len([r for r in rows[1:] if any(c.strip() for c in r)])
    accepted = bool(devices) and rejected <= total * 0.2
    if not accepted and devices:
        issues.insert(
            0,
            Issue(
                row=None,
                level="error",
                message=f"{rejected} of {total} rows have errors (over 20%); fix the export and upload again",
            ),
        )
    return Validation(
        template=t.key,
        columns={c: rows[0][i] for c, i in columns.items()},
        rows_total=total,
        rows_ok=len(devices),
        rows_rejected=rejected,
        accepted=accepted,
        issues=issues,
        devices=devices,
    )


def template_csv(key: str) -> str:
    t = TEMPLATES[key]
    cols = list(t.required) + list(t.one_of) + [c for c in t.optional if c not in t.required]
    return ",".join(ALIASES[c][0].title() for c in cols) + "\n"


def edr_coverage(devices: list[dict[str, Any]]) -> dict[str, Any]:
    """Control 5: devices reconciled across sources; covered = an active EDR agent seen in any source."""
    total = len(devices)
    covered = sum(1 for d in devices if d["edr"] == "active")
    return {"devices": total, "covered": covered, "uncovered": total - covered}


def reconcile(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Match observations across sources: serial first, then hostname. Unmatched devices are kept."""
    by_serial: dict[str, dict[str, Any]] = {}
    by_host: dict[str, dict[str, Any]] = {}
    devices: list[dict[str, Any]] = []
    for o in observations:
        d = (by_serial.get(o["serial"]) if o.get("serial") else None) or (
            by_host.get(o["hostname"]) if o.get("hostname") else None
        )
        if d is None:
            d = {
                "hostname": None,
                "serial": None,
                "os": None,
                "sources": [],
                "edr": "none",
                "managed": False,
                "last_seen": None,
                "site": None,
            }
            devices.append(d)
        d["hostname"] = d["hostname"] or o.get("hostname")
        d["serial"] = d["serial"] or o.get("serial")
        d["os"] = d["os"] or o.get("os")
        d["site"] = d["site"] or o.get("site")
        if o["source"] not in d["sources"]:
            d["sources"].append(o["source"])
        if o.get("edr_status") == "active" or (d["edr"] != "active" and o.get("edr_status") == "inactive"):
            d["edr"] = o["edr_status"]
        d["managed"] = d["managed"] or bool(o.get("managed"))
        if o.get("last_seen") and (d["last_seen"] is None or o["last_seen"] > d["last_seen"]):
            d["last_seen"] = o["last_seen"]
        if d["serial"]:
            by_serial[d["serial"]] = d
        if d["hostname"]:
            by_host[d["hostname"]] = d
    for d in devices:
        d["matched"] = len(d["sources"]) > 1
    return devices


def export_date(v: str | None) -> date | None:
    if not v:
        return None
    d = parse_date(v)
    return d.date() if d else None

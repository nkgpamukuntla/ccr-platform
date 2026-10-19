"""Evaluate the stored Microsoft responses into control states (walkthrough slide 22).

Deterministic and pure: the same bundle always gives the same result. A read Microsoft did
not answer (403/404, or a licence the tenant lacks) makes the dependent control
`not_observed`: an unobserved answer never produces a met, and never an adverse result either.
"""

from typing import Any, Literal

from pydantic import BaseModel

from app.microsoft.graph import items

State = Literal["met", "gap", "weak", "not_observed", "pending"]

# Methods that leave an admin on phone-based MFA only (walkthrough: "Admin with SMS-only MFA").
PHONE_METHODS = {"mobilePhone", "alternateMobilePhone", "officePhone", "sms", "voice"}
PHISHING_RESISTANT = {
    "fido2",
    "windowsHelloForBusiness",
    "passKeyDeviceBound",
    "passKeyDeviceBoundAuthenticator",
    "passKeyDeviceBoundWindowsHello",
    "x509Certificate",
    "certificateBasedAuthentication",
}

CONTROLS = {
    1: "MFA on remote access",
    2: "MFA for third-party access",
    3: "MFA for privileged accounts",
    4: "MFA on backups",
    5: "EDR on endpoints",
    6: "Backups isolated",
    7: "DR plan",
    8: "Phishing training",
}


class ControlResult(BaseModel):
    control: int
    name: str
    state: State
    method: str
    detail: dict[str, Any]


def _reads(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["name"]: r for r in bundle.get("reads", [])}


def _status(reads: dict[str, dict[str, Any]], name: str) -> int:
    return int(reads.get(name, {}).get("status", 0))


def _requires_mfa(p: dict[str, Any]) -> bool:
    g = p.get("grantControls") or {}
    return "mfa" in (g.get("builtInControls") or []) or bool(g.get("authenticationStrength"))


def _covers_all_users(p: dict[str, Any]) -> bool:
    users = (p.get("conditions") or {}).get("users") or {}
    return "All" in (users.get("includeUsers") or [])


def _covers_all_apps(p: dict[str, Any]) -> bool:
    apps = (p.get("conditions") or {}).get("applications") or {}
    return "All" in (apps.get("includeApplications") or [])


def _excludes_guests(p: dict[str, Any]) -> bool:
    users = (p.get("conditions") or {}).get("users") or {}
    return bool(users.get("excludeGuestsOrExternalUsers")) or "GuestsOrExternalUsers" in (users.get("excludeUsers") or [])


def _includes_guests(p: dict[str, Any]) -> bool:
    users = (p.get("conditions") or {}).get("users") or {}
    return bool(users.get("includeGuestsOrExternalUsers")) or "GuestsOrExternalUsers" in (users.get("includeUsers") or [])


def evaluate(bundle: dict[str, Any]) -> list[ControlResult]:
    reads = _reads(bundle)
    sd_items = items(reads.get("security_defaults", {}))
    sd_known = _status(reads, "security_defaults") == 200
    sd_on = sd_known and bool(sd_items and sd_items[0].get("isEnabled"))
    ca_known = _status(reads, "ca_policies") == 200
    policies = items(reads.get("ca_policies", {}))
    enabled = [p for p in policies if p.get("state") == "enabled" and _requires_mfa(p)]
    report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced" and _requires_mfa(p)]
    graph_method = "Connected · Graph"

    results: list[ControlResult] = []

    # 1 MFA on remote access: all users, all cloud apps (or Security Defaults).
    c1 = [p["displayName"] for p in enabled if _covers_all_users(p) and _covers_all_apps(p)]
    if sd_on or c1:
        results.append(
            ControlResult(
                control=1,
                name=CONTROLS[1],
                state="met",
                method=graph_method + " + CA",
                detail={"security_defaults": sd_on, "policies": c1},
            )
        )
    elif not (ca_known and sd_known):
        results.append(
            ControlResult(
                control=1,
                name=CONTROLS[1],
                state="not_observed",
                method=graph_method,
                detail={
                    "reason": "Conditional Access or Security Defaults not readable",
                    "ca_status": _status(reads, "ca_policies"),
                    "sd_status": _status(reads, "security_defaults"),
                },
            )
        )
    else:
        ro = [p["displayName"] for p in report_only if _covers_all_users(p)]
        results.append(
            ControlResult(
                control=1,
                name=CONTROLS[1],
                state="weak" if ro else "gap",
                method=graph_method + " + CA",
                detail={
                    "report_only_policies": ro,
                    "note": "MFA policy is report-only, not enforced" if ro else "No enforced MFA policy for all users",
                },
            )
        )

    # 2 MFA for third parties: guests and external users covered.
    c2 = [p["displayName"] for p in enabled if (_covers_all_users(p) and not _excludes_guests(p)) or _includes_guests(p)]
    if sd_on or c2:
        results.append(
            ControlResult(
                control=2,
                name=CONTROLS[2],
                state="met",
                method=graph_method + " + CA",
                detail={"security_defaults": sd_on, "policies": c2},
            )
        )
    elif not (ca_known and sd_known):
        results.append(
            ControlResult(
                control=2,
                name=CONTROLS[2],
                state="not_observed",
                method=graph_method,
                detail={"reason": "Conditional Access or Security Defaults not readable"},
            )
        )
    else:
        results.append(
            ControlResult(
                control=2,
                name=CONTROLS[2],
                state="gap",
                method=graph_method + " + CA",
                detail={"note": "Guests and external users are not covered by an enforced MFA policy"},
            )
        )

    # 3 MFA for privileged accounts: every admin registered, none on phone-only methods.
    if _status(reads, "auth_methods_registration") != 200:
        results.append(
            ControlResult(
                control=3,
                name=CONTROLS[3],
                state="not_observed",
                method=graph_method,
                detail={
                    "reason": "Authentication-method registration report not readable (needs Entra ID P1 or P2)",
                    "status": _status(reads, "auth_methods_registration"),
                },
            )
        )
    else:
        admins = [u for u in items(reads["auth_methods_registration"]) if u.get("isAdmin")]
        unregistered = [u.get("userPrincipalName") for u in admins if not u.get("isMfaRegistered")]
        phone_only = [
            u.get("userPrincipalName")
            for u in admins
            if u.get("isMfaRegistered") and set(u.get("methodsRegistered") or []) <= PHONE_METHODS
        ]
        resistant = [u.get("userPrincipalName") for u in admins if set(u.get("methodsRegistered") or []) & PHISHING_RESISTANT]
        detail = {
            "admins": len(admins),
            "not_registered": unregistered,
            "phone_only": phone_only,
            "phishing_resistant": len(resistant),
        }
        if not admins:
            state: State = "not_observed"
        elif unregistered:
            state = "gap"
        elif phone_only:
            state = "weak"
        else:
            state = "met"
        results.append(
            ControlResult(control=3, name=CONTROLS[3], state=state, method=graph_method + " · roles × methods", detail=detail)
        )

    results.append(
        ControlResult(
            control=4,
            name=CONTROLS[4],
            state="not_observed",
            method="Conditional",
            detail={"note": "Depends on the backup product; read in a later phase"},
        )
    )
    results.append(
        ControlResult(
            control=5,
            name=CONTROLS[5],
            state="not_observed",
            method="EDR connector (phase 4)",
            detail={"note": "Needs the EDR console, an import or the collector"},
        )
    )
    for c in (6, 7, 8):
        results.append(ControlResult(control=c, name=CONTROLS[c], state="pending", method="Attested", detail={}))
    return results


def facts(bundle: dict[str, Any]) -> dict[str, Any]:
    """Context shown beside the controls: licences, devices, and what each read returned."""
    reads = _reads(bundle)
    skus = items(reads.get("subscribed_skus", {}))
    devices = items(reads.get("devices", {}))
    return {
        "licences": [
            {
                "sku": s.get("skuPartNumber"),
                "enabled": (s.get("prepaidUnits") or {}).get("enabled"),
                "consumed": s.get("consumedUnits"),
            }
            for s in skus
            if s.get("capabilityStatus") == "Enabled"
        ],
        "devices": {
            "total": len(devices),
            "managed": sum(1 for d in devices if d.get("isManaged")),
            "compliant": sum(1 for d in devices if d.get("isCompliant")),
        }
        if _status(reads, "devices") == 200
        else None,
        "reads": {name: r.get("status") for name, r in reads.items()},
    }

"""Microsoft 365 licences: what is bought, who holds it, whether it is used, and which security it pays for.

`compact` keeps what the model needs from a scan (evaluator, no internet); `model` builds the view at
request time, with the office's own prices and its device register, so a price change shows at once.
Unread sources stay "not checked": no sign-in dates means no "inactive" claims, never zero.
"""

from datetime import datetime, timedelta
from typing import Any

from app.microsoft.graph import items

INACTIVE = timedelta(days=90)

# Product names for common SKUs, and list prices in USD per user per month (annual commitment).
# Prices are a starting point only: each office enters its own contract prices.
SKUS: dict[str, tuple[str, float | None]] = {
    "O365_BUSINESS_ESSENTIALS": ("Microsoft 365 Business Basic", 6.0),
    "O365_BUSINESS_PREMIUM": ("Microsoft 365 Business Standard", 12.5),
    "SPB": ("Microsoft 365 Business Premium", 22.0),
    "STANDARDPACK": ("Office 365 E1", 10.0),
    "ENTERPRISEPACK": ("Office 365 E3", 23.0),
    "ENTERPRISEPREMIUM": ("Office 365 E5", 38.0),
    "SPE_E3": ("Microsoft 365 E3", 36.0),
    "SPE_E5": ("Microsoft 365 E5", 57.0),
    "SPE_F1": ("Microsoft 365 F3", 8.0),
    "M365_F1": ("Microsoft 365 F1", 2.25),
    "EMS": ("Enterprise Mobility + Security E3", 10.6),
    "EMSPREMIUM": ("Enterprise Mobility + Security E5", 16.4),
    "AAD_PREMIUM": ("Microsoft Entra ID P1", 6.0),
    "AAD_PREMIUM_P2": ("Microsoft Entra ID P2", 9.0),
    "INTUNE_A": ("Microsoft Intune Plan 1", 8.0),
    "DEFENDER_ENDPOINT_P1": ("Defender for Endpoint P1", 3.0),
    "WIN_DEF_ATP": ("Defender for Endpoint P2", 5.2),
    "MDATP_XPLAT": ("Defender for Endpoint P2", 5.2),
    "ATP_ENTERPRISE": ("Defender for Office 365 P1", 2.0),
    "THREAT_INTELLIGENCE": ("Defender for Office 365 P2", 5.0),
    "EXCHANGESTANDARD": ("Exchange Online Plan 1", 4.0),
    "EXCHANGEENTERPRISE": ("Exchange Online Plan 2", 8.0),
    "Microsoft_Teams_Essentials": ("Microsoft Teams Essentials", 4.0),
    "VISIOCLIENT": ("Visio Plan 2", 15.0),
    "PROJECTPROFESSIONAL": ("Project Plan 3", 30.0),
    "POWER_BI_PRO": ("Power BI Pro", 14.0),
}
# Free, trial and self-service SKUs: never counted as waste.
FREE_HINTS = ("FREE", "VIRAL", "EXPLORATORY", "TRIAL", "DEVELOPER", "STREAM", "WINDOWS_STORE", "FLOW_FREE", "POWER_BI_STANDARD")

# Security features found in the service plans of the licences, and how we tell whether each is used.
SECURITY: list[tuple[str, str, tuple[str, ...]]] = [
    ("conditional_access", "Conditional Access (Entra ID P1)", ("AAD_PREMIUM",)),
    ("identity_protection", "Risk-based sign-in protection and PIM (Entra ID P2)", ("AAD_PREMIUM_P2",)),
    ("intune", "Device management (Intune)", ("INTUNE_A",)),
    ("defender_endpoint", "Microsoft EDR: Defender for Endpoint or Defender for Business", ("MDE_LITE", "WINDEFATP", "MDE_SMB")),
    ("defender_office", "Email attack protection (Defender for Office 365)", ("ATP_ENTERPRISE", "THREAT_INTELLIGENCE")),
    ("info_protection", "Labels and encryption for documents (Purview)", ("RMS_S_PREMIUM", "RMS_S_PREMIUM2", "MIP_S_CLP1")),
    ("cloud_apps", "Shadow IT and app control (Defender for Cloud Apps)", ("ADALLOM_S_STANDALONE", "ADALLOM_S_O365")),
    ("audit_premium", "Long audit log retention (Audit Premium)", ("M365_ADVANCED_AUDITING",)),
]


def _when(s: str | None) -> datetime | None:
    if not s or s.startswith("0001-"):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def free(part: str, enabled: int) -> bool:
    return any(h in part.upper() for h in FREE_HINTS) or enabled >= 10000


def compact(reads: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """What the licence model needs from one scan."""
    skus_r, users_r = reads.get("subscribed_skus", {}), reads.get("users", {})
    if skus_r.get("status") != 200:
        return None
    skus = [
        {
            "id": s.get("skuId"),
            "part": s.get("skuPartNumber") or "",
            "enabled": int((s.get("prepaidUnits") or {}).get("enabled") or 0),
            "suspended": int((s.get("prepaidUnits") or {}).get("suspended") or 0),
            "consumed": int(s.get("consumedUnits") or 0),
            "plans": sorted(
                p.get("servicePlanName") for p in s.get("servicePlans") or [] if p.get("provisioningStatus") != "Disabled"
            ),
        }
        for s in items(skus_r)
        if s.get("capabilityStatus") in ("Enabled", "Warning")
    ]
    signins_ok = reads.get("user_signins", {}).get("status") == 200
    last = {
        u.get("id"): (u.get("signInActivity") or {}).get("lastSuccessfulSignInDateTime")
        or (u.get("signInActivity") or {}).get("lastSignInDateTime")
        for u in items(reads.get("user_signins", {}))
    }
    users = (
        [
            {
                "upn": u.get("userPrincipalName"),
                "enabled": bool(u.get("accountEnabled")),
                "guest": u.get("userType") == "Guest",
                "skus": [a.get("skuId") for a in u.get("assignedLicenses") or []],
                "created": u.get("createdDateTime"),
                "last_sign_in": last.get(u.get("id")),
            }
            for u in items(users_r)
            if u.get("assignedLicenses")
        ]
        if users_r.get("status") == 200
        else None
    )
    usage_r = reads.get("usage_30d", {})
    usage = None
    concealed = False
    if usage_r.get("status") == 200:
        usage = {}
        for row in items(usage_r):
            upn = str(row.get("userPrincipalName") or "")
            concealed = concealed or ("@" not in upn and bool(upn))
            dates = [v for k, v in row.items() if k.endswith("LastActivityDate") and v]
            usage[upn.lower()] = max(dates) if dates else None
    pols = items(reads.get("ca_policies", {}))
    on = [p for p in pols if p.get("state") == "enabled"]
    return {
        "skus": skus,
        "users": users,
        "signins_read": signins_ok,
        "usage": None if concealed else usage,
        "usage_concealed": concealed,
        "signals": {
            "ca_read": reads.get("ca_policies", {}).get("status") == 200,
            "ca_enabled": len(on),
            "ca_risk": sum(
                1
                for p in on
                if (p.get("conditions") or {}).get("userRiskLevels") or (p.get("conditions") or {}).get("signInRiskLevels")
            ),
        },
    }


def _name(part: str) -> str:
    return SKUS.get(part, (part.replace("_", " ").title(), None))[0]


def model(
    data: dict[str, Any], at: datetime, prices: dict[str, float], intune_total: int | None, edr_other: int
) -> dict[str, Any]:
    """Seats, people to review, what the security licences give and whether it is used, and the monthly cost of waste."""
    by_id = {s["id"]: s for s in data["skus"]}
    price = {s["part"]: prices.get(s["part"], SKUS.get(s["part"], ("", None))[1]) for s in data["skus"]}
    products = []
    for s in sorted(data["skus"], key=lambda x: -x["consumed"]):
        is_free = free(s["part"], s["enabled"])
        unused = 0 if is_free else max(s["enabled"] - s["consumed"], 0)
        p = price[s["part"]]
        products.append(
            {
                "part": s["part"],
                "name": _name(s["part"]),
                "bought": s["enabled"],
                "assigned": s["consumed"],
                "unassigned": unused,
                "free": is_free,
                "price": p,
                "price_source": "yours" if s["part"] in prices else "list" if p is not None else None,
                "monthly": round(p * s["enabled"], 2) if p is not None and not is_free else None,
            }
        )

    people: list[dict[str, Any]] = []
    users = data["users"]
    usage = data["usage"]
    if users is not None:
        for u in users:
            held = [by_id[x] for x in u["skus"] if x in by_id and not free(by_id[x]["part"], by_id[x]["enabled"])]
            if not held:
                continue
            reasons = []
            if not u["enabled"]:
                reasons.append("Account is disabled but still holds a licence")
            elif data["signins_read"]:
                seen = _when(u["last_sign_in"])
                made = _when(u["created"])
                if seen is None and made is not None and at - made > INACTIVE:
                    reasons.append("Has never signed in")
                elif seen is not None and at - seen > INACTIVE:
                    reasons.append(f"No sign-in for {(at - seen).days} days")
            if (
                u["enabled"]
                and usage is not None
                and not reasons
                and u["upn"]
                and u["upn"].lower() in usage
                and not usage[u["upn"].lower()]
            ):
                reasons.append("Used no Microsoft 365 app in the last 30 days")
            plans = {s["part"]: set(s["plans"]) for s in held}
            for a in held:
                for b in held:
                    if a is not b and plans[a["part"]] and plans[a["part"]] < plans[b["part"]]:
                        reasons.append(f"{_name(a['part'])} is already included in {_name(b['part'])}")
            if u["guest"]:
                reasons.append("Guest account with a paid licence")
            if reasons:
                cost = sum(price[s["part"]] or 0 for s in held)
                people.append(
                    {
                        "upn": u["upn"],
                        "licences": [_name(s["part"]) for s in held],
                        "reasons": reasons,
                        "last_sign_in": u["last_sign_in"],
                        "monthly": round(cost, 2),
                    }
                )
    people.sort(key=lambda x: -x["monthly"])

    plans_held = {p: s["part"] for s in data["skus"] if s["consumed"] for p in s["plans"]}
    sig = data["signals"]
    security = []
    for key, label, names in SECURITY:
        via = sorted({_name(plans_held[n]) for n in names if n in plans_held})
        if not via:
            continue
        if key == "conditional_access":
            used = (sig["ca_enabled"] > 0) if sig["ca_read"] else None
            note = f"{sig['ca_enabled']} policies switched on" if sig["ca_read"] else "Not checked yet"
        elif key == "identity_protection":
            used = (sig["ca_risk"] > 0) if sig["ca_read"] else None
            note = f"{sig['ca_risk']} risk-based policies on" if sig["ca_read"] else "Not checked yet"
        elif key == "intune":
            used = (intune_total > 0) if intune_total is not None else None
            note = (
                f"{intune_total} devices managed" if intune_total is not None else "Not checked yet (needs the added permission)"
            )
        elif key == "defender_endpoint":
            used = None
            note = (
                f"Included in your licences, while {edr_other} computers run another EDR: review whether you pay twice"
                if edr_other
                else "Included in your licences: check it is switched on for every computer"
            )
        else:
            used, note = None, "Included; usage not read yet"
        security.append({"key": key, "feature": label, "included_in": via, "in_use": used, "note": note})

    seats = sum(p["unassigned"] * (p["price"] or 0) for p in products)
    reviewed = sum(x["monthly"] for x in people)
    paid = [p for p in products if not p["free"]]
    return {
        "products": products,
        "people": people,
        "security": security,
        "totals": {
            "paid_licences": sum(p["bought"] for p in paid),
            "assigned": sum(p["assigned"] for p in paid),
            "unassigned": sum(p["unassigned"] for p in paid),
            "monthly_spend": round(sum(p["monthly"] or 0 for p in paid), 2),
            "unpriced": [p["name"] for p in paid if p["price"] is None],
            "monthly_unassigned": round(seats, 2),
            "monthly_review": round(reviewed, 2),
            "people_to_review": len(people),
        },
        "read": {
            "users": users is not None,
            "sign_ins": data["signins_read"],
            "usage": usage is not None,
            "usage_concealed": data["usage_concealed"],
        },
    }

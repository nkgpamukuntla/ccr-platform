"""Country frameworks: each of our checks runs once and is mapped to every framework clause it supports.

Countries are chosen per office (office.jurisdictions). A requirement is "In place" only when every
check behind it is met; one gap makes it "Needs action"; checks we could not read keep it at
"Partly checked" or "Not checked yet", never "In place". Requirements nothing in Microsoft 365
can show (Office macros, application control, plans and training) wait for the office's answer.

This shows our evidence against each framework. It is not a certification or legal advice.
"""

from typing import Any

COUNTRIES = {"US": "United States", "AU": "Australia", "SG": "Singapore"}

# What each check is, in the words the page shows.
CHECKS = {
    "c1": "MFA for all staff",
    "c2": "MFA for guests and vendors",
    "c3": "MFA for administrators",
    "c4": "MFA on backups",
    "c5": "EDR on every computer",
    "c6": "Backups kept separate",
    "c7": "Disaster recovery plan",
    "c8": "Phishing training",
    "admins": "Administrator roles kept few and time-limited",
    "legacy": "Old sign-in methods that skip MFA are blocked",
    "phish_mfa": "Phishing-resistant MFA (security keys, passkeys)",
    "logs": "Security logs sent to the people who watch them",
    "inventory": "A list of every computer",
    "supported_os": "Computers on a supported operating system",
    "compliance": "Device security rules set and met (Intune)",
    "encryption": "Computer disks encrypted",
    "email": "Email domains protected from spoofing",
}

R = tuple[str, str, list[str]]  # clause id, what it asks, checks behind it

FRAMEWORKS: list[dict[str, Any]] = [
    {
        "key": "nist_csf",
        "country": "US",
        "name": "NIST Cybersecurity Framework 2.0",
        "applies": "The common US reference, used by insurers, state agencies and auditors.",
        "requirements": [
            ("ID.AM-01", "Keep an inventory of hardware", ["inventory"]),
            ("PR.AA-03", "Users are authenticated (MFA)", ["c1", "c2", "legacy"]),
            ("PR.AA-05", "Access follows least privilege", ["c3", "admins"]),
            ("PR.AT-01", "Staff are trained to spot attacks", ["c8"]),
            ("PR.DS-01", "Stored data is protected", ["encryption"]),
            ("PR.DS-11", "Backups are made, protected and tested", ["c4", "c6"]),
            ("PR.PS-01", "Secure configuration is applied", ["compliance", "email"]),
            ("PR.PS-02", "Software is kept up to date and supported", ["supported_os"]),
            ("PR.PS-04", "Security logs are kept and used", ["logs"]),
            ("DE.CM-09", "Computers are monitored for attacks", ["c5"]),
            ("RC.RP-01", "A recovery plan exists and is used", ["c7"]),
        ],
    },
    {
        "key": "cjis",
        "country": "US",
        "name": "FBI CJIS Security Policy v6.0",
        "applies": "Only where the office reaches criminal justice information (CJI), "
        "for example court and law-enforcement systems.",
        "requirements": [
            ("IA-2(1)", "MFA for privileged accounts", ["c3"]),
            ("IA-2(2)", "MFA for all other accounts", ["c1", "legacy"]),
            ("IA-8", "MFA for outside users (vendors, guests)", ["c2"]),
            ("AC-6", "Least privilege for administrators", ["admins"]),
            ("AT-2", "Security awareness training", ["c8"]),
            ("AU-6", "Audit logs reviewed", ["logs"]),
            ("CM-8", "Inventory of system components", ["inventory"]),
            ("SC-28", "Information protected at rest", ["encryption"]),
            ("SI-2", "Flaws fixed (supported, patched systems)", ["supported_os", "compliance"]),
            ("SI-3", "Malicious code protection", ["c5"]),
            ("SI-4", "System monitoring", ["c5"]),
        ],
    },
    {
        "key": "essential_eight",
        "country": "AU",
        "name": "ASD Essential Eight",
        "applies": "The Australian Government baseline, expected by insurers and government clients. "
        "This shows evidence toward Maturity Level 1-2; a maturity rating needs an assessor.",
        "requirements": [
            ("E8-1", "Application control", []),
            ("E8-2", "Patch applications", []),
            ("E8-3", "Restrict Microsoft Office macros", []),
            ("E8-4", "User application hardening", []),
            ("E8-5", "Restrict administrative privileges", ["admins"]),
            ("E8-6", "Patch operating systems", ["supported_os", "compliance"]),
            ("E8-7", "Multi-factor authentication", ["c1", "c2", "c3", "phish_mfa"]),
            ("E8-8", "Regular backups", ["c4", "c6"]),
        ],
    },
    {
        "key": "privacy_au",
        "country": "AU",
        "name": "Privacy Act 1988 (APP 11 and data breach notification)",
        "applies": "Organisations with turnover over AUD 3 million, health providers, and Australian Government agencies.",
        "requirements": [
            ("APP 11.1", "Personal information protected from unauthorised access", ["c1", "c2", "c3", "encryption"]),
            ("APP 11.1", "Personal information protected from misuse and loss", ["c5", "supported_os", "c4", "c6"]),
            ("Part IIIC", "Ready to assess and report a data breach", ["c7", "logs"]),
        ],
    },
    {
        "key": "cyber_essentials_sg",
        "country": "SG",
        "name": "CSA Cyber Essentials mark",
        "applies": "Singapore's baseline certification for organisations, issued by the Cyber Security Agency.",
        "requirements": [
            ("A.1", "Assets: people are trained", ["c8"]),
            ("A.2", "Assets: hardware and software are listed", ["inventory"]),
            ("A.3", "Assets: data is protected", ["encryption"]),
            ("B.4", "Virus and malware protection", ["c5"]),
            ("B.5", "Access control", ["c1", "c2", "c3", "admins"]),
            ("B.6", "Secure configuration", ["legacy", "compliance", "email"]),
            ("C.7", "Software updates", ["supported_os"]),
            ("D.8", "Back up essential data", ["c4", "c6"]),
            ("E.9", "Incident response", ["c7"]),
        ],
    },
    {
        "key": "pdpa",
        "country": "SG",
        "name": "Personal Data Protection Act 2012 (PDPA)",
        "applies": "Every organisation that handles personal data in Singapore.",
        "requirements": [
            ("s24", "Protection obligation: reasonable security for personal data", ["c1", "c3", "c5", "encryption"]),
            ("Part 6A", "Ready to assess and notify a data breach", ["c7", "logs"]),
        ],
    },
]

# Incident reporting clocks. The page shows them as a reminder, not legal advice.
DEADLINES: dict[str, list[tuple[str, str]]] = {
    "US": [
        (
            "Data breach, Georgia (O.C.G.A. 10-1-912)",
            "Tell affected people in the most expedient time possible, without unreasonable delay.",
        ),
        ("Other US states", "Each state has its own breach law; many set 30 to 60 days."),
        ("CJIS incident", "Report to your state CJIS Systems Agency promptly, as your agreement sets out."),
    ],
    "AU": [
        (
            "Notifiable data breach (Privacy Act)",
            "Assess a suspected breach within 30 days; notify the OAIC and affected people as soon as practicable.",
        ),
        (
            "Ransomware payment (Cyber Security Act 2024)",
            "Report to ASD within 72 hours of paying (businesses over AUD 3 million turnover).",
        ),
        ("Cyber incident", "Report to ASD through ReportCyber."),
    ],
    "SG": [
        (
            "Data breach (PDPA)",
            "Assess within 30 days of becoming aware; notify the PDPC within 3 calendar days once it is notifiable.",
        ),
        ("Critical information infrastructure", "Owners report to CSA within 2 hours of becoming aware."),
    ],
}


def combine(states: list[str]) -> str:
    if not states:
        return "pending"
    if "gap" in states:
        return "gap"
    if "weak" in states:
        return "weak"
    if all(s == "met" for s in states):
        return "met"
    if "met" in states:
        return "partly_checked"
    return "pending" if all(s == "pending" for s in states) else "not_observed"


def _scuba(statuses: dict[str, str], ids: list[str]) -> tuple[str, str]:
    got = {p: s for p, s in statuses.items() if any(p.startswith(i) for i in ids) and s not in ("error", "na")}
    if not got:
        return "not_observed", "Not read yet"
    fail = [p for p, s in got.items() if s == "fail"]
    warn = [p for p, s in got.items() if s == "warning"]
    ok = sum(1 for s in got.values() if s == "pass")
    state = "gap" if fail else "weak" if warn else "met"
    return state, f"{ok} of {len(got)} CISA SCuBA rules met" + (
        f" (not met: {', '.join(sorted(fail + warn))})" if fail or warn else ""
    )


def checks(
    controls: list[dict[str, Any]], facts: dict[str, Any] | None, scuba: dict[str, str], devs: list[dict[str, Any]]
) -> dict[str, dict[str, str]]:
    """Every check's state and a one-line note, from what is already stored."""
    out: dict[str, dict[str, str]] = {}
    for c in controls:
        out[f"c{c['control']}"] = {"state": c["state"], "note": c.get("summary") or ""}
    for n in range(1, 9):
        out.setdefault(f"c{n}", {"state": "not_observed", "note": "No scan yet"})
    for key, ids in (
        ("admins", ["MS.AAD.7."]),
        ("legacy", ["MS.AAD.1.1"]),
        ("phish_mfa", ["MS.AAD.3.1"]),
        ("logs", ["MS.AAD.4.1"]),
    ):
        st, note = _scuba(scuba, ids)
        out[key] = {"state": st, "note": note}

    fx = facts or {}
    it = fx.get("intune")
    entra = fx.get("devices")
    if devs:
        out["inventory"] = {"state": "met", "note": f"{len(devs)} computers in the device register"}
    elif it and it["total"]:
        out["inventory"] = {"state": "met", "note": f"{it['total']} devices managed in Intune"}
    elif entra:
        out["inventory"] = {
            "state": "weak",
            "note": "Only Entra ID records, which include phones and old entries; import the EDR list",
        }
    else:
        out["inventory"] = {"state": "not_observed", "note": "No device list yet"}

    win10 = sum(1 for d in devs if "windows 10" in (d.get("os") or "").lower()) if devs else (it["windows10"] if it else None)
    if win10 is None:
        out["supported_os"] = {"state": "not_observed", "note": "No device list yet"}
    else:
        out["supported_os"] = {
            "state": "gap" if win10 else "met",
            "note": f"{win10} on Windows 10 (out of support)" if win10 else "None on Windows 10",
        }

    if not it:
        out["compliance"] = {"state": "not_observed", "note": "Intune not read (needs the added permission or an Intune licence)"}
        out["encryption"] = {"state": "not_observed", "note": "Intune not read (needs the added permission or an Intune licence)"}
    else:
        if it["policies"] == 0:
            out["compliance"] = {"state": "gap", "note": "No Intune compliance rules set"}
        elif it["noncompliant"]:
            out["compliance"] = {"state": "weak", "note": f"{it['noncompliant']} of {it['total']} devices fail the rules"}
        elif it["policies"] is None:
            out["compliance"] = {"state": "not_observed", "note": "Compliance rules not read"}
        else:
            out["compliance"] = {"state": "met", "note": f"All {it['total']} devices meet the rules"}
        if not it["computers"]:
            out["encryption"] = {"state": "not_observed", "note": "No computers in Intune"}
        else:
            out["encryption"] = {
                "state": "gap" if it["unencrypted"] else "met",
                "note": f"{it['encrypted']} of {it['computers']} computers encrypted",
            }

    em = fx.get("email")
    if not em:
        out["email"] = {"state": "not_observed", "note": "Domains not read yet"}
    else:
        safe = len(em["domains"]) - len(em["unsafe"]) - len(em["loose"])
        out["email"] = {"state": em["state"], "note": f"{safe} of {len(em['domains'])} domains reject fake email"}
    return out


def assess(jurisdictions: list[str], found: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    out = []
    for fw in FRAMEWORKS:
        if fw["country"] not in jurisdictions:
            continue
        reqs = []
        for clause, asks, keys in fw["requirements"]:
            evidence = [{"key": k, "label": CHECKS[k], **found[k]} for k in keys]
            state = combine([e["state"] for e in evidence])
            reqs.append({"clause": clause, "asks": asks, "state": state, "evidence": evidence})
        counts: dict[str, int] = {}
        for r in reqs:
            counts[r["state"]] = counts.get(r["state"], 0) + 1
        out.append({**{k: fw[k] for k in ("key", "country", "name", "applies")}, "counts": counts, "requirements": reqs})
    return out

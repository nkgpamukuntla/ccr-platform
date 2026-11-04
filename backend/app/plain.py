"""Plain-language wording for findings, written for a non-technical reader.

Each entry: title (what is wrong, in everyday words), why (why it matters), fix (what to ask
IT to do). The official wording (SCuBA policy text, control detail) stays with the finding as
`technical`, shown only on request. Recommendations name outcomes, never products.
"""

from typing import Any

# CISA SCuBA Entra ID (AAD) baseline v1.8.0, policy by policy.
SCUBA: dict[str, tuple[str, str, str]] = {
    "MS.AAD.1.1v1": (
        "Old sign-in methods that skip MFA are still allowed",
        "Older email apps and protocols can sign in with just a password, so a stolen password is enough to get in.",
        "Block legacy (basic) authentication for everyone.",
    ),
    "MS.AAD.2.1v1": (
        "Accounts Microsoft flags as high risk are not blocked",
        "When Microsoft believes an account is compromised, it can still be used until someone notices.",
        "Block sign-ins from users Microsoft rates as high risk until they are checked.",
    ),
    "MS.AAD.2.2v1": (
        "Nobody is alerted when an account is flagged as high risk",
        "A compromised account can go unnoticed for days.",
        "Send an alert to the IT administrators when a high-risk user is detected.",
    ),
    "MS.AAD.2.3v1": (
        "Risky sign-ins are not blocked",
        "Sign-ins that look like an attacker (unusual place, known bad address) are let through.",
        "Block sign-ins that Microsoft rates as high risk.",
    ),
    "MS.AAD.3.1v1": (
        "Staff are not required to use the strongest type of MFA",
        "Text-message and app-approval codes can be tricked out of people by fake login pages; security keys and Windows Hello cannot.",
        "Plan a move to phishing-resistant MFA (security keys, Windows Hello or passkeys), starting with the most exposed staff.",
    ),
    "MS.AAD.3.2v1": (
        "Not every user has to pass a second check (MFA) when signing in",
        "Without MFA, a single stolen or guessed password gives full access to email and files.",
        "Turn on a sign-in policy that requires MFA for all users.",
    ),
    "MS.AAD.3.3v2": (
        "The Authenticator app does not show where a sign-in request comes from",
        "Without the app name and location on screen, people approve attacker requests by mistake.",
        "Turn on 'show application name' and 'show location' in Microsoft Authenticator.",
    ),
    "MS.AAD.3.4v1": (
        "MFA settings are still split between the old and new admin pages",
        "Old and new settings can contradict each other, leaving weaker methods switched on.",
        "Finish Microsoft's authentication-methods migration (set it to Migration Complete).",
    ),
    "MS.AAD.3.5v1": (
        "Weak MFA methods (text message, phone call, email code) are still allowed",
        "These codes can be intercepted or talked out of people.",
        "Switch off SMS, voice call and email one-time codes once staff have a stronger method.",
    ),
    "MS.AAD.3.6v1": (
        "Administrators are not required to use the strongest type of MFA",
        "Admin accounts control everything; a tricked admin approval means a full takeover.",
        "Require phishing-resistant MFA (security key, Windows Hello or passkey) for all administrator roles.",
    ),
    "MS.AAD.3.7v1": (
        "Sign-ins are allowed from any device, including unmanaged ones",
        "Company data can be opened on personal or unprotected computers.",
        "Require a company-managed device to sign in, at least for sensitive apps.",
    ),
    "MS.AAD.3.8v1": (
        "MFA can be set up from any device",
        "An attacker with a password can register their own phone as the user's second check.",
        "Allow MFA registration only from company-managed devices or trusted locations.",
    ),
    "MS.AAD.3.9v1": (
        "The 'enter a code on another device' sign-in is allowed",
        "This sign-in style is a common phishing trick to take over accounts.",
        "Block device-code sign-in except where it is genuinely needed.",
    ),
    "MS.AAD.4.1v1": (
        "Sign-in and audit logs are not sent to a security monitoring service",
        "Attacks are only noticed if someone is watching the logs.",
        "Send Entra ID logs to your security monitoring (SOC or SIEM).",
    ),
    "MS.AAD.5.1v1": (
        "Any user can register new applications",
        "Users can create apps that read company data without IT knowing.",
        "Allow only administrators to register applications.",
    ),
    "MS.AAD.5.2v1": (
        "Any user can give outside apps access to company data",
        "A fake app can trick a user into granting access to their mailbox and files.",
        "Allow only administrators to approve app access.",
    ),
    "MS.AAD.5.3v1": (
        "There is no way for users to request app approval from IT",
        "Without a request process, people look for workarounds.",
        "Turn on the admin consent request workflow so users can ask and IT can approve.",
    ),
    "MS.AAD.6.1v1": (
        "Passwords are set to expire",
        "Forced changes lead to weaker, predictable passwords; current guidance is to stop expiring them when MFA is on.",
        "Set passwords to never expire (with MFA in place).",
    ),
    "MS.AAD.7.1v1": (
        "The number of top-level (Global) administrators is outside the safe range",
        "Too many Global Admins means more accounts that can take over everything; fewer than two risks being locked out.",
        "Keep between two and eight Global Administrators.",
    ),
    "MS.AAD.7.2v1": (
        "Admins use the all-powerful Global Administrator role for everyday work",
        "Most admin tasks need far less power; every extra Global Admin widens the damage of one stolen account.",
        "Give admins the narrower role their job needs (e.g. User or Exchange Administrator).",
    ),
    "MS.AAD.7.3v1": (
        "Administrator accounts are synced from the office network",
        "If the office network is breached, the attacker also gets the cloud admin accounts.",
        "Use separate cloud-only accounts for administrator roles.",
    ),
    "MS.AAD.7.4v1": (
        "Administrators hold their powerful roles permanently",
        "A permanently active admin account is always a valuable target.",
        "Make admin roles 'eligible' and activated only when needed, for a limited time.",
    ),
    "MS.AAD.7.5v1": (
        "Admin roles are handed out directly instead of through an approval system",
        "Roles granted outside a controlled process are easy to forget and hard to audit.",
        "Grant admin roles only through Privileged Identity Management (or a similar access system).",
    ),
    "MS.AAD.7.6v1": (
        "Turning on Global Administrator rights needs no approval",
        "One person, or an attacker with their account, can give themselves full control.",
        "Require a second person's approval to activate the Global Administrator role.",
    ),
    "MS.AAD.7.7v1": (
        "Nobody is alerted when someone is given admin rights",
        "An attacker who makes themselves admin would go unnoticed.",
        "Send an alert whenever a powerful admin role is assigned.",
    ),
    "MS.AAD.7.8v1": (
        "Nobody is alerted when Global Administrator rights are switched on",
        "Use of the most powerful role should always be visible to the team.",
        "Send an alert whenever someone activates the Global Administrator role.",
    ),
    "MS.AAD.7.9v1": (
        "Nobody is alerted when other admin roles are switched on",
        "Admin activity outside normal patterns can signal an attack.",
        "Send an alert when other powerful admin roles are activated.",
    ),
    "MS.AAD.8.1v1": (
        "Guest users can see too much of the company directory",
        "Outside guests can list staff, groups and structure, which helps targeted phishing.",
        "Restrict what guest users can see in the directory.",
    ),
    "MS.AAD.8.2v1": (
        "Anyone can invite outside guests",
        "Outsiders can be given access without IT knowing.",
        "Allow only people with the Guest Inviter role (or admins) to invite guests.",
    ),
    "MS.AAD.8.3v1": (
        "Guests can be invited from any outside organisation",
        "Access can be shared with unknown or personal email domains.",
        "Allow guest invitations only from approved partner domains.",
    ),
}

CONTROL: dict[tuple[int, str], tuple[str, str]] = {
    (1, "gap"): (
        "Staff can sign in from outside the office without a second check (MFA)",
        "Remote access with just a password is the most common way attackers get in.",
    ),
    (1, "weak"): (
        "MFA for remote sign-in is only being tested, not enforced",
        "A policy in report-only mode logs what would happen but does not stop anyone.",
    ),
    (2, "gap"): (
        "Outside users (guests, vendors, IT providers) are not required to use MFA",
        "Third-party accounts are a frequent way into an organisation.",
    ),
    (2, "weak"): (
        "MFA for outside users is only being tested, not enforced",
        "A policy in report-only mode does not stop anyone.",
    ),
    (3, "gap"): (
        "Administrator accounts are not all protected with MFA",
        "An administrator account without MFA can be taken over with one password.",
    ),
    (3, "weak"): (
        "Some administrators only use a text message or phone call as their second check",
        "Phone codes can be intercepted or tricked out of people; admin accounts need stronger protection.",
    ),
    (4, "gap"): (
        "Backup systems do not require MFA",
        "Attackers delete backups first so a ransom has to be paid.",
    ),
}

DEVICE: dict[str, str] = {
    "device:edr_missing": "Without EDR, malware and attackers on that computer go undetected.",
    "device:edr_stale": "A sensor that has stopped reporting gives no protection or alerts.",
    "device:windows10": "Windows 10 no longer receives security fixes, so known holes stay open.",
    "intune:unencrypted": "If an unencrypted laptop is lost or stolen, anyone can read the files on it.",
    "intune:noncompliant": "These devices fail the security rules you set in Intune, so they may be missing protection.",
    "intune:stale": "A device that has not checked in for a month gets no new policies and may be lost or retired.",
    "email:spoofable": "Without SPF and DMARC anyone can send email that appears to come from you, the most common start of fraud.",
    "email:dmarc_monitor": "DMARC is only watching: fake email using your name is still delivered to inboxes.",
}

SEVERITY = {"Mandatory": "Must fix", "High": "Important", "Medium": "Good practice"}


def scuba(policy_id: str) -> tuple[str, str, str] | None:
    return SCUBA.get(policy_id)


def control(c: int, state: str) -> tuple[str, str] | None:
    return CONTROL.get((c, state))


def answer(c: dict[str, Any]) -> str:
    """One plain sentence for a control's evidence in the pack."""
    d = c.get("detail") or {}
    req = d.get("required")
    if isinstance(req, dict) and req:
        failing = [p for p, s in req.items() if s != "pass"]
        n = len(req)
        if not failing:
            return f"All {n} required Microsoft 365 checks pass."
        names = "; ".join(SCUBA[p][0] for p in failing if p in SCUBA) or ", ".join(failing)
        return f"{len(failing)} of {n} required Microsoft 365 checks fail: {names}."
    return ""


ABOUT = {
    1: "Staff signing in from outside the office must pass a second check (MFA), not just a password.",
    2: "Vendors, guests and IT providers who sign in must also use MFA.",
    3: "Administrator accounts must use MFA, ideally the phishing-resistant kind.",
    4: "Getting into the backup system must require MFA.",
    5: "Every computer must run an active EDR agent that detects attacks.",
    6: "Backups must be kept apart from the main network so ransomware cannot reach them.",
    7: "A written, tested plan exists for recovering from a major outage or attack.",
    8: "Staff get regular training on spotting phishing emails.",
}
STATE = {
    "met": "In place",
    "gap": "Needs action",
    "weak": "Partly in place",
    "not_observed": "Not checked yet",
    "pending": "Awaiting your answer",
}
NOT_YET = {
    4: "Depends on the backup product; checked in a later phase.",
    5: "Upload the EDR host export (Devices page) to check this.",
}


def summary(c: dict[str, Any]) -> str:
    """One plain sentence for what the evidence shows for a control."""
    d = c.get("detail") or {}
    if c["control"] == 5 and "devices" in d:
        return f"{d['covered']} of {d['devices']} computers have an active EDR agent."
    if c["state"] == "pending":
        return "Answered by your team in the questionnaire (coming next)."
    if c["state"] == "not_observed":
        return NOT_YET.get(c["control"], "We could not read this yet.")
    if c["state"] == "met":
        return answer(c) or "The evidence shows this is in place."
    words = control(c["control"], c["state"])
    return answer(c) or (words[0] + "." if words else "")


# Remediation groups findings into a few recommendations, each an outcome a manager can assign.
THEMES: dict[str, tuple[str, str]] = {
    "mfa": (
        "Require a second check (MFA) for everyone",
        "A stolen password alone is no longer enough to get in, for staff, guests and vendors.",
    ),
    "admins": (
        "Lock down administrator accounts",
        "Admin accounts become much harder to take over, and every use of admin rights is visible.",
    ),
    "signin": (
        "Block risky and outdated sign-ins",
        "Sign-ins that look like an attacker, and old methods that skip MFA, are stopped.",
    ),
    "devices": ("Protect every computer", "Every computer runs a working EDR agent on a supported version of Windows."),
    "backups": ("Protect the backups", "Backups cannot be reached or deleted with a stolen password."),
    "apps": ("Control apps and guest access", "Outside apps and guests cannot quietly get access to company data."),
    "monitor": ("Make sure someone sees the warning signs", "Security alerts and logs reach the people who watch for attacks."),
    "email": (
        "Stop others sending email as you",
        "Email that pretends to come from your domains is rejected before it reaches anyone.",
    ),
}
_THEME_OF = {
    "control:1": "mfa",
    "control:2": "mfa",
    "control:3": "admins",
    "control:4": "backups",
    "MS.AAD.1.1v1": "signin",
    "MS.AAD.2.1v1": "signin",
    "MS.AAD.2.2v1": "monitor",
    "MS.AAD.2.3v1": "signin",
    "MS.AAD.3.1v1": "mfa",
    "MS.AAD.3.2v1": "mfa",
    "MS.AAD.3.3v2": "mfa",
    "MS.AAD.3.4v1": "mfa",
    "MS.AAD.3.5v1": "mfa",
    "MS.AAD.3.6v1": "admins",
    "MS.AAD.3.7v1": "signin",
    "MS.AAD.3.8v1": "signin",
    "MS.AAD.3.9v1": "signin",
    "MS.AAD.4.1v1": "monitor",
    "MS.AAD.6.1v1": "mfa",
}


def theme(key: str) -> str:
    """The recommendation a finding belongs to."""
    if key.startswith(("device:", "intune:")):
        return "devices"
    if key.startswith("email:"):
        return "email"
    k = key.removeprefix("scuba:")
    if k in _THEME_OF:
        return _THEME_OF[k]
    if k.startswith(("MS.AAD.7.",)):
        return "admins"
    if k.startswith(("MS.AAD.5.", "MS.AAD.8.")):
        return "apps"
    return "monitor"


# Evidence asks each control as the question a court or insurer would.
QUESTION = {
    1: "Is MFA required when staff sign in remotely?",
    2: "Is MFA required for vendors, guests and IT providers?",
    3: "Are administrator accounts protected with MFA?",
    4: "Is MFA required to reach the backups?",
    5: "Does every computer run an active EDR agent?",
    6: "Are backups kept separate from the main network?",
    7: "Is there a tested disaster recovery plan?",
    8: "Do staff receive phishing awareness training?",
}

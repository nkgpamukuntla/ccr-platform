"""Seed and restore the lab-county scenarios in a test tenant (walkthrough slide 28).

    uv run --no-project --with msal==1.34.0 --with httpx==0.28.1 python scripts/lab_scenarios.py \
        --tenant <test tenant domain> seed-a        # snapshot, then plant lab county A's issues
    ... restore --snapshot labs/<file>.json         # put everything back

Lab county A's seeded issues: the MFA policy is report-only (not enforced), and one admin has
SMS-only MFA. The expected result after the next collection: control 1 Weak, control 2 Gap,
control 3 lists the SMS-only admin.

Test tenants only. A Global Administrator signs in through the device-code flow in their own
browser (MFA included); this script never sees a password. Every change is recorded in the
snapshot so `restore` can undo it. The lab admin account is created disabled, so it adds no
sign-in risk; its password is random and discarded.
"""

import argparse
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import msal

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_POWERSHELL_CLIENT = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft first-party public client
SCOPES = [
    "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Policy.ReadWrite.SecurityDefaults",
    "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "UserAuthenticationMethod.ReadWrite.All",
]
LAB_ADMIN = "lab-admin-sms"
LAB_ROLE_TEMPLATE = "729827e3-9c14-49f7-bb1b-9608f156bbb8"  # Helpdesk Administrator (built-in, counted as admin)
LAB_PHONE = "+1 2025550123"  # fictional number range


def sign_in(tenant: str) -> httpx.Client:
    app = msal.PublicClientApplication(GRAPH_POWERSHELL_CLIENT, authority=f"https://login.microsoftonline.com/{tenant}")
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise SystemExit(f"device flow failed: {flow.get('error_description')}")
    print(f"SIGN-IN: open {flow['verification_uri']} and enter code {flow['user_code']}", flush=True)
    r = app.acquire_token_by_device_flow(flow)
    if "access_token" not in r:
        raise SystemExit(f"sign-in failed: {r.get('error')}: {r.get('error_description')}")
    print(f"signed in as {r.get('id_token_claims', {}).get('preferred_username')}", flush=True)
    return httpx.Client(headers={"Authorization": f"Bearer {r['access_token']}"}, timeout=60)


def check(r: httpx.Response) -> Any:
    if r.status_code >= 400:
        raise SystemExit(f"{r.request.method} {r.request.url} -> {r.status_code}: {r.text[:500]}")
    return r.json() if r.content else {}


def mfa_all_users(p: dict[str, Any]) -> bool:
    g = p.get("grantControls") or {}
    users = (p.get("conditions") or {}).get("users") or {}
    apps = (p.get("conditions") or {}).get("applications") or {}
    return ("mfa" in (g.get("builtInControls") or []) or bool(g.get("authenticationStrength"))) and \
        "All" in (users.get("includeUsers") or []) and "All" in (apps.get("includeApplications") or [])


def state(http: httpx.Client) -> dict[str, Any]:
    policies = check(http.get(f"{GRAPH}/identity/conditionalAccess/policies"))["value"]
    sd = check(http.get(f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy"))
    return {"security_defaults": sd.get("isEnabled"), "policies": [
        {"id": p["id"], "displayName": p["displayName"], "state": p["state"], "mfa_all_users": mfa_all_users(p)} for p in policies]}


def show(s: dict[str, Any]) -> None:
    print(f"  Security Defaults: {'ON' if s['security_defaults'] else 'off'}")
    for p in s["policies"]:
        print(f"  CA  {p['state']:<40} {'[MFA, all users] ' if p['mfa_all_users'] else ''}{p['displayName']}")


def seed_a(http: httpx.Client, snap_dir: Path) -> None:
    org = check(http.get(f"{GRAPH}/organization?$select=id,displayName,verifiedDomains"))["value"][0]
    domain = next(d["name"] for d in org["verifiedDomains"] if d.get("isInitial"))
    before = state(http)
    print("BEFORE"); show(before)
    snap_dir.mkdir(exist_ok=True)
    snap = snap_dir / f"{domain}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    record: dict[str, Any] = {"tenant": org["id"], "domain": domain, "before": before, "changes": []}

    # 1. MFA policy report-only: no enforced MFA for all users (and Security Defaults off).
    if before["security_defaults"]:
        check(http.patch(f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy", json={"isEnabled": False}))
        record["changes"].append({"security_defaults": "off"})
    for p in before["policies"]:
        if p["mfa_all_users"] and p["state"] == "enabled":
            check(http.patch(f"{GRAPH}/identity/conditionalAccess/policies/{p['id']}", json={"state": "enabledForReportingButNotEnforced"}))
            record["changes"].append({"policy": p["id"], "from": "enabled", "to": "enabledForReportingButNotEnforced"})
    if not any(p["mfa_all_users"] for p in before["policies"]):
        r = check(http.post(f"{GRAPH}/identity/conditionalAccess/policies", json={
            "displayName": "LAB A - Require MFA for all users (report-only, seeded)",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]},
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        }))
        record["changes"].append({"created_policy": r["id"]})

    # 2. One admin on SMS-only MFA: a disabled lab account with a built-in admin role and a phone method only.
    upn = f"{LAB_ADMIN}@{domain}"
    found = check(http.get(f"{GRAPH}/users", params={"$filter": f"userPrincipalName eq '{upn}'"}))["value"]
    if found:
        user_id = found[0]["id"]
    else:
        user_id = check(http.post(f"{GRAPH}/users", json={
            "accountEnabled": False, "displayName": "LAB A admin (SMS-only MFA, seeded)", "mailNickname": LAB_ADMIN,
            "userPrincipalName": upn,
            "passwordProfile": {"forceChangePasswordNextSignIn": True, "password": secrets.token_urlsafe(24) + "aA1!"},
        }))["id"]
        record["changes"].append({"created_user": user_id, "upn": upn})
    roles = check(http.get(f"{GRAPH}/roleManagement/directory/roleAssignments",
                           params={"$filter": f"principalId eq '{user_id}'"}))["value"]
    role_def = check(http.get(f"{GRAPH}/roleManagement/directory/roleDefinitions",
                              params={"$filter": f"templateId eq '{LAB_ROLE_TEMPLATE}'"}))["value"][0]["id"]
    if not any(r["roleDefinitionId"] == role_def for r in roles):
        a = check(http.post(f"{GRAPH}/roleManagement/directory/roleAssignments",
                            json={"principalId": user_id, "roleDefinitionId": role_def, "directoryScopeId": "/"}))
        record["changes"].append({"role_assignment": a["id"]})
    phones = check(http.get(f"{GRAPH}/users/{user_id}/authentication/phoneMethods"))["value"]
    if not phones:
        check(http.post(f"{GRAPH}/users/{user_id}/authentication/phoneMethods", json={"phoneNumber": LAB_PHONE, "phoneType": "mobile"}))
        record["changes"].append({"phone_method": user_id})

    snap.write_text(json.dumps(record, indent=2))
    print("AFTER"); show(state(http))
    print(f"lab admin: {upn} (disabled, Helpdesk Administrator, SMS only)")
    print(f"SNAPSHOT: {snap}")


def restore(http: httpx.Client, snap: Path) -> None:
    record = json.loads(snap.read_text())
    for ch in reversed(record["changes"]):
        if "policy" in ch:
            check(http.patch(f"{GRAPH}/identity/conditionalAccess/policies/{ch['policy']}", json={"state": ch["from"]}))
        elif "created_policy" in ch:
            check(http.delete(f"{GRAPH}/identity/conditionalAccess/policies/{ch['created_policy']}"))
        elif ch.get("security_defaults") == "off":
            check(http.patch(f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy", json={"isEnabled": True}))
        elif "created_user" in ch:
            check(http.delete(f"{GRAPH}/users/{ch['created_user']}"))  # removes its role and methods too
    print("RESTORED"); show(state(http))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tenant", required=True)
    p.add_argument("action", choices=["show", "seed-a", "restore"])
    p.add_argument("--snapshot", type=Path)
    a = p.parse_args()
    http = sign_in(a.tenant)
    if a.action == "show":
        show(state(http))
    elif a.action == "seed-a":
        seed_a(http, Path("labs"))
    else:
        if not a.snapshot:
            raise SystemExit("--snapshot is required for restore")
        restore(http, a.snapshot)
    return 0


if __name__ == "__main__":
    sys.exit(main())

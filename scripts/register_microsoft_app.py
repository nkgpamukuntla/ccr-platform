"""Create (or update) the collector's multi-tenant app registration through Microsoft Graph.

    uv run --with msal==1.34.0 --with httpx==0.28.1 python scripts/register_microsoft_app.py \
        --tenant <home tenant domain> --name "CCR Evidence Collector (dev)" \
        --redirect-uri https://<portal>/consent/microsoft/callback --cert docs/ccr-evidence-collector-dev.cer

An administrator of the home tenant signs in through the device-code flow in their own
browser (MFA included); this script never sees a password. It configures exactly what
docs/MICROSOFT-APP-SETUP.md describes: multitenant, Web redirect URI, five Graph
*application* permissions, the KMS-signed public certificate, and no client secret.
It does not grant consent: each tenant's own administrator does that from the portal.
Idempotent: running it again updates the registration with the same name.
"""

import argparse
import base64
import json
import sys
from pathlib import Path

import httpx
import msal
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

GRAPH = "https://graph.microsoft.com/v1.0"
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft first-party public client
PERMISSIONS = ["Policy.Read.All", "RoleManagement.Read.Directory", "AuditLog.Read.All", "Device.Read.All", "LicenseAssignment.Read.All"]


def sign_in(tenant: str) -> str:
    app = msal.PublicClientApplication(AZURE_CLI_CLIENT_ID, authority=f"https://login.microsoftonline.com/{tenant}")
    flow = app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
    if "user_code" not in flow:
        raise SystemExit(f"device flow failed: {flow.get('error_description')}")
    print(f"SIGN-IN: open {flow['verification_uri']} and enter code {flow['user_code']}", flush=True)
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise SystemExit(f"sign-in failed: {result.get('error')}: {result.get('error_description')}")
    print(f"signed in as {result.get('id_token_claims', {}).get('preferred_username')}", flush=True)
    token: str = result["access_token"]
    return token


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tenant", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--redirect-uri", required=True)
    p.add_argument("--cert", required=True, type=Path)
    a = p.parse_args()

    cert = x509.load_pem_x509_certificate(a.cert.read_bytes())
    thumb = cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303 - Entra's display thumbprint

    token = sign_in(a.tenant)
    http = httpx.Client(headers={"Authorization": f"Bearer {token}"}, timeout=30)

    # Resolve permission names to Microsoft Graph app-role ids (never hard-coded).
    sp = http.get(f"{GRAPH}/servicePrincipals(appId='{MS_GRAPH_APP_ID}')", params={"$select": "appRoles"})
    sp.raise_for_status()
    roles = {r["value"]: r["id"] for r in sp.json()["appRoles"]}
    missing = [x for x in PERMISSIONS if x not in roles]
    if missing:
        raise SystemExit(f"unknown Graph application permissions: {missing}")

    body = {
        "displayName": a.name,
        "signInAudience": "AzureADMultipleOrgs",
        "web": {"redirectUris": [a.redirect_uri]},
        "requiredResourceAccess": [{
            "resourceAppId": MS_GRAPH_APP_ID,
            "resourceAccess": [{"id": roles[x], "type": "Role"} for x in PERMISSIONS],
        }],
        "keyCredentials": [{
            "type": "AsymmetricX509Cert",
            "usage": "Verify",
            "key": base64.b64encode(cert.public_bytes(Encoding.DER)).decode(),
            "displayName": f"KMS signing key ({cert.subject.rfc4514_string()})",
        }],
        "passwordCredentials": [],
    }

    existing = http.get(f"{GRAPH}/applications", params={"$filter": f"displayName eq '{a.name}'", "$select": "id,appId"}).json()["value"]
    if existing:
        app_obj = existing[0]
        r = http.patch(f"{GRAPH}/applications/{app_obj['id']}", json=body)
        r.raise_for_status()
        action = "updated"
    else:
        r = http.post(f"{GRAPH}/applications", json=body)
        r.raise_for_status()
        app_obj = r.json()
        action = "created"

    check = http.get(f"{GRAPH}/applications/{app_obj['id']}",
                     params={"$select": "appId,displayName,signInAudience,web,keyCredentials,passwordCredentials,requiredResourceAccess"}).json()
    org = http.get(f"{GRAPH}/organization", params={"$select": "id,displayName"}).json()["value"][0]
    print(json.dumps({
        "action": action,
        "application_client_id": check["appId"],
        "home_tenant_id": org["id"],
        "home_tenant": org["displayName"],
        "sign_in_audience": check["signInAudience"],
        "redirect_uris": check["web"]["redirectUris"],
        "certificates": [{"thumbprint": k.get("customKeyIdentifier"),  # Graph returns the SHA-1 thumbprint as a hex string
                          "end": k.get("endDateTime")} for k in check["keyCredentials"]],
        "expected_thumbprint": thumb,
        "client_secrets": len(check["passwordCredentials"]),
        "graph_application_permissions": len(check["requiredResourceAccess"][0]["resourceAccess"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""What the collector reads from Microsoft Graph, and how responses are recorded raw.

Each read uses the least-privileged permission its endpoint's documentation names
(handover section 7). Every response is kept as returned, including 403 and 404: what
Microsoft returns at each licensing level is itself the evidence, and an unobserved answer
withholds any adverse result that depends on it.
"""

import csv
import io
from dataclasses import dataclass
from typing import Any

import httpx

from app.scuba.aad import PERMISSIONS as _SCUBA_AAD_PERMISSIONS

GRAPH = "https://graph.microsoft.com"
MAX_PAGES = 50


@dataclass(frozen=True)
class Read:
    name: str
    path: str
    permission: str
    max_pages: int = MAX_PAGES


READS = [
    Read("ca_policies", "/v1.0/identity/conditionalAccess/policies", "Policy.Read.All"),
    Read("security_defaults", "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", "Policy.Read.All"),
    Read(
        "role_definitions",
        "/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,templateId",
        "RoleManagement.Read.Directory",
    ),
    Read("role_assignments", "/v1.0/roleManagement/directory/roleAssignments", "RoleManagement.Read.Directory"),
    Read("auth_methods_registration", "/v1.0/reports/authenticationMethods/userRegistrationDetails", "AuditLog.Read.All"),
    Read(
        "devices",
        "/v1.0/devices?$top=999&$select=id,displayName,operatingSystem,operatingSystemVersion,isCompliant,isManaged,trustType,"
        "approximateLastSignInDateTime,registrationDateTime,deviceOwnership",
        "Device.Read.All",
    ),
    Read("subscribed_skus", "/v1.0/subscribedSkus", "LicenseAssignment.Read.All"),
    Read("domains", "/v1.0/domains?$select=id,isVerified,isDefault,supportedServices", "Directory.Read.All"),
    # Intune: the real list of managed computers, their encryption and compliance (needs an Intune licence).
    Read(
        "managed_devices",
        "/v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,isEncrypted,"
        "lastSyncDateTime,managedDeviceOwnerType,serialNumber,enrolledDateTime",
        "DeviceManagementManagedDevices.Read.All",
    ),
    Read(
        "compliance_policies",
        "/v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName,lastModifiedDateTime",
        "DeviceManagementConfiguration.Read.All",
    ),
    # Microsoft Secure Score: the newest daily score only, and the actions it is made of.
    Read("secure_scores", "/v1.0/security/secureScores?$top=1", "SecurityEvents.Read.All", max_pages=1),
    Read("secure_score_profiles", "/v1.0/security/secureScoreControlProfiles", "SecurityEvents.Read.All"),
    # Licences: who holds what, whether they still sign in, and which Microsoft 365 apps they use.
    Read(
        "users",
        "/v1.0/users?$top=999&$select=id,userPrincipalName,accountEnabled,userType,assignedLicenses,createdDateTime",
        "User.Read.All",
    ),
    # Sign-in dates need Entra ID P1/P2; a tenant without them answers 403 and activity reads "not checked".
    Read(
        "user_signins", "/v1.0/users?$top=120&$select=id,signInActivity", "AuditLog.Read.All", max_pages=200
    ),  # 120 is the most per page
    Read(
        "usage_30d",
        "/v1.0/reports/getOffice365ActiveUserDetail(period='D30')",  # answers with a redirect to a CSV
        "Reports.Read.All",
    ),
]

# Our reads plus what ScubaGear's Entra collection needs (app/scuba/aad.py); all read-only.
PERMISSIONS = sorted({r.permission for r in READS} | set(_SCUBA_AAD_PERMISSIONS))
KEEP_HEADERS = ("request-id", "client-request-id", "date", "x-ms-ags-diagnostic")


def fetch(http: httpx.Client, token: str, read: Read) -> dict[str, Any]:
    """Follows @odata.nextLink. Returns {status, pages:[...], headers} exactly as Microsoft answered."""
    url: str | None = GRAPH + read.path
    pages: list[Any] = []
    status = 0
    headers: dict[str, str] = {}
    while url and len(pages) < read.max_pages:
        r = http.get(url, headers={"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}, timeout=60)
        if r.status_code == 302 and r.headers.get("location", "").startswith("https://"):
            # Usage reports hand back a short-lived, pre-signed CSV link; it needs no token.
            r = http.get(r.headers["location"], timeout=60)
        status = r.status_code
        headers = {k: v for k, v in r.headers.items() if k.lower() in KEEP_HEADERS}
        try:
            body = r.json()
        except ValueError:
            body = csv_rows(r.text) if status == 200 else {"_non_json": r.text[:2000]}
        pages.append(body)
        url = body.get("@odata.nextLink") if status == 200 and isinstance(body, dict) else None
    return {
        "name": read.name,
        "path": read.path,
        "permission": read.permission,
        "status": status,
        "headers": headers,
        "pages": pages,
    }


def csv_rows(text: str) -> dict[str, Any]:
    """A report CSV as {"value": [...]}, headers in Graph's JSON style ("User Principal Name" -> userPrincipalName)."""

    def key(h: str) -> str:
        words = h.replace("\ufeff", "").strip().split()
        return (words[0].lower() + "".join(w[:1].upper() + w[1:] for w in words[1:])) if words else h

    rows = list(csv.DictReader(io.StringIO(text.lstrip("\ufeff"))))
    return {"value": [{key(k): v for k, v in row.items() if k} for row in rows]}


def items(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """All `value` items across pages of a successful read (or the single object)."""
    if entry.get("status") != 200:
        return []
    out: list[dict[str, Any]] = []
    for page in entry["pages"]:
        if isinstance(page, dict) and isinstance(page.get("value"), list):
            out += page["value"]
        elif isinstance(page, dict):
            out.append(page)
    return out

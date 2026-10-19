"""What the collector reads from Microsoft Graph, and how responses are recorded raw.

Each read uses the least-privileged permission its endpoint's documentation names
(handover section 7). Every response is kept as returned, including 403 and 404: what
Microsoft returns at each licensing level is itself the evidence, and an unobserved answer
withholds any adverse result that depends on it.
"""

from dataclasses import dataclass
from typing import Any

import httpx

GRAPH = "https://graph.microsoft.com"
MAX_PAGES = 50


@dataclass(frozen=True)
class Read:
    name: str
    path: str
    permission: str


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
        "/v1.0/devices?$select=id,displayName,operatingSystem,operatingSystemVersion,isCompliant,isManaged,trustType,approximateLastSignInDateTime",
        "Device.Read.All",
    ),
    Read("subscribed_skus", "/v1.0/subscribedSkus", "LicenseAssignment.Read.All"),
]

PERMISSIONS = sorted({r.permission for r in READS})
KEEP_HEADERS = ("request-id", "client-request-id", "date", "x-ms-ags-diagnostic")


def fetch(http: httpx.Client, token: str, read: Read) -> dict[str, Any]:
    """Follows @odata.nextLink. Returns {status, pages:[...], headers} exactly as Microsoft answered."""
    url: str | None = GRAPH + read.path
    pages: list[Any] = []
    status = 0
    headers: dict[str, str] = {}
    while url and len(pages) < MAX_PAGES:
        r = http.get(url, headers={"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}, timeout=60)
        status = r.status_code
        headers = {k: v for k, v in r.headers.items() if k.lower() in KEEP_HEADERS}
        try:
            body = r.json()
        except ValueError:
            body = {"_non_json": r.text[:2000]}
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

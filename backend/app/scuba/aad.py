"""ScubaGear's Entra ID (AAD) provider, ported so the SCuBA rules can score our own collection.

Mirrors ScubaGear v1.8.0 `Export-AADProvider` (PowerShell/ScubaGear/Modules/Providers/
ExportAADProvider.psm1) for every input the v1.8.0 `AADConfig.rego` reads:
conditional_access_policies, authorization_policies, privileged_users, privileged_roles,
service_plans, directory_settings, authentication_method, domain_settings.

One code path serves both sides of the fence:
- the worker runs `build_provider(LiveGraph(...))`, which makes the Graph calls and records
  every response;
- the evaluator (no internet) runs `build_provider(RecordedGraph(responses))` on the sealed
  bundle and gets the identical input for OPA.

ScubaGear calls Graph directly and converts each response with ConvertFrom-GraphHashtable,
which upper-cases the first letter of every key recursively; `pascal()` does the same. Each
top-level call is wrapped like ScubaGear's CommandTracker.TryCommand: a failure yields an empty
result and is listed in aad_unsuccessful_commands, so the affected policies can be shown as not
observed instead of failed.
"""

from collections.abc import Callable
from typing import Any

GRAPH = "https://graph.microsoft.com"

# ScubaConfigDefaults.json "privilegedRoles" (v1.8.0).
PRIVILEGED_ROLES = [
    "Global Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "SharePoint Administrator",
    "Exchange Administrator",
    "Hybrid Identity Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
]

# ScubaGearPermissions.json apiResource per cmdlet (commercial). {id} is substituted.
PATHS = {
    "Get-MgBetaIdentityConditionalAccessPolicy": "/beta/identity/conditionalAccess/policies",
    "Get-MgBetaSubscribedSku": "/beta/subscribedSkus",
    "Get-MgBetaDirectoryRole": "/beta/directoryRoles",
    "Get-MgBetaDirectoryRoleMember": "/beta/directoryRoles/{id}/members",
    "Get-MgBetaUser": "/beta/users/{id}",
    "Get-MgBetaServicePrincipal": "/beta/servicePrincipals/{id}",
    "Get-MgBetaGroupMember": "/beta/groups/{id}/members",
    "Get-MgBetaDirectoryObject": "/beta/directoryObjects/{id}",
    "Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance": "/beta/roleManagement/directory/roleEligibilityScheduleInstances",
    "Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance": "/beta/roleManagement/directory/roleAssignmentScheduleInstances",
    "Get-MgBetaDirectoryRoleTemplate": "/beta/directoryRoleTemplates",
    "Get-MgBetaPolicyRoleManagementPolicyAssignment": "/beta/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'",
    "Get-MgBetaPolicyRoleManagementPolicyRule": "/beta/policies/roleManagementPolicies/{id}/rules",
    "Get-MgBetaIdentityGovernancePrivilegedAccessGroup": "/beta/identityGovernance/privilegedAccess/group/resources",
    "Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance": "/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances/?$filter=groupId eq '{id}'",
    "Get-MgBetaUserCount": "/beta/users/$count",
    "Get-MgBetaPolicyAuthorizationPolicy": "/beta/policies/authorizationPolicy",
    "Get-MgBetaDirectorySetting": "/beta/settings",
    "Get-MgBetaPolicyAuthenticationMethodPolicy": "/beta/policies/authenticationMethodsPolicy",
    "Get-MgBetaDomain": "/beta/domains",
    # PIM-for-groups batch calls in GetConfigurationsForPimGroups, made as plain GETs here.
    "GroupDisplayName": "/beta/groups/{id}?$select=displayName",
    "PimGroupPolicyAssignment": "/beta/policies/roleManagementPolicyAssignments?$filter=scopeId eq '{id}' and scopeType eq 'Group' and roleDefinitionId eq 'member'",
}

# Microsoft Graph application permissions the provider needs (all read-only); the docs list
# for ScubaGear's Entra product, used here with our own certificate held in KMS.
PERMISSIONS = [
    "Directory.Read.All",
    "Policy.Read.All",
    "PrivilegedAccess.Read.AzureADGroup",
    "PrivilegedEligibilitySchedule.Read.AzureADGroup",
    "RoleManagement.Read.Directory",
    "RoleManagementPolicy.Read.AzureADGroup",
    "User.Read.All",
]


class GraphError(Exception):
    def __init__(self, path: str, status: int, body: Any) -> None:
        super().__init__(f"{status} on {path}")
        self.path, self.status, self.body = path, status, body


Get = Callable[[str], Any]  # path -> parsed JSON body (pages merged into "value"); raises GraphError


def pascal(data: Any) -> Any:
    """ConvertFrom-GraphHashtable: first letter of every key upper-cased, recursively."""
    if isinstance(data, dict):
        return {(k[:1].upper() + k[1:]) if k else k: pascal(v) for k, v in data.items()}
    if isinstance(data, list):
        return [pascal(x) for x in data]
    return data


def path(cmdlet: str, id_: str = "") -> str:
    return PATHS[cmdlet].replace("{id}", id_)


class Tracker:
    """CommandTracker: records which top-level commands succeeded or failed."""

    def __init__(self) -> None:
        self.ok: list[str] = []
        self.failed: list[str] = []

    def run(self, name: str, fn: Callable[[], Any], empty: Any) -> Any:
        try:
            out = fn()
        except GraphError:
            self.failed.append(name)
            return empty
        self.ok.append(name)
        return out


def _odata_type(obj: dict[str, Any]) -> str:
    return str(obj.get("@odata.type", "")).replace("#microsoft.graph.", "")


def _load_object(
    get: Get, users: dict[str, Any], role: str, object_id: str, premium: bool, kind: str = "", depth: int = 0
) -> None:
    """LoadObjectDataIntoPrivilegedUserHashtable."""
    if depth >= 2:
        return
    if not kind:
        try:
            kind = _odata_type(get(path("Get-MgBetaDirectoryObject", object_id)))
        except GraphError as e:
            if e.status == 404:  # recently deleted: ScubaGear ignores it
                return
            raise
    kind = kind.lower()
    if kind == "user":
        if object_id not in users:
            u = get(path("Get-MgBetaUser", object_id))
            users[object_id] = {
                "DisplayName": u.get("displayName"),
                "OnPremisesImmutableId": u.get("onPremisesImmutableId"),
                "roles": [],
            }
        if role not in users[object_id]["roles"]:
            users[object_id]["roles"].append(role)
    elif kind == "serviceprincipal":
        if object_id not in users:
            sp = get(path("Get-MgBetaServicePrincipal", object_id))
            users[object_id] = {
                "DisplayName": sp.get("displayName"),
                "ServicePrincipalId": sp.get("id"),
                "AppId": sp.get("appId"),
                "roles": [],
            }
        if role not in users[object_id]["roles"]:
            users[object_id]["roles"].append(role)
    elif kind == "group":
        for m in get(path("Get-MgBetaGroupMember", object_id)).get("value", []):
            mtype = _odata_type(m).lower()
            if mtype in ("user", "serviceprincipal"):
                _load_object(get, users, role, m["id"], premium, mtype, depth)
        if premium:
            pim = get(path("Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance", object_id)).get(
                "value", []
            )
            for m in pim:
                if m.get("accessId") != "member":
                    continue
                _load_object(get, users, role, m["principalId"], premium, "", depth + 1)


def privileged_objects(get: Get, premium: bool) -> dict[str, Any]:
    """Get-PrivilegedUser: users and service principals in the privileged roles (active + PIM eligible)."""
    users: dict[str, Any] = {}
    roles = [r for r in get(path("Get-MgBetaDirectoryRole")).get("value", []) if r.get("displayName") in PRIVILEGED_ROLES]
    for r in roles:
        for m in get(path("Get-MgBetaDirectoryRoleMember", r["id"])).get("value", []):
            _load_object(get, users, r["displayName"], m["id"], premium, _odata_type(m).lower())
    if premium:
        eligible = get(path("Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance")).get("value", [])
        for r in roles:
            for a in [a for a in eligible if a.get("roleDefinitionId") == r.get("roleTemplateId")]:
                _load_object(get, users, r["displayName"], a["principalId"], premium)
    return users


def _with_source(rules: list[dict[str, Any]], source: str, source_type: str) -> list[dict[str, Any]]:
    return [{**r, "RuleSource": source, "RuleSourceType": source_type} for r in rules]


def privileged_roles(get: Get, premium: bool) -> list[dict[str, Any]]:
    """Get-PrivilegedRole: the privileged role templates, with PIM rules and assignments when licensed."""
    templates = pascal(get(path("Get-MgBetaDirectoryRoleTemplate"))).get("Value", [])
    roles: list[dict[str, Any]] = [
        {"DisplayName": t["DisplayName"], "RoleTemplateId": t["Id"]}
        for t in templates
        if t.get("DisplayName") in PRIVILEGED_ROLES
    ]
    if not premium:
        return roles
    active = pascal(get(path("Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance"))).get("Value", [])
    eligible = pascal(get(path("Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance"))).get("Value", [])

    # GetConfigurationsForRoles
    policy_assignments = pascal(get(path("Get-MgBetaPolicyRoleManagementPolicyAssignment"))).get("Value", [])
    for role in roles:
        pa: dict[str, Any] | None = next(
            (p for p in policy_assignments if p.get("RoleDefinitionId") == role["RoleTemplateId"]), None
        )
        rules = pascal(get(path("Get-MgBetaPolicyRoleManagementPolicyRule", pa["PolicyId"]))).get("Value", []) if pa else []
        role["Assignments"] = [a for a in active if a.get("RoleDefinitionId") == role["RoleTemplateId"]]
        role["Rules"] = role.get("Rules", []) + _with_source(rules, role["DisplayName"], "Directory Role")

    # GetConfigurationsForPimGroups (active + eligible assignments)
    all_assignments = active + eligible
    groups = pascal(get(path("Get-MgBetaIdentityGovernancePrivilegedAccessGroup"))).get("Value", [])
    for g in groups:
        name = get(path("GroupDisplayName", g["Id"])).get("displayName")
        assignment = get(path("PimGroupPolicyAssignment", g["Id"])).get("value", [])
        policy_id = assignment[0]["policyId"] if assignment else None
        rules = pascal(get(path("Get-MgBetaPolicyRoleManagementPolicyRule", policy_id))).get("Value", []) if policy_id else []
        rules = _with_source(rules, name, "PIM Group")
        for a in [a for a in all_assignments if a.get("PrincipalId") == g["Id"]]:
            target: dict[str, Any] | None = next((r for r in roles if r["RoleTemplateId"] == a.get("RoleDefinitionId")), None)
            if target is not None:
                target["Rules"] = target.get("Rules", []) + rules
    return roles


def build_provider(get: Get) -> dict[str, Any]:
    """Export-AADProvider: the AAD part of ScubaGear's ProviderSettingsExport.json."""
    t = Tracker()
    policies = t.run(
        "Get-MgBetaIdentityConditionalAccessPolicy",
        lambda: pascal(get(path("Get-MgBetaIdentityConditionalAccessPolicy"))).get("Value", []),
        [],
    )
    skus = t.run("Get-MgBetaSubscribedSku", lambda: pascal(get(path("Get-MgBetaSubscribedSku"))).get("Value", []), [])
    service_plans = [sp for s in skus for sp in (s.get("ServicePlans") or []) if sp.get("ProvisioningStatus") == "Success"]

    privileged_users: dict[str, Any] = {}
    privileged_sps: dict[str, Any] = {}
    roles: list[dict[str, Any]] = []
    if service_plans:
        premium = any(sp.get("ServicePlanName") == "AAD_PREMIUM_P2" for sp in service_plans)
        objs = t.run("Get-PrivilegedUser", lambda: privileged_objects(get, premium), {})
        for k, v in objs.items():
            (privileged_sps if v.get("ServicePrincipalId") is not None else privileged_users)[k] = v
        roles = t.run("Get-PrivilegedRole", lambda: privileged_roles(get, premium), [])
    else:
        t.failed += ["Get-PrivilegedRole", "Get-PrivilegedUser"]

    count = t.run("Get-MgBetaUserCount", lambda: get(path("Get-MgBetaUserCount")), -1)
    authz = t.run("Get-MgBetaPolicyAuthorizationPolicy", lambda: pascal(get(path("Get-MgBetaPolicyAuthorizationPolicy"))), None)
    settings = t.run("Get-MgBetaDirectorySetting", lambda: pascal(get(path("Get-MgBetaDirectorySetting"))).get("Value", []), [])
    amp = t.run(
        "Get-MgBetaPolicyAuthenticationMethodPolicy",
        lambda: pascal(get(path("Get-MgBetaPolicyAuthenticationMethodPolicy"))),
        None,
    )
    domains = t.run("Get-MgBetaDomain", lambda: pascal(get(path("Get-MgBetaDomain"))).get("Value", []), [])

    auth_method: list[dict[str, Any]] = []
    if amp is not None:
        features = [c for c in (amp.get("AuthenticationMethodConfigurations") or []) if c.get("Id")]
        root = {k: v for k, v in amp.items() if k != "AuthenticationMethodConfigurations"}
        auth_method = [{"authentication_method_policy": root, "authentication_method_feature_settings": features}]

    return {
        "conditional_access_policies": policies,
        "authorization_policies": [authz] if authz is not None else [],
        "privileged_users": privileged_users,
        "privileged_service_principals": privileged_sps,
        "privileged_roles": roles,
        "service_plans": service_plans,
        "directory_settings": settings,
        "authentication_method": auth_method,
        "domain_settings": domains,
        "license_information": [
            {k: v for k, v in s.items() if k.startswith("Sku") or k in ("ConsumedUnits", "PrepaidUnits")} for s in skus
        ],
        "total_user_count": count if isinstance(count, int) else -1,
        "aad_successful_commands": t.ok,
        "aad_unsuccessful_commands": t.failed,
    }


def opa_input(provider: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """The document ScubaGear hands to OPA: provider output plus the run's metadata and config."""
    return {
        "baseline_version": "1",
        "module_version": "1.8.0",
        "tenant_details": [{"TenantId": tenant_id}],
        "scuba_config": {"M365Environment": "commercial", "ProductNames": ["aad"]},
        **provider,
    }


# ---------- recording and replay ----------
class LiveGraph:
    """Worker side: GETs against Graph, follows paging like Invoke-GraphDirectly, records everything."""

    def __init__(self, http: Any, token: str) -> None:
        self.http, self.token = http, token
        self.responses: dict[str, dict[str, Any]] = {}

    def __call__(self, p: str) -> Any:
        if p in self.responses:
            return self._result(p)
        headers = {"Authorization": f"Bearer {self.token}"}
        if p.endswith("$count"):
            headers["ConsistencyLevel"] = "eventual"
        r = self.http.get(GRAPH + p, headers=headers, timeout=60)
        if r.status_code != 200:
            try:
                body: Any = r.json()
            except ValueError:
                body = r.text[:2000]
            self.responses[p] = {"status": r.status_code, "body": body}
            return self._result(p)
        body = int(r.text) if p.endswith("$count") else r.json()
        if isinstance(body, dict) and "value" in body:
            items = list(body["value"])
            nxt = body.get("@odata.nextLink")
            while nxt:
                page = self.http.get(nxt, headers=headers, timeout=60)
                if page.status_code != 200:
                    self.responses[p] = {"status": page.status_code, "body": page.json()}
                    return self._result(p)
                pb = page.json()
                items += pb.get("value", [])
                nxt = pb.get("@odata.nextLink")
            body = {**body, "value": items}
            body.pop("@odata.nextLink", None)
        self.responses[p] = {"status": 200, "body": body}
        return self._result(p)

    def _result(self, p: str) -> Any:
        rec = self.responses[p]
        if rec["status"] != 200:
            raise GraphError(p, rec["status"], rec["body"])
        return rec["body"]


class RecordedGraph:
    """Evaluator side: replays the sealed responses; a call that was never made is an error, not data."""

    def __init__(self, responses: dict[str, dict[str, Any]]) -> None:
        self.responses = responses

    def __call__(self, p: str) -> Any:
        rec = self.responses.get(p)
        if rec is None:
            raise GraphError(p, 0, "not recorded")
        if rec["status"] != 200:
            raise GraphError(p, rec["status"], rec["body"])
        return rec["body"]

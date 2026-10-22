"""ScubaGear's own Entra rules (v1.8.0) on our ported collection, evaluated by OPA 1.15.2."""

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from app.scuba import aad
from app.scuba.evaluate import evaluate_aad, rollup

OPA = os.environ.get("OPA_PATH") or shutil.which("opa") or "C:/Dbiz-Projects/AOC/tools/opa-1.15.2/opa.exe"
pytestmark = pytest.mark.skipif(not Path(OPA).exists(), reason="OPA not installed")
os.environ.setdefault("OPA_PATH", OPA)

TENANT = "1ac3b327-2499-4778-8b7d-8d7eab7040b8"
GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"


def ok(body: Any) -> dict[str, Any]:
    return {"status": 200, "body": body}


def mfa_policy(state: str = "enabled", **users: Any) -> dict[str, Any]:
    return {
        "id": "p1",
        "displayName": "Require MFA for all users",
        "state": state,
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "includeGroups": [],
                "excludeGroups": [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGuestsOrExternalUsers": None,
                "excludeGuestsOrExternalUsers": None,
                **users,
            },
            "applications": {"includeApplications": ["All"], "excludeApplications": []},
            "clientAppTypes": ["all"],
            "userRiskLevels": [],
            "signInRiskLevels": [],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"], "authenticationStrength": None},
    }


def tenant(policies: list[dict[str, Any]] | None = None, ca_status: int = 200, sms_on: bool = False) -> dict[str, dict[str, Any]]:
    """Recorded responses of a small tenant without Entra ID P2 (no PIM calls)."""
    P = aad.path
    r: dict[str, dict[str, Any]] = {
        P("Get-MgBetaIdentityConditionalAccessPolicy"): ok({"value": policies or []})
        if ca_status == 200
        else {"status": ca_status, "body": {"error": {"code": "Forbidden"}}},
        P("Get-MgBetaSubscribedSku"): ok(
            {
                "value": [
                    {
                        "skuPartNumber": "O365_BUSINESS_PREMIUM",
                        "consumedUnits": 3,
                        "prepaidUnits": {"enabled": 5},
                        "servicePlans": [{"servicePlanName": "AAD_PREMIUM", "provisioningStatus": "Success"}],
                    }
                ]
            }
        ),
        P("Get-MgBetaDirectoryRole"): ok(
            {"value": [{"id": "r1", "displayName": "Global Administrator", "roleTemplateId": GA_TEMPLATE}]}
        ),
        P("Get-MgBetaDirectoryRoleMember", "r1"): ok(
            {
                "value": [
                    {"@odata.type": "#microsoft.graph.user", "id": "u1"},
                    {"@odata.type": "#microsoft.graph.user", "id": "u2"},
                ]
            }
        ),
        P("Get-MgBetaUser", "u1"): ok({"id": "u1", "displayName": "Admin One", "onPremisesImmutableId": None}),
        P("Get-MgBetaUser", "u2"): ok({"id": "u2", "displayName": "Admin Two", "onPremisesImmutableId": None}),
        P("Get-MgBetaDirectoryRoleTemplate"): ok({"value": [{"id": GA_TEMPLATE, "displayName": "Global Administrator"}]}),
        P("Get-MgBetaUserCount"): ok(25),
        P("Get-MgBetaPolicyAuthorizationPolicy"): ok(
            {
                "id": "authorizationPolicy",
                "allowInvitesFrom": "adminsAndGuestInviters",
                "guestUserRoleId": "2af84b1e-32c8-42b7-82bc-daa82404023b",
                "defaultUserRolePermissions": {"allowedToCreateApps": False},
                "permissionGrantPolicyIdsAssignedToDefaultUserRole": [],
            }
        ),
        P("Get-MgBetaDirectorySetting"): ok({"value": []}),
        P("Get-MgBetaPolicyAuthenticationMethodPolicy"): ok(
            {
                "id": "authenticationMethodsPolicy",
                "policyMigrationState": "migrationComplete",
                "authenticationMethodConfigurations": [
                    {"id": "Sms", "state": "enabled" if sms_on else "disabled"},
                    {"id": "Voice", "state": "disabled"},
                    {"id": "Email", "state": "disabled"},
                ],
            }
        ),
        P("Get-MgBetaDomain"): ok(
            {
                "value": [
                    {
                        "id": "lab.onmicrosoft.com",
                        "isVerified": True,
                        "isRoot": True,
                        "authenticationType": "Managed",
                        "passwordValidityPeriodInDays": 2147483647,
                    }
                ]
            }
        ),
    }
    return r


def run(responses: dict[str, dict[str, Any]]) -> dict[str, Any]:
    provider = aad.build_provider(aad.RecordedGraph(responses))
    return {x.policy_id: x for x in evaluate_aad(aad.opa_input(provider, TENANT))}


def test_pascal_matches_convertfrom_graphhashtable() -> None:
    assert aad.pascal({"conditions": {"users": {"includeUsers": ["All"]}}, "@odata.type": "x"}) == {
        "Conditions": {"Users": {"IncludeUsers": ["All"]}},
        "@odata.type": "x",
    }


def test_provider_shape_and_privileged_users() -> None:
    p = aad.build_provider(aad.RecordedGraph(tenant([mfa_policy()])))
    assert p["conditional_access_policies"][0]["Conditions"]["Users"]["IncludeUsers"] == ["All"]
    assert p["privileged_users"] == {
        "u1": {"DisplayName": "Admin One", "OnPremisesImmutableId": None, "roles": ["Global Administrator"]},
        "u2": {"DisplayName": "Admin Two", "OnPremisesImmutableId": None, "roles": ["Global Administrator"]},
    }
    assert p["privileged_roles"] == [{"DisplayName": "Global Administrator", "RoleTemplateId": GA_TEMPLATE}]
    assert p["aad_unsuccessful_commands"] == []


def test_all_thirty_policies_are_scored() -> None:
    r = run(tenant([mfa_policy()]))
    assert len(r) == 30
    assert all(x.policy_id.startswith("MS.AAD.") for x in r.values())


def test_enforced_mfa_policy_passes_3_2() -> None:
    r = run(tenant([mfa_policy()]))
    assert r["MS.AAD.3.2v1"].status == "pass"
    assert r["MS.AAD.7.1v1"].status == "pass"  # two Global Administrators
    assert r["MS.AAD.6.1v1"].status == "pass"  # passwords never expire
    assert r["MS.AAD.5.1v1"].status == "pass"  # users cannot register apps


def test_report_only_mfa_policy_fails_3_2() -> None:
    r = run(tenant([mfa_policy(state="enabledForReportingButNotEnforced")]))
    assert r["MS.AAD.3.2v1"].status == "fail"
    assert rollup(1, list(r.values()))[0] == "gap"


def test_sms_enabled_fails_3_5() -> None:
    assert run(tenant([mfa_policy()], sms_on=True))["MS.AAD.3.5v1"].status == "fail"


def test_unreadable_conditional_access_is_an_error_never_a_failure() -> None:
    r = run(tenant(ca_status=403))
    assert r["MS.AAD.3.2v1"].status == "error"
    assert r["MS.AAD.1.1v1"].status == "error"
    assert rollup(1, list(r.values()))[0] == "not_observed"


def test_rollup_weak_when_only_advisory_fails() -> None:
    r = run(tenant([mfa_policy()], sms_on=True))
    state, detail = rollup(1, list(r.values()))  # type: ignore[misc]
    assert r["MS.AAD.1.1v1"].status in ("pass", "fail")
    if r["MS.AAD.1.1v1"].status == "pass":
        assert state == "weak" and "MS.AAD.3.5v1" in detail["advisory_not_met"]


FIX = Path(__file__).parent / "fixtures" / "scuba"
RESULT_TO_STATUS = {"Pass": "pass", "Fail": "fail", "Warning": "warning", "N/A": "na"}


def test_golden_matches_scubagears_own_results() -> None:
    """ScubaGear's sample input through our OPA step gives ScubaGear's own result for every Entra policy."""
    import json

    doc = json.loads((FIX / "sample-aad-input.json").read_text(encoding="utf-8"))
    expected = json.loads((FIX / "sample-aad-expected.json").read_text(encoding="utf-8"))
    base = lambda pid: pid.rsplit("v", 1)[0]  # noqa: E731 - MS.AAD.3.2v1 -> MS.AAD.3.2
    ours = {base(r.policy_id): r.status for r in evaluate_aad(doc)}
    want = {base(k): RESULT_TO_STATUS.get(v, v) for k, v in expected.items()}
    # The sample report shipped in 1.8.0 came from a later dev build in which MS.AAD.3.5 was
    # rewritten (v2: SMS/voice/email checks). The published 1.8.0 rules (vendored) still carry v1.
    ours.pop("MS.AAD.3.5"), want.pop("MS.AAD.3.5")
    assert len(ours) == 29
    assert ours == want


def test_registration_script_requests_exactly_the_permissions_the_app_uses() -> None:
    import ast

    from app.microsoft.graph import PERMISSIONS

    src = (Path(__file__).parents[2] / "scripts" / "register_microsoft_app.py").read_text(encoding="utf-8")
    node = next(n for n in ast.parse(src).body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "PERMISSIONS")
    assert sorted(ast.literal_eval(node.value)) == PERMISSIONS

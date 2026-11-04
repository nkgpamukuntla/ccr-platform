"""Intune, Secure Score, email DNS and the country frameworks, without a database."""

from datetime import UTC, datetime
from typing import Any

from app import email_dns, frameworks, tenant_checks
from app.controls import facts
from tests.test_microsoft import bundle, read

AT = datetime(2026, 11, 4, tzinfo=UTC)


def txt(*records: str) -> dict[str, Any]:
    return {"status": "ok" if records else "none", "records": list(records)}


def dkim(on: bool) -> dict[str, Any]:
    return {
        s: {"status": "ok", "records": ["x.onmicrosoft.com"]} if on else {"status": "none", "records": []}
        for s in ("selector1", "selector2")
    }


def test_email_domains_scored_from_recorded_dns() -> None:
    assert email_dns.domains(
        [
            {"id": "b.org", "isVerified": True},
            {"id": "Contoso.onmicrosoft.com", "isVerified": True, "isDefault": True},
            {"id": "a.org", "isVerified": True, "isDefault": True},
            {"id": "pending.org", "isVerified": False},
        ]
    ) == ["a.org", "b.org"]
    good = {
        "spf": txt("v=spf1 include:spf.protection.outlook.com -all"),
        "dmarc": txt("v=DMARC1; p=reject; rua=mailto:x@a.org"),
        "dkim": dkim(True),
    }
    monitor = {"spf": txt("v=spf1 include:x ~all"), "dmarc": txt("v=DMARC1; p=none"), "dkim": dkim(False)}
    bare = {"spf": txt("google-site-verification=1"), "dmarc": txt(), "dkim": dkim(False)}
    failed = {"spf": {"status": "error", "error": "Timeout", "records": []}, "dmarc": txt(), "dkim": dkim(False)}

    r = email_dns.domain_result("a.org", good)
    assert (r["spf"], r["dmarc"], r["dkim"]) == ("ok", "reject", "on")
    assert email_dns.evaluate({"a.org": good})["state"] == "met"
    assert email_dns.evaluate({"a.org": good, "b.org": monitor}) | {"domains": None} == {
        "state": "weak",
        "domains": None,
        "unsafe": [],
        "loose": ["b.org"],
    }
    e = email_dns.evaluate({"a.org": good, "c.org": bare})
    assert e is not None and e["state"] == "gap" and e["unsafe"] == ["c.org"]
    # A failed lookup is not checked, never "missing".
    assert email_dns.domain_result("d.org", failed)["spf"] == "not_checked"
    assert email_dns.evaluate({"d.org": failed | {"dmarc": txt("v=DMARC1; p=reject")}})["state"] == "not_observed"  # type: ignore[index]
    assert email_dns.evaluate({}) is None


MANAGED = [
    {
        "deviceName": "LT-1",
        "operatingSystem": "Windows",
        "osVersion": "10.0.26100.1",
        "complianceState": "compliant",
        "isEncrypted": True,
        "lastSyncDateTime": "2026-11-03T00:00:00Z",
    },
    {
        "deviceName": "LT-2",
        "operatingSystem": "Windows",
        "osVersion": "10.0.19045.5",
        "complianceState": "noncompliant",
        "isEncrypted": False,
        "lastSyncDateTime": "2026-09-01T00:00:00Z",
    },
    {
        "deviceName": "PHONE",
        "operatingSystem": "iOS",
        "osVersion": "18.1",
        "complianceState": "compliant",
        "isEncrypted": False,
        "lastSyncDateTime": "2026-11-03T00:00:00Z",
        "managedDeviceOwnerType": "personal",
    },
]


def test_intune_and_secure_score_from_reads() -> None:
    reads = {
        "managed_devices": read("managed_devices", 200, {"value": MANAGED}),
        "compliance_policies": read("compliance_policies", 200, {"value": [{"id": "p1"}]}),
        "secure_scores": read(
            "secure_scores",
            200,
            {
                "value": [
                    {
                        "currentScore": 40.0,
                        "maxScore": 80.0,
                        "createdDateTime": "2026-11-03T00:00:00Z",
                        "controlScores": [
                            {"controlName": "MFARegistrationV2", "score": 2.0},
                            {"controlName": "BlockLegacyAuthentication", "score": 8.0},
                        ],
                        "averageComparativeScores": [{"basis": "AllTenants", "averageScore": 33.25}],
                    }
                ]
            },
        ),
        "secure_score_profiles": read(
            "secure_score_profiles",
            200,
            {
                "value": [
                    {"id": "MFARegistrationV2", "title": "Ensure all users can complete MFA", "maxScore": 9.0},
                    {"id": "BlockLegacyAuthentication", "title": "Block legacy", "maxScore": 8.0},
                ]
            },
        ),
    }
    it = tenant_checks.intune(reads, AT)
    assert it is not None
    assert (
        it["total"],
        it["computers"],
        it["encrypted"],
        it["unencrypted"],
        it["noncompliant"],
        it["windows10"],
        it["stale"],
        it["personal"],
    ) == (3, 2, 1, 1, 1, 1, 1, 1)
    assert it["sample"]["unencrypted"] == ["LT-2"] and it["policies"] == 1  # a phone is not counted as an unencrypted computer
    ss = tenant_checks.secure_score(reads)
    assert ss is not None and ss["percent"] == 50 and ss["all_tenants_average"] == 33.2
    assert ss["top_actions"] == [{"title": "Ensure all users can complete MFA", "category": None, "gain": 7.0, "impact": None}]
    # Not consented yet: nothing, which the pages show as not checked.
    assert tenant_checks.intune({"managed_devices": read("managed_devices", 403, {})}, AT) is None
    assert tenant_checks.secure_score({}) is None
    assert tenant_checks.windows10("Windows", "10.0.22631.1") is False


def test_facts_carry_intune_secure_score_and_email() -> None:
    b = bundle()
    b["reads"].append(read("managed_devices", 200, {"value": MANAGED}))
    b["email_dns"] = {"a.org": {"spf": txt(), "dmarc": txt(), "dkim": dkim(False)}, "_error": "ignored"}
    f = facts(b, AT)
    assert f["intune"]["total"] == 3 and len(f["intune_devices"]) == 3 and f["secure_score"] is None
    assert f["email"]["state"] == "gap"
    assert facts(bundle(), AT)["intune"] is None and facts(bundle(), AT)["email"] is None


def test_frameworks_never_claim_more_than_the_evidence() -> None:
    assert frameworks.combine(["met", "met"]) == "met"
    assert frameworks.combine(["met", "not_observed"]) == "partly_checked"
    assert frameworks.combine(["met", "gap", "not_observed"]) == "gap"
    assert frameworks.combine(["pending"]) == "pending" and frameworks.combine([]) == "pending"
    assert frameworks.combine(["pending", "not_observed"]) == "not_observed"
    # Every mapped check exists, and every framework is for one of our countries.
    for fw in frameworks.FRAMEWORKS:
        assert fw["country"] in frameworks.COUNTRIES and fw["country"] in frameworks.DEADLINES
        for _, _, keys in fw["requirements"]:
            assert set(keys) <= set(frameworks.CHECKS)
    assert not any("CIS" in fw["name"].split() for fw in frameworks.FRAMEWORKS)

    controls = [{"control": 1, "state": "met", "summary": "On"}, {"control": 3, "state": "weak", "summary": "Phone only"}]
    found = frameworks.checks(controls, None, {"MS.AAD.7.1v1": "pass", "MS.AAD.7.4v1": "fail", "MS.AAD.1.1v1": "pass"}, [])
    assert found["admins"]["state"] == "gap" and "MS.AAD.7.4v1" in found["admins"]["note"]
    assert found["legacy"]["state"] == "met" and found["encryption"]["state"] == "not_observed"
    assert found["c2"]["state"] == "not_observed" and found["inventory"]["state"] == "not_observed"

    out = frameworks.assess(["AU"], found)
    assert [f["key"] for f in out] == ["essential_eight", "privacy_au"]
    e8 = {r["asks"]: r for r in out[0]["requirements"]}
    assert e8["Restrict Microsoft Office macros"]["state"] == "pending"  # only the office can answer
    assert e8["Multi-factor authentication"]["state"] == "weak"
    assert e8["Restrict administrative privileges"]["state"] == "gap"
    assert frameworks.assess([], found) == []

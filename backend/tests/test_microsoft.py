"""Certificate, client assertion and control rules, with a local RSA key standing in for KMS."""

import json
from datetime import UTC, datetime
from typing import Any

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.controls import evaluate, facts
from app.microsoft.certificate import build_certificate, thumbprints, to_pem
from app.microsoft.token import client_assertion


class LocalSigner:
    """Same contract as KmsSigner: RSASSA-PKCS1-v1_5 with SHA-256 over the raw message."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    def public_key_der(self) -> bytes:
        return self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(scope="module")
def signer() -> LocalSigner:
    return LocalSigner()


def test_certificate_is_valid_and_self_signed(signer: LocalSigner) -> None:
    der = build_certificate(signer, "CCR Evidence Collector dev", 365, now=datetime(2026, 10, 19, tzinfo=UTC))
    cert = x509.load_der_x509_certificate(der)
    assert cert.subject == cert.issuer
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "CCR Evidence Collector dev"
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 365
    # The signature verifies with the KMS public key: the private key was never needed locally.
    cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert x509.load_pem_x509_certificate(to_pem(der).encode()).fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256())


def test_thumbprints_match_the_certificate(signer: LocalSigner) -> None:
    import base64

    der = build_certificate(signer, "x", 1)
    x5t, x5t_s256 = thumbprints(der)
    cert = x509.load_der_x509_certificate(der)
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    assert base64.urlsafe_b64decode(pad(x5t)) == cert.fingerprint(hashes.SHA1())  # noqa: S303
    assert base64.urlsafe_b64decode(pad(x5t_s256)) == cert.fingerprint(hashes.SHA256())


def test_client_assertion_verifies_and_carries_microsoft_claims(signer: LocalSigner) -> None:
    tenant = "11111111-2222-3333-4444-555555555555"
    token = client_assertion(signer, "app-client-id", tenant, "x5t-value", "x5t256-value")
    header = jwt.get_unverified_header(token)
    assert header == {"alg": "RS256", "typ": "JWT", "x5t": "x5t-value", "x5t#S256": "x5t256-value"}
    claims = jwt.decode(
        token,
        signer.key.public_key(),
        algorithms=["RS256"],
        audience=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    )
    assert claims["iss"] == claims["sub"] == "app-client-id"
    assert claims["exp"] - claims["iat"] == 600


# ---------- control rules ----------
def read(name: str, status: int, body: Any) -> dict[str, Any]:
    return {"name": name, "status": status, "pages": [body]}


def policy(
    name: str, state: str = "enabled", users: list[str] | None = None, apps: list[str] | None = None, **user_extra: Any
) -> dict[str, Any]:
    return {
        "displayName": name,
        "state": state,
        "conditions": {
            "users": {"includeUsers": users or ["All"], **user_extra},
            "applications": {"includeApplications": apps or ["All"]},
        },
        "grantControls": {"builtInControls": ["mfa"]},
    }


def bundle(
    ca: list[dict[str, Any]] | None = None,
    ca_status: int = 200,
    sd: bool = False,
    regs: list[dict[str, Any]] | None = None,
    regs_status: int = 200,
) -> dict[str, Any]:
    return {
        "reads": [
            read("ca_policies", ca_status, {"value": ca or []} if ca_status == 200 else {"error": {"code": "Forbidden"}}),
            read("security_defaults", 200, {"isEnabled": sd}),
            read("auth_methods_registration", regs_status, {"value": regs or []} if regs_status == 200 else {"error": {}}),
            read(
                "subscribed_skus",
                200,
                {
                    "value": [
                        {
                            "skuPartNumber": "SPE_E5",
                            "capabilityStatus": "Enabled",
                            "prepaidUnits": {"enabled": 25},
                            "consumedUnits": 20,
                        }
                    ]
                },
            ),
            read("devices", 200, {"value": [{"isManaged": True, "isCompliant": False}, {"isManaged": False}]}),
        ]
    }


def states(b: dict[str, Any]) -> dict[int, str]:
    return {r.control: r.state for r in evaluate(b)}


def test_enforced_policy_meets_controls_1_and_2() -> None:
    s = states(bundle(ca=[policy("Require MFA for all users")]))
    assert s[1] == "met" and s[2] == "met"


def test_report_only_policy_is_weak_not_met() -> None:
    s = states(bundle(ca=[policy("MFA (report-only)", state="enabledForReportingButNotEnforced")]))
    assert s[1] == "weak" and s[2] == "gap"


def test_guest_exclusion_is_a_third_party_gap() -> None:
    s = states(
        bundle(
            ca=[policy("MFA except guests", excludeGuestsOrExternalUsers={"guestOrExternalUserTypes": "b2bCollaborationGuest"})]
        )
    )
    assert s[1] == "met" and s[2] == "gap"


def test_security_defaults_meet_controls_1_and_2() -> None:
    s = states(bundle(sd=True))
    assert s[1] == "met" and s[2] == "met"


def test_unreadable_conditional_access_is_not_observed_never_adverse() -> None:
    s = states(bundle(ca_status=403, regs_status=403))
    assert s[1] == "not_observed" and s[2] == "not_observed" and s[3] == "not_observed"


def test_admin_on_sms_only_is_a_weak_method() -> None:
    regs = [
        {
            "userPrincipalName": "admin1@lab",
            "isAdmin": True,
            "isMfaRegistered": True,
            "methodsRegistered": ["microsoftAuthenticatorPush"],
        },
        {"userPrincipalName": "admin2@lab", "isAdmin": True, "isMfaRegistered": True, "methodsRegistered": ["mobilePhone"]},
        {"userPrincipalName": "user@lab", "isAdmin": False, "isMfaRegistered": False, "methodsRegistered": []},
    ]
    r = {x.control: x for x in evaluate(bundle(regs=regs))}
    assert r[3].state == "weak" and r[3].detail["phone_only"] == ["admin2@lab"]


def test_unregistered_admin_is_a_gap() -> None:
    regs = [{"userPrincipalName": "a@lab", "isAdmin": True, "isMfaRegistered": False, "methodsRegistered": []}]
    assert states(bundle(regs=regs))[3] == "gap"


def test_later_phase_controls_are_never_met() -> None:
    s = states(bundle(sd=True))
    assert s[5] == "not_observed" and {s[6], s[7], s[8]} == {"pending"}


def test_facts_summarise_licences_and_devices() -> None:
    f = facts(bundle())
    assert f["licences"] == [{"sku": "SPE_E5", "enabled": 25, "consumed": 20}]
    assert f["devices"] == {"total": 2, "managed": 1, "compliant": 0}
    assert json.dumps(f)  # stored as JSON


def test_risk_based_policy_is_not_mfa_for_everyone() -> None:
    risky = policy("MFA on high user risk")
    risky["conditions"]["userRiskLevels"] = ["high"]
    assert states(bundle(ca=[risky]))[1] == "gap"
    legacy_only = policy("MFA for legacy clients only")
    legacy_only["conditions"]["clientAppTypes"] = ["exchangeActiveSync", "other"]
    assert states(bundle(ca=[legacy_only]))[1] == "gap"


def test_seeded_lab_a_shape() -> None:
    """The CDX lab after seeding: unconditional MFA policy report-only, risk policies report-only, admin on SMS."""
    vendor = policy("MFA for partners and vendors", state="enabledForReportingButNotEnforced")
    risk = policy("Reauth on sign-in risk", state="enabledForReportingButNotEnforced")
    risk["conditions"]["signInRiskLevels"] = ["high", "medium"]
    regs = [
        {"userPrincipalName": "lab-admin-sms@lab", "isAdmin": True, "isMfaRegistered": True, "methodsRegistered": ["mobilePhone"]}
    ]
    r = {x.control: x for x in evaluate(bundle(ca=[vendor, risk], regs=regs))}
    assert r[1].state == "weak" and r[1].detail["report_only_policies"] == ["MFA for partners and vendors"]
    assert r[2].state == "gap" and r[3].state == "weak"

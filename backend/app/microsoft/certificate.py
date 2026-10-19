"""A self-signed X.509 certificate whose signature is a kms:Sign by the signing key.

Built field by field with asn1crypto because no library will sign a certificate with a key it
does not hold. The public certificate is uploaded to the app registration; the private key
never exists outside KMS (handover section 8).
"""

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from asn1crypto import keys, pem, x509

from app.microsoft.signer import Signer

SHA256_RSA = {"algorithm": "sha256_rsa"}


def build_certificate(signer: Signer, common_name: str, days: int, now: datetime | None = None) -> bytes:
    """Returns the DER certificate."""
    now = (now or datetime.now(UTC)).replace(microsecond=0)
    public_key = keys.PublicKeyInfo.load(signer.public_key_der())
    name = x509.Name.build({"common_name": common_name, "organization_name": "Evidence Collector"})
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": int.from_bytes(secrets.token_bytes(16), "big") >> 1,  # positive, 127 bits
            "signature": SHA256_RSA,
            "issuer": name,
            "validity": {
                "not_before": x509.Time({"utc_time": now - timedelta(minutes=5)}),
                "not_after": x509.Time({"utc_time": now + timedelta(days=days)}),
            },
            "subject": name,
            "subject_public_key_info": public_key,
            "extensions": [
                {"extn_id": "basic_constraints", "critical": True, "extn_value": {"ca": False}},
                {"extn_id": "key_usage", "critical": True, "extn_value": {"digital_signature"}},
                {
                    "extn_id": "key_identifier",
                    "critical": False,
                    "extn_value": hashlib.sha1(public_key["public_key"].contents, usedforsecurity=False).digest(),
                },
            ],
        }
    )
    signature = signer.sign(tbs.dump())
    cert = x509.Certificate({"tbs_certificate": tbs, "signature_algorithm": SHA256_RSA, "signature_value": signature})
    der: bytes = cert.dump()
    return der


def to_pem(der: bytes) -> str:
    out: bytes = pem.armor("CERTIFICATE", der)
    return out.decode()


def thumbprints(der: bytes) -> tuple[str, str]:
    """(x5t, x5t#S256): base64url SHA-1 and SHA-256 of the DER certificate, for the JWT header."""

    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    return b64(hashlib.sha1(der, usedforsecurity=False).digest()), b64(hashlib.sha256(der).digest())

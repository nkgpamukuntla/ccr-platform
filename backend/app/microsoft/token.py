"""App-only token for one consenting tenant: client credentials with a certificate assertion.

The assertion is a JWT signed by kms:Sign (RS256), so the worker holds no private key and
no client secret exists (R3). Read-only application permissions only (R7).
"""

import base64
import json
import time
import uuid

import httpx

from app.microsoft.signer import Signer

GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def client_assertion(signer: Signer, client_id: str, tenant_id: str, x5t: str, x5t_s256: str, now: int | None = None) -> str:
    now = now or int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": x5t, "x5t#S256": x5t_s256}
    claims = {
        "aud": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now - 30,
        "iat": now,
        "exp": now + 600,
    }
    signing_input = (
        f"{_b64(json.dumps(header, separators=(',', ':')).encode())}.{_b64(json.dumps(claims, separators=(',', ':')).encode())}"
    )
    return f"{signing_input}.{_b64(signer.sign(signing_input.encode()))}"


class TokenError(Exception):
    pass


def get_token(http: httpx.Client, signer: Signer, client_id: str, tenant_id: str, x5t: str, x5t_s256: str) -> str:
    r = http.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "client_id": client_id,
            "scope": GRAPH_SCOPE,
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion(signer, client_id, tenant_id, x5t, x5t_s256),
        },
        timeout=30,
    )
    if r.status_code != 200:
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        # error codes only; never log the assertion
        raise TokenError(f"{r.status_code} {body.get('error', '')}: {str(body.get('error_description', ''))[:300]}")
    token: str = r.json()["access_token"]
    return token

"""Sign-in with Cognito (authorization code + PKCE, public client: no client secret exists).

The ID token is kept in an HttpOnly, Secure, SameSite=Lax cookie and verified on every
request against the user pool's published keys, so the server holds no signing secret.
Groups: platform_admin (everything), aoc_viewer (aggregate, read-only), and office members.
"""

import base64
import hashlib
import secrets
import time
from typing import Annotated, Any
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.config import Settings, get_settings

SESSION_COOKIE = "ccr_session"
FLOW_COOKIE = "ccr_flow"

router = APIRouter(prefix="/auth", tags=["auth"])


class User(BaseModel):
    sub: str
    email: str
    groups: list[str]

    @property
    def is_admin(self) -> bool:
        return "platform_admin" in self.groups

    @property
    def is_aoc(self) -> bool:
        return self.is_admin or "aoc_viewer" in self.groups


_jwks: jwt.PyJWKClient | None = None


def _jwks_client(s: Settings) -> jwt.PyJWKClient:
    global _jwks
    if _jwks is None:
        _jwks = jwt.PyJWKClient(f"{s.cognito_issuer}/.well-known/jwks.json", cache_keys=True, lifespan=3600)
    return _jwks


def verify_id_token(token: str, s: Settings) -> dict[str, Any]:
    key = _jwks_client(s).get_signing_key_from_jwt(token)
    claims: dict[str, Any] = jwt.decode(
        token,
        key.key,
        algorithms=["RS256"],
        audience=s.cognito_client_id,
        issuer=s.cognito_issuer,
        options={"require": ["exp", "iat", "sub", "token_use"]},
    )
    if claims.get("token_use") != "id":
        raise jwt.InvalidTokenError("not an ID token")
    return claims


def current_user(request: Request, s: Annotated[Settings, Depends(get_settings)]) -> User:
    if s.auth_mode == "dev":
        # Workstation only (config refuses dev mode outside environment=local).
        email = request.headers.get("x-dev-user", "dev@example.test")
        groups = [g for g in request.headers.get("x-dev-groups", "platform_admin").split(",") if g]
        return User(sub=f"dev:{email}", email=email, groups=groups)
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "sign in required")
    try:
        claims = verify_id_token(token, s)
    except jwt.PyJWTError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired or invalid") from e
    # Membership is keyed on email, so only a verified address counts.
    email = claims.get("email", "").lower() if claims.get("email_verified") in (True, "true") else ""
    return User(sub=claims["sub"], email=email, groups=claims.get("cognito:groups", []))


CurrentUser = Annotated[User, Depends(current_user)]


def require_admin(user: CurrentUser) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "platform administrators only")
    return user


def require_aoc(user: CurrentUser) -> User:
    if not user.is_aoc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "AOC view only")
    return user


# ---------- browser flow ----------
def safe_next(target: str | None) -> str:
    """Only same-site paths: never an absolute URL or a scheme-relative //host (open redirect)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@router.get("/login")
def login(s: Annotated[Settings, Depends(get_settings)], next: str | None = None) -> RedirectResponse:  # noqa: A002
    if s.auth_mode == "dev":
        return RedirectResponse(safe_next(next))
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(24)
    query = urlencode(
        {
            "response_type": "code",
            "client_id": s.cognito_client_id,
            "redirect_uri": f"{s.public_url}/auth/callback",
            "scope": "openid email profile",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    resp = RedirectResponse(f"{s.cognito_domain}/oauth2/authorize?{query}")
    resp.set_cookie(
        FLOW_COOKIE,
        f"{state}.{verifier}.{base64.urlsafe_b64encode(safe_next(next).encode()).decode()}",
        max_age=600,
        httponly=True,
        secure=s.secure_cookies,
        samesite="lax",
        path="/auth",
    )
    return resp


@router.get("/callback")
def callback(request: Request, code: str, state: str, s: Annotated[Settings, Depends(get_settings)]) -> RedirectResponse:
    flow = request.cookies.get(FLOW_COOKIE, "")
    expected_state, _, rest = flow.partition(".")
    verifier, _, next_b64 = rest.partition(".")
    if not verifier or not secrets.compare_digest(expected_state, state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "sign-in state mismatch; start again")
    r = httpx.post(
        f"{s.cognito_domain}/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": s.cognito_client_id,
            "code": code,
            "redirect_uri": f"{s.public_url}/auth/callback",
            "code_verifier": verifier,
        },
        timeout=10,
    )
    if r.status_code != 200:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "sign-in failed")
    id_token = r.json()["id_token"]
    claims = verify_id_token(id_token, s)
    try:
        target = safe_next(base64.urlsafe_b64decode(next_b64.encode()).decode())
    except ValueError:
        target = "/"
    resp = RedirectResponse(target)
    resp.set_cookie(
        SESSION_COOKIE,
        id_token,
        max_age=max(60, int(claims["exp"] - time.time())),
        httponly=True,
        secure=s.secure_cookies,
        samesite="lax",
        path="/",
    )
    resp.delete_cookie(FLOW_COOKIE, path="/auth")
    return resp


@router.get("/logout")
def logout(s: Annotated[Settings, Depends(get_settings)]) -> RedirectResponse:
    target = (
        "/"
        if s.auth_mode == "dev"
        else (f"{s.cognito_domain}/logout?" + urlencode({"client_id": s.cognito_client_id, "logout_uri": f"{s.public_url}/"}))
    )
    resp = RedirectResponse(target)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

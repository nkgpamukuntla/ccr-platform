"""Portal users in Cognito. Users are created by administrators only (no self sign-up);
Cognito emails each new user a temporary password, which nothing here ever sees."""

from typing import Any

import boto3

from app.config import get_settings

ASSIGNABLE_GROUPS = {"aoc_viewer"}  # platform_admin is granted through Terraform only


def _client() -> Any:
    return boto3.client("cognito-idp", region_name=get_settings().aws_region)


def ensure_user(email: str) -> str:
    """Creates the user if new; returns 'invited' or 'exists'."""
    c, pool = _client(), get_settings().cognito_user_pool_id
    try:
        c.admin_get_user(UserPoolId=pool, Username=email)
        return "exists"
    except c.exceptions.UserNotFoundException:
        c.admin_create_user(
            UserPoolId=pool,
            Username=email,
            UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
            DesiredDeliveryMediums=["EMAIL"],
        )
        return "invited"


def add_to_group(email: str, group: str) -> None:
    if group not in ASSIGNABLE_GROUPS:
        raise ValueError(f"group {group} cannot be assigned from the portal")
    _client().admin_add_user_to_group(UserPoolId=get_settings().cognito_user_pool_id, Username=email, GroupName=group)


def list_users() -> list[dict[str, Any]]:
    c, pool = _client(), get_settings().cognito_user_pool_id
    users: list[dict[str, Any]] = []
    for page in c.get_paginator("list_users").paginate(UserPoolId=pool):
        for u in page["Users"]:
            attrs = {a["Name"]: a["Value"] for a in u.get("Attributes", [])}
            users.append(
                {
                    "email": attrs.get("email", u["Username"]).lower(),
                    "status": u.get("UserStatus"),
                    "enabled": u.get("Enabled", True),
                    "created": u.get("UserCreateDate"),
                }
            )
    groups: dict[str, list[str]] = {}
    for g in ("platform_admin", "aoc_viewer"):
        for page in c.get_paginator("list_users_in_group").paginate(UserPoolId=pool, GroupName=g):
            for u in page["Users"]:
                email = {a["Name"]: a["Value"] for a in u.get("Attributes", [])}.get("email", u["Username"]).lower()
                groups.setdefault(email, []).append(g)
    for u in users:
        u["groups"] = groups.get(u["email"], [])
    return users

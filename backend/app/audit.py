"""Append-only audit trail. Every write in the portal records who, what and for which office."""

from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from app.auth import User


def record(conn: psycopg.Connection[Any], user: User, action: str, office_id: UUID | None = None, **detail: Any) -> None:
    conn.execute(
        "INSERT INTO audit_log (actor_sub, actor_email, office_id, action, detail) VALUES (%s, %s, %s, %s, %s)",
        (user.sub, user.email, office_id, action, Jsonb(detail)),
    )

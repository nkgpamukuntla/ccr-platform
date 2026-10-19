"""Who may see or change an office. Applied in every office route.

R11: this separates code paths; it is not tenant isolation. The database grants are what
hold against a compromised component."""

from typing import Any
from uuid import UUID

import psycopg
from fastapi import HTTPException, status

from app.auth import User


def office_role(conn: psycopg.Connection[Any], user: User, office_id: UUID) -> str | None:
    row = conn.execute(
        "SELECT role FROM membership WHERE email = %s AND office_id = %s", (user.email.lower(), office_id)
    ).fetchone()
    return row["role"] if row else None


def can_read(conn: psycopg.Connection[Any], user: User, office_id: UUID) -> None:
    if user.is_aoc or office_role(conn, user, office_id):
        return
    raise HTTPException(status.HTTP_404_NOT_FOUND, "office not found")


def can_write(conn: psycopg.Connection[Any], user: User, office_id: UUID) -> None:
    if user.is_admin or office_role(conn, user, office_id):
        return
    if user.is_aoc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "the AOC view is read-only")
    raise HTTPException(status.HTTP_404_NOT_FOUND, "office not found")

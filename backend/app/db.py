"""Connection pool. In AWS each new connection logs in with a fresh RDS IAM auth token."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.config import Settings, get_settings

_pool: ConnectionPool | None = None


def _iam_token(s: Settings) -> str:
    import boto3

    client = boto3.client("rds", region_name=s.aws_region)
    token: str = client.generate_db_auth_token(DBHostname=s.pghost, Port=s.pgport, DBUsername=s.pguser, Region=s.aws_region)
    return token


class _IamConnection(psycopg.Connection[Any]):
    """Mints a token at connect time; tokens last 15 minutes, connections can outlive them."""

    @classmethod
    def connect(cls, conninfo: str = "", **kwargs: Any) -> "_IamConnection":
        kwargs["password"] = _iam_token(get_settings())
        return super().connect(conninfo, **kwargs)


def conninfo(s: Settings) -> dict[str, Any]:
    info: dict[str, Any] = {
        "host": s.pghost,
        "port": s.pgport,
        "dbname": s.pgdatabase,
        "user": s.pguser,
        "sslmode": s.pgsslmode,
    }
    if s.pgsslrootcert:
        info["sslrootcert"] = s.pgsslrootcert
    if s.pgpassword and not s.db_iam_auth:
        info["password"] = s.pgpassword
    return info


def open_pool() -> ConnectionPool:
    global _pool
    s = get_settings()
    connection_class: type[psycopg.Connection[Any]] = _IamConnection if s.db_iam_auth else psycopg.Connection
    _pool = ConnectionPool(
        kwargs={**conninfo(s), "row_factory": dict_row},
        connection_class=connection_class,
        min_size=1,
        max_size=5,
        max_lifetime=600,  # recycle well inside the token's life
        open=True,
    )
    return _pool


def close_pool() -> None:
    if _pool is not None:
        _pool.close()


@contextmanager
def tx() -> Iterator[psycopg.Connection[dict[str, Any]]]:
    """One transaction: commits on success, rolls back on error."""
    assert _pool is not None, "pool not opened"
    with _pool.connection() as conn, conn.transaction():
        yield conn  # type: ignore[misc]

"""Apply numbered SQL migrations once each, then grant CONNECT to the runtime roles.

Runs as the one-off db-bootstrap ECS task with the RDS-managed master credentials
(PGUSER/PGPASSWORD injected from Secrets Manager), or locally against a dev database.

    python -m app.migrate --dir migrations
"""

import argparse
import sys
from pathlib import Path

import psycopg
from psycopg import sql

from app.config import get_settings
from app.db import conninfo

RUNTIME_ROLES = ("ec_portal",)


def migrate(directory: Path) -> list[str]:
    s = get_settings()
    info = conninfo(s)
    applied: list[str] = []
    with psycopg.connect(**info, autocommit=True) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migration ( name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {r[0] for r in conn.execute("SELECT name FROM schema_migration").fetchall()}
        for path in sorted(directory.glob("*.sql")):
            if path.name in done:
                continue
            with conn.transaction():
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migration (name) VALUES (%s)", (path.name,))
            applied.append(path.name)
        for role in RUNTIME_ROLES:
            conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(s.pgdatabase), sql.Identifier(role)))
    return applied


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default="migrations")
    args = parser.parse_args()
    applied = migrate(Path(args.dir))
    print(f"applied {len(applied)} migration(s): {', '.join(applied) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

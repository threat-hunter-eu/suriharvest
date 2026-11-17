"""SQLite engine (WAL) and Alembic schema management.

Schema changes are additive Alembic migrations. Code refuses to work on a database whose schema is behind, except
the commands that write (`doctor`, `update`, `sync`), which upgrade it under the workspace lock first; so an old
database is never written by newer code by accident.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import ClauseElement, ColumnElement, Engine, bindparam, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

MIGRATIONS = Path(__file__).parent / "migrations"


class SchemaBehind(RuntimeError):
    """The database schema is older than the code: run `suriharvest doctor`."""


# SQLite's upstream default for bound variables. Python builds from python.org, uv and Windows keep it; Ubuntu's
# system SQLite allows 250,000. Every connection is lowered to it so a long IN list fails in tests, not for users.
MAX_SQL_VARIABLES = 32766


def in_list(col: Any, values: Iterable[Any]) -> ColumnElement[bool]:
    """`col IN (values)` with ONE bound parameter (a JSON array read by json_each), for lists of any length."""
    if isinstance(values, ClauseElement):  # a subquery binds nothing
        return col.in_(values)
    vals = list(values)
    return col.in_(text("SELECT value FROM json_each(:vals)").bindparams(bindparam("vals", json.dumps(vals), unique=True)))


def make_engine(db_path: Path, **pool: Any) -> Engine:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30}, **pool)

    @event.listens_for(engine, "connect")
    def _pragmas(conn, _record):  # type: ignore[no-untyped-def]
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()
        if isinstance(conn, sqlite3.Connection) and hasattr(conn, "setlimit"):
            conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, MAX_SQL_VARIABLES)

    return engine


def alembic_config(db_path: Path) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config(Path("x.db"))).get_current_head()


def current_revision(db_path: Path) -> str | None:
    if not db_path.exists():
        return None
    engine = make_engine(db_path)
    try:
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()


def upgrade(db_path: Path) -> None:
    """Create the database or migrate it to the latest schema."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(db_path), "head")


def session_factory(db_path: Path, *, migrate: bool = False, **pool: Any) -> sessionmaker[Session]:
    if migrate:
        upgrade(db_path)
    cur, head = current_revision(db_path), head_revision()
    if cur != head:
        what = "does not exist" if cur is None else f"is at {cur}, code expects {head}"
        raise SchemaBehind(f"database {db_path} {what}; run `suriharvest doctor` to create or upgrade it")
    engine = make_engine(db_path, **pool)
    relocate(engine, db_path.resolve().parent.parent)
    return sessionmaker(engine, expire_on_commit=False)


# Stored folders that live inside the workspace: (table, column, the part of the path from the workspace root).
RELOCATABLE = (("profile_builds", "path", "/data/profiles/"), ("update_runs", "report_path", "/reports/"))


def relocate(engine: Engine, root: Path) -> None:
    """The workspace folder was moved or copied: point stored build and report paths at the new place."""
    r = str(root)
    # Paths are stored with the separator of the OS that wrote them; match both, so a workspace moved (or copied
    # between Linux and Windows) is still found. The new prefix uses this OS's separator.
    variants = [(t, col, m.replace("/", sep), sep) for t, col, m in RELOCATABLE for sep in dict.fromkeys(("/", os.sep))]
    with engine.connect() as c:
        stale = sum(
            c.exec_driver_sql(
                # table and column names come from the RELOCATABLE constant; values are bound parameters
                f"SELECT count(*) FROM {t} WHERE {col} IS NOT NULL AND {col} NOT LIKE ? AND instr({col}, ?) > 0",  # noqa: S608
                (r + os.sep + "%", m),
            ).scalar_one()
            for t, col, m, _ in variants
        )
    if not stale:
        return
    with engine.begin() as c:
        for t, col, m, _ in variants:
            c.exec_driver_sql(
                f"UPDATE {t} SET {col} = ? || substr({col}, instr({col}, ?)) WHERE {col} IS NOT NULL AND {col} NOT LIKE ? AND instr({col}, ?) > 0",  # noqa: S608 (constant names)
                (r, m, r + os.sep + "%", m),
            )


def get_meta(s: Session, key: str) -> str | None:
    from suriharvest.models import Meta

    row = s.get(Meta, key)
    return row.value if row is not None else None


def set_meta(s: Session, key: str, value: str) -> None:
    from suriharvest.models import Meta

    row = s.get(Meta, key)
    if row is None:
        s.add(Meta(key=key, value=value))
    else:
        row.value = value

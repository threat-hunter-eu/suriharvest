"""Alembic environment: the database URL comes from suriharvest.db.alembic_config."""

from alembic import context
from sqlalchemy import create_engine

from suriharvest.models import Base

config = context.config
target_metadata = Base.metadata


def include_object(obj, name, type_, reflected, compare_to):  # type: ignore[no-untyped-def]
    # FTS5 tables are created by raw SQL; autogenerate must never touch them.
    return not (type_ == "table" and name and name.startswith("rules_fts"))


def run_migrations_online() -> None:
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True, include_object=include_object)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


run_migrations_online()

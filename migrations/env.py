import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from vaultrewind.server import models  # noqa: F401
from vaultrewind.server.db import Base

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
url = os.environ.get("VAULTREWIND_DATABASE_URL")
if url:
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
target_metadata = Base.metadata


def offline():
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata,
                      literal_binds=True, dialect_opts={"paramstyle": "named"}, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def online():
    supplied = config.attributes.get("connection")
    if supplied is not None:
        context.configure(connection=supplied, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    connectable = engine_from_config(config.get_section(config.config_ini_section), prefix="sqlalchemy.",
                                    poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    offline()
else:
    online()

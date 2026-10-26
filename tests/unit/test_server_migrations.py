from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.unit.test_server import env  # noqa: F401
from vaultrewind.server.app import create_app
from vaultrewind.server.db import Base, make_engine


def config(connection):
    result=Config(str(Path("alembic.ini").resolve()))
    result.attributes["connection"]=connection
    return result


def test_sqlite_real_migrations_match_metadata_and_readiness_uses_actual_head(env,tmp_path):  # noqa: F811
    settings,_,_,_,_=env
    engine=make_engine("sqlite+pysqlite:///"+str(tmp_path/"migrations.db"))
    # Alembic's batch table rebuilds are run in its own migration connection, with FK enforcement
    # disabled only on this empty disposable SQLite migration database.
    with engine.begin() as connection:
        connection.execute(text("PRAGMA foreign_keys=OFF"))
        command.upgrade(config(connection),"head")
        differences=compare_metadata(MigrationContext.configure(connection),Base.metadata)
        assert differences==[]
    app=create_app(settings,engine=engine)
    client=TestClient(app,base_url="http://localhost")
    assert client.get("/api/v1/health/ready").status_code==200
    with engine.begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num='outdated'"))
    assert client.get("/api/v1/health/ready").status_code==503
    with engine.begin() as connection:
        head=ScriptDirectory("migrations").get_current_head()
        connection.execute(text("UPDATE alembic_version SET version_num=:head"),{"head":head})
        command.downgrade(config(connection),"base")
        command.upgrade(config(connection),"head")
    assert client.get("/api/v1/health/ready").status_code==200
    engine.dispose()


def test_readiness_accepts_configured_future_migration_head(env,tmp_path):  # noqa: F811
    settings,engine,_,_,_=env
    directory=tmp_path/"future-migrations"
    (directory/"versions").mkdir(parents=True)
    (directory/"versions/future.py").write_text("revision='future_head'\ndown_revision=None\n")
    settings.migrations_dir=directory
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)"))
        connection.execute(text("INSERT INTO alembic_version VALUES ('future_head')"))
    client=TestClient(create_app(settings,engine=engine),base_url="http://localhost")
    assert client.get("/api/v1/health/ready").status_code==200

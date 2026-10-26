from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool


def now() -> datetime:
    return datetime.now(UTC)


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def uid() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


def make_engine(url: str):
    kw = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            kw["poolclass"] = StaticPool
    engine = create_engine(url, **kw)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def sqlite_fk(conn, _):
            conn.execute("PRAGMA foreign_keys=ON")
    return engine


def sessions(engine):
    return sessionmaker(engine, expire_on_commit=False)

"""Opt-in PostgreSQL concurrency evidence, isolated in an ephemeral schema."""
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server.db import Base, now, sessions, uid
from vaultrewind.server.models import Job
from vaultrewind.server.queue import assert_fence, claim, enqueue, finish


@pytest.fixture
def postgres():
    url = os.environ.get("VAULTREWIND_TEST_DATABASE_URL")
    fixture = Path(".runtime/controller/database-url")
    if not url and fixture.exists():
        url = fixture.read_text().strip()
    if not url:
        pytest.skip("A disposable PostgreSQL database URL is required")
    bootstrap = create_engine(url)
    schema = "server_test_" + uid().replace("-", "")
    with bootstrap.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"}, pool_size=6)
    Base.metadata.create_all(engine)
    yield engine, sessions(engine)
    engine.dispose()
    with bootstrap.begin() as conn:
        conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    bootstrap.dispose()


def test_postgres_concurrent_claims_enforce_global_limit_and_no_duplicate_claim(postgres):
    _engine, factory = postgres
    with factory.begin() as db:
        for index in range(6):
            enqueue(db, kind="doctor", request={"n":index}, key=f"request-{index}", resources=[f"physical:{index}"])
    barrier = threading.Barrier(4)
    def take(index):
        barrier.wait()
        with factory.begin() as db:
            job = claim(db, f"worker:{index}", global_concurrency=2)
            return job.id if job else None
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(take, range(4)))
    claimed = [r for r in results if r]
    assert len(claimed) == 2 and len(set(claimed)) == 2
    with factory() as db:
        assert len(list(db.scalars(select(Job).where(Job.state=="running")))) == 2


def test_postgres_expired_physical_owner_requires_reconciliation_before_new_job(postgres):
    _, factory = postgres
    with factory.begin() as db:
        first = enqueue(db,kind="doctor",request={},key="first",resources=["physical:shared"])
        second = enqueue(db,kind="doctor",request={},key="second",resources=["physical:shared"])
    with factory.begin() as db:
        old = claim(db,"worker:one")
        token = old.fencing_token
        old.lease_expires_at = now()-timedelta(seconds=1)
    with factory.begin() as db:
        recovered = claim(db,"worker:two")
        assert recovered.id==first.id and recovered.reconcile_required and recovered.fencing_token>token
        finish(db,recovered,"succeeded")
    with factory.begin() as db:
        next_job = claim(db,"worker:three")
        assert next_job.id==second.id and next_job.fencing_token>recovered.fencing_token
    with factory.begin() as db, pytest.raises(VaultRewindError):
        assert_fence(db,first.id,"worker:one",token)


def test_postgres_concurrent_identical_keys_return_single_durable_job(postgres):
    _, factory = postgres
    barrier = threading.Barrier(4)
    def submit(index):
        barrier.wait()
        with factory.begin() as db:
            return enqueue(db,kind="doctor",request={"same":True},key="identical",resources=["physical:one"]).id
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(submit,range(4)))
    assert len(set(results))==1

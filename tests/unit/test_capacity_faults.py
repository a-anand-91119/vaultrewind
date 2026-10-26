"""Real controller quota/accounting and extraction; no mocked workflow success."""
import io
import tarfile

import httpx
import pytest
from sqlalchemy import select

from scripts.prove_capacity_faults import MIB, Controller, QuotaS3, decode_s3_upload, tree_hash
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server.models import StagingAllocation


@pytest.fixture
def controller(tmp_path):
    ctl = Controller(tmp_path / "controller")
    yield ctl
    ctl.engine.dispose()


def test_per_job_rejection_creates_no_staging_or_allocation(controller):
    ctx = controller.context()
    with pytest.raises(VaultRewindError, match="per-job staging quota") as caught:
        ctx.reserve(controller.settings.per_job_quota_bytes + 1)
    assert caught.value.code == "INSUFFICIENT_SPACE"
    assert not ctx.root.exists()
    with controller.worker.sessions() as db:
        assert db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == ctx.id)) is None
    assert controller.failed(ctx, caught.value)["active_job_count"] == 0


def test_global_reservations_block_second_job_without_touching_first(controller):
    controller.settings.staging_quota_bytes = 4*MIB
    first = controller.context()
    first.reserve()
    payload = first.root / "protected-capture"
    payload.write_bytes(b"immutable captured bytes")
    second = controller.context()
    with pytest.raises(VaultRewindError, match="global staging quota") as caught:
        second.reserve()
    assert caught.value.code == "INSUFFICIENT_SPACE"
    assert payload.read_bytes() == b"immutable captured bytes"
    assert not second.root.exists()
    with controller.worker.sessions() as db:
        allocations = list(db.scalars(select(StagingAllocation)))
        assert len(allocations) == 1
        assert allocations[0].job_id == first.id
        assert allocations[0].reserved_bytes == 4*MIB
    # Settle both real claims, then require the failed job leaves no active owner.
    first.finish("cancelled")
    first.cleanup()
    assert controller.failed(second, caught.value)["active_job_count"] == 0


def test_retained_retry_bytes_are_accounted_and_never_evicted(controller):
    controller.settings.staging_quota_bytes = 4*MIB
    first = controller.context()
    first.reserve()
    payload = first.root / "retry-capture"
    payload.write_bytes(b"r"*1024)
    first.cleanup(preserve=True)
    first.finish("failed")
    with controller.worker.sessions() as db:
        row = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == first.id))
        assert (row.state, row.actual_bytes, row.reserved_bytes) == ("retained", 1024, 1024)
    second = controller.context()
    with pytest.raises(VaultRewindError, match="global staging quota") as caught:
        second.reserve()
    assert payload.read_bytes() == b"r"*1024
    assert controller.failed(second, caught.value)["active_job_count"] == 0
    with controller.worker.sessions() as db:
        row = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == first.id))
        assert row.state == "retained"


def test_compressed_expansion_uses_real_context_budget_before_writing_files(controller):
    controller.settings.per_job_quota_bytes = MIB
    ctx = controller.context()
    ctx.reserve()
    archive = ctx.root / "capture.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("data/attachment")
        member.size = 2*MIB
        output.addfile(member, io.BytesIO(b"x"*member.size))
    original = archive.read_bytes()
    assert len(original) < 4096
    with pytest.raises(VaultRewindError) as caught:
        ctx.extract(archive, ctx.root / "snapshot", "unused-because-extraction-must-fail")
    assert caught.value.code == "STAGING_QUOTA_EXCEEDED"
    assert archive.read_bytes() == original
    assert list((ctx.root / "snapshot").rglob("*")) == []
    result = controller.failed(ctx, caught.value)
    assert result["allocation_state"] == "released"
    assert result["active_job_count"] == 0


def test_synthetic_s3_quota_rejects_real_http_put_while_old_bytes_remain_readable():
    with QuotaS3() as fixture, httpx.Client(trust_env=False, timeout=5) as client:
        url = f"http://127.0.0.1:{fixture.server.server_port}/capacity-fixture/old-object"
        assert client.put(url, content=b"older encrypted bytes").status_code == 200
        assert client.head(url).headers["content-length"] == "21"
        assert "last-modified" in client.head(url).headers
        before = fixture.digest()
        fixture.quota = True
        rejected = client.put(url, content=b"replacement must fail")
        assert rejected.status_code == 403
        assert "<Code>QuotaExceeded</Code>" in rejected.text
        assert fixture.digest() == before
        assert client.get(url).content == b"older encrypted bytes"
        partial = client.get(url, headers={"Range": "bytes=6-14"})
        assert partial.status_code == 206 and partial.content == b"encrypted"
        assert fixture.rejected == [{"method": "PUT", "status": 403, "code": "QuotaExceeded"}]


def test_preservation_hash_detects_empty_replacement_directory(tmp_path):
    (tmp_path / "old-object").write_bytes(b"older repository bytes")
    before = tree_hash(tmp_path)
    (tmp_path / "unwanted-empty-replacement").mkdir()
    assert tree_hash(tmp_path) != before


def test_s3_signed_stream_frames_are_not_stored_as_repository_bytes():
    wire = b"5;chunk-signature=fixture\r\nolder\r\n6;chunk-signature=fixture\r\n bytes\r\n0;chunk-signature=fixture\r\n\r\n"
    assert decode_s3_upload(wire, "11") == b"older bytes"
    with pytest.raises(AssertionError, match="LENGTH_MISMATCH"):
        decode_s3_upload(wire, "12")
    with pytest.raises(AssertionError, match="CHUNK_TRUNCATED"):
        decode_s3_upload(wire[:30], "11")

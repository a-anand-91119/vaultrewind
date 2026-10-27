"""Exercise the publishing boundary without Docker, GitLab or real credentials."""
from __future__ import annotations

import csv
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".gitlab/build-image.sh"
SHA = "a" * 40
PASSWORD = "synthetic-ci-password-not-a-live-token"


@pytest.fixture
def publishing_job(tmp_path):
    context = tmp_path / "checkout"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\n")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    capture = tmp_path / "captured.json"
    buildctl = binaries / "buildctl-daemonless.sh"
    buildctl.write_text(f"#!{sys.executable}\n" + '''
import base64,json,os,stat,sys
from pathlib import Path
directory=Path(os.environ['DOCKER_CONFIG'])
config=directory/'config.json'
value=json.loads(config.read_text())['auths'][os.environ['CI_REGISTRY']]['auth']
expected=os.environ['CI_REGISTRY_USER']+':'+os.environ['CI_REGISTRY_PASSWORD']
assert base64.b64decode(value).decode()==expected
assert stat.S_IMODE(directory.stat().st_mode)==0o700
assert stat.S_IMODE(config.stat().st_mode)==0o600
assert not directory.is_relative_to(Path(os.environ['CI_PROJECT_DIR']))
assert os.environ['CI_REGISTRY_PASSWORD'] not in '\\0'.join(sys.argv)
Path(os.environ['CAPTURE']).write_text(json.dumps({'arguments':sys.argv[1:],
    'auth_directory':str(directory),'authenticated':True}))
if os.environ.get('FAIL_BUILD')=='1':sys.exit(17)
metadata=Path(sys.argv[sys.argv.index('--metadata-file')+1])
metadata.write_text(json.dumps({'containerimage.digest':'sha256:'+'b'*64}))
''')
    buildctl.chmod(0o700)
    environment = {
        "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
        "CI_COMMIT_TAG": "v1.2.3",
        "CI_COMMIT_SHA": SHA,
        "CI_PROJECT_DIR": str(context),
        "CI_PROJECT_URL": "https://gitlab.example.invalid/group/vaultrewind",
        "CI_REGISTRY": "registry.example.invalid:5050",
        "CI_REGISTRY_IMAGE": "registry.example.invalid:5050/group/vaultrewind",
        "CI_REGISTRY_USER": "gitlab-ci-token",
        "CI_REGISTRY_PASSWORD": PASSWORD,
        "CAPTURE": str(capture),
    }
    return context, capture, environment


def invoke(job, **changes):
    _, _, environment = job
    return subprocess.run(["sh", str(SCRIPT)], env={**environment, **changes},
                          capture_output=True, text=True, timeout=10, check=False)


@pytest.mark.parametrize("tag", ["v1.2.3", "v1.2.3-rc.1", "release_2026-10-27", "a" * 128])
def test_publishes_exact_tag_and_commit_without_leaking_credentials(publishing_job, tag):
    context, capture, environment = publishing_job
    result = invoke(publishing_job, CI_COMMIT_TAG=tag)
    assert result.returncode == 0, result.stderr
    recorded = json.loads(capture.read_text())
    arguments = recorded["arguments"]
    output = next(csv.reader([arguments[arguments.index("--output") + 1]]))
    assert output == ["type=image", (f"name={environment['CI_REGISTRY_IMAGE']}:{tag},"
                                    f"{environment['CI_REGISTRY_IMAGE']}:sha-{SHA}"), "push=true"]
    assert "platform=linux/amd64" in arguments
    assert f"label:org.opencontainers.image.revision={SHA}" in arguments
    assert f"label:org.opencontainers.image.version={tag}" in arguments
    assert not any(":latest" in value for value in arguments)
    assert PASSWORD not in result.stdout + result.stderr + json.dumps(arguments)
    assert recorded["authenticated"]
    assert not Path(recorded["auth_directory"]).exists()
    assert json.loads((context / "build-metadata.json").read_text())["containerimage.digest"] == "sha256:" + "b" * 64
    assert set(context.iterdir()) == {context / "Dockerfile", context / "build-metadata.json"}


@pytest.mark.parametrize("tag", ["", "release/v1.2.3", ".hidden", "-option", "v1.2.3+metadata",
                                 "contains space", "$(touch unwanted)", "a" * 129])
def test_invalid_or_missing_tag_never_authenticates_or_invokes_builder(publishing_job, tag):
    _, capture, _ = publishing_job
    result = invoke(publishing_job, CI_COMMIT_TAG=tag)
    assert result.returncode != 0
    assert not capture.exists()
    assert PASSWORD not in result.stdout + result.stderr


@pytest.mark.parametrize("changes", [{"CI_COMMIT_SHA": "a" * 7}, {"CI_COMMIT_SHA": "g" * 40},
                                     {"CI_REGISTRY_PASSWORD": ""}, {"CI_REGISTRY_IMAGE": "elsewhere.invalid/repo"}])
def test_invalid_commit_or_registry_configuration_never_invokes_builder(publishing_job, changes):
    _, capture, _ = publishing_job
    result = invoke(publishing_job, **changes)
    assert result.returncode != 0
    assert not capture.exists()


def test_build_failure_stays_failed_and_private_auth_is_removed(publishing_job):
    _, capture, _ = publishing_job
    result = invoke(publishing_job, FAIL_BUILD="1")
    assert result.returncode == 17
    assert "Published" not in result.stdout
    assert PASSWORD not in result.stdout + result.stderr
    assert not Path(json.loads(capture.read_text())["auth_directory"]).exists()


def test_arm_runner_is_rejected_before_registry_authentication(publishing_job):
    _, capture, environment = publishing_job
    binaries = Path(environment["PATH"].split(os.pathsep)[0])
    uname = binaries / "uname"
    uname.write_text("#!/bin/sh\nprintf 'aarch64\\n'\n")
    uname.chmod(0o700)
    result = invoke(publishing_job)
    assert result.returncode != 0
    assert "native Linux amd64 runner" in result.stderr
    assert not capture.exists()


def test_pipeline_is_tag_only_with_pinned_rootless_builder_and_digest_artifact():
    config = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())
    assert config["workflow"]["rules"] == [{"if": "$CI_COMMIT_TAG"}, {"when": "never"}]
    job = config["build-image"]
    assert job["image"]["name"].startswith("moby/buildkit:v0.34.1-rootless@sha256:")
    assert len(job["image"]["name"].rsplit("sha256:", 1)[1]) == 64
    assert job["image"]["entrypoint"] == [""]
    assert "services" not in job
    assert job["script"] == ["sh .gitlab/build-image.sh"]
    assert job["artifacts"]["paths"] == ["build-metadata.json"]
    assert job["resource_group"] == "tagged-container-images"
    assert config["variables"]["IMAGE_RUNNER_TAG"] == "linux-amd64"
    assert job["tags"] == ["$IMAGE_RUNNER_TAG"]
    assert not job["interruptible"]
    assert stat.S_IMODE(SCRIPT.stat().st_mode) & stat.S_IXUSR

#!/usr/bin/env python3
"""Create a disposable MinIO fixture with private generated credentials and a deletion-denied role."""
import argparse
import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import boto3
import httpx

parser = argparse.ArgumentParser()
parser.add_argument("--binary", default="minio", help="MinIO binary built from tools/minio-fixture.lock.json")
parser.add_argument("--stop", action="store_true")
args = parser.parse_args()
root = Path(".runtime/minio")
root.mkdir(parents=True, exist_ok=True, mode=0o700)
os.umask(0o077)
if args.stop:
    if (root / "pid").exists():
        import signal
        os.kill(int((root / "pid").read_text()), signal.SIGTERM)
    raise SystemExit(0)
binary = shutil.which(args.binary)
if binary is None:
    raise SystemExit("Build the pinned MinIO source first; see tools/minio-fixture.lock.json and docs/TESTING.md.")
config_file = root / "credentials.json"
if config_file.exists():
    credentials = json.loads(config_file.read_text())
else:
    credentials = {"access_key": secrets.token_hex(12), "secret_key": secrets.token_urlsafe(48),
                   "endpoint": "http://127.0.0.1:19000"}
    config_file.write_text(json.dumps(credentials))
    config_file.chmod(0o600)
with httpx.Client(timeout=2, trust_env=False) as http:
    try:
        existing = http.get(credentials["endpoint"] + "/minio/health/ready").status_code == 200
    except httpx.HTTPError:
        existing = False
    if not existing:
        with (root / "server.log").open("ab") as log:
            process = subprocess.Popen([binary, "server", "--address", "127.0.0.1:19000", "--console-address",
                "127.0.0.1:19001", str((root / "data").resolve())],
                env={**os.environ, "MINIO_ROOT_USER": credentials["access_key"],
                     "MINIO_ROOT_PASSWORD": credentials["secret_key"]}, stdout=log, stderr=log,
                start_new_session=True)
        (root / "pid").write_text(str(process.pid))
        for attempt in range(60):
            try:
                if http.get(credentials["endpoint"] + "/minio/health/ready").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        else:
            raise SystemExit("Synthetic MinIO did not become ready; private diagnostics remain in .runtime/minio.")
common = {"endpoint_url": credentials["endpoint"], "region_name": "us-east-1",
          "aws_access_key_id": credentials["access_key"], "aws_secret_access_key": credentials["secret_key"]}
s3 = boto3.client("s3", **common)
if not any(bucket["Name"] == "vaultrewind-synthetic" for bucket in s3.list_buckets()["Buckets"]):
    s3.create_bucket(Bucket="vaultrewind-synthetic")
policy = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::vaultrewind-synthetic", "arn:aws:s3:::vaultrewind-synthetic/*"]},
    {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["arn:aws:s3:::vaultrewind-synthetic/*/snapshots/*"]}]}
restricted = boto3.client("sts", **common).assume_role(RoleArn="arn:aws:iam::123456789012:role/synthetic",
    RoleSessionName="vaultrewind-delete-denied", Policy=json.dumps(policy))["Credentials"]
file = root / "restricted.json"
file.write_text(json.dumps(restricted, default=str))
file.chmod(0o600)
print("Synthetic MinIO ready on loopback. Credentials are restricted to .runtime/minio; none were printed.")

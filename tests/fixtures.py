"""Synthetic application-shaped data, never owner data. Not a running Vaultwarden server."""
import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path


def synthetic_data(root: Path) -> sqlite3.Connection:
    root.mkdir(parents=True, mode=0o700)
    connection = sqlite3.connect(root / "db.sqlite3")
    connection.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA wal_autocheckpoint=0;
        CREATE TABLE users(uuid TEXT PRIMARY KEY, name TEXT);
        CREATE TABLE organizations(uuid TEXT PRIMARY KEY, name TEXT);
        CREATE TABLE ciphers(uuid TEXT PRIMARY KEY, user_uuid TEXT, data TEXT);
        CREATE TABLE attachments(id TEXT PRIMARY KEY, cipher_uuid TEXT, file_name TEXT);
        CREATE TABLE sends(uuid TEXT PRIMARY KEY, atype INTEGER, data TEXT, deletion_date TEXT);
        INSERT INTO users VALUES('user-one','Synthetic One'),('user-two','Synthetic Two');
        INSERT INTO organizations VALUES('org-one','Synthetic Organization');
        INSERT INTO ciphers VALUES('cipher-one','user-one','encrypted-placeholder-one'),
                                  ('cipher-two','user-two','encrypted-placeholder-two');
        INSERT INTO attachments VALUES('attachment-one','cipher-one','synthetic private file');
    """)
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    connection.execute("INSERT INTO sends VALUES(?,?,?,?)", ("send-one", 1, json.dumps({"Id": "file-one"}), future))
    connection.commit()
    for relative, content in {
        "attachments/cipher-one/attachment-one": b"synthetic attachment bytes\x00\xff",
        "sends/send-one/file-one": b"synthetic Send bytes",
        "rsa_key.pem": b"SYNTHETIC-NONKEY-PRIVATE-KEY",
        "rsa_key.pub.pem": b"SYNTHETIC-NONKEY-PUBLIC-KEY",
        "config.json": b'{"synthetic_secret":"fixture-only-not-a-real-secret"}',
        ".unknown-state": b"unknown regular persistent file",
        "nested/space and Unicode \u03bb.txt": b"unicode fixture",
    }.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (root / "empty directory").mkdir()
    (root / "internal-link").symlink_to(".unknown-state")
    os.link(root / ".unknown-state", root / "hardlink")
    (root / "attachments/cipher-one/attachment-one").chmod(0o600)
    (root / "config.json").chmod(0o600)
    if os.geteuid() == 0:
        os.chown(root / "nested/space and Unicode \u03bb.txt", 1234, 2345)
    return connection

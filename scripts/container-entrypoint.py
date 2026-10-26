#!/usr/bin/env python3
"""Read a mounted password privately and replace this process with the requested role."""
import os
import sys
from pathlib import Path
from urllib.parse import quote

if "VAULTREWIND_DATABASE_URL" not in os.environ:
    path = Path(os.environ.get("VAULTREWIND_DATABASE_PASSWORD_FILE", "/run/secrets/database_password"))
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise SystemExit("The database password file must be a protected regular file")
    password = path.read_text().strip()
    os.environ["VAULTREWIND_DATABASE_URL"] = "postgresql+psycopg://vaultrewind:" + quote(password, safe="") + "@db:5432/vaultrewind"
os.umask(0o077)
os.execvp(sys.argv[1], sys.argv[1:])

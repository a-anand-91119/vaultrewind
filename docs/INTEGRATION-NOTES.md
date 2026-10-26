# Live integration coordination

Parent integration environment is ready: `.venv` via uv, real restic 0.19.1, rclone 1.75.2, Docker 26.1.5, PostgreSQL 17 at localhost:5432. Core exports are re-exported from core/__init__.py.

Real core and Vaultwarden saved-image pipeline evidence are in docs/evidence/core-roundtrip.json and application-roundtrip.json. Frontend now lives in frontend/; API should serve frontend/dist/ when present, same origin. Cookie vr_csrf and routes from docs/API-CONTRACT.md are implemented.

MinIO fixture is running on http://127.0.0.1:19000; credentials are private at .runtime/minio/credentials.json. Bucket vaultrewind-synthetic exists. Never print those credentials. MinIO was built from official pinned source release RELEASE.2025-10-15T17-29-55Z because public binary/container downloads are unavailable.

A real bootable QEMU Debian 13 fixture is being prepared at .runtime/vm; SSH loopback port 22229, private generated key and scanned known_hosts there. Root is supervising. Do not reboot controller environment.

No dedicated Drive credentials yet; optional user question pending. Report live verification as blocked unless authorized real test flow completes.

Parent later restarted native API/worker against current code after explicitly upgrading ONLY its generated fixture legacy-secret rows to bound AAD (same master, no plaintext persisted). Production schema/rolling-upgrade handling still belongs to server implementation. New source/helper fencing floor surfaced by provisioning.py is useful; don't reset any real fences.

Frontend source onboarding now uses HostOnboarding and /jobs/{id}/enrollment proposals, then activation preview/confirm and operational discovery/enrollment without JSON entry. Existing root-policy preservation and stable remote IDs must hold when adding another instance; do not replace other enrolled instance policies or assign new IDs to existing container/resources on each discovery. UI needs a prepared-empty-alternate target form and safe image ID in snapshot detail. Policy-change preview needs hypothetical retention_days input (current Empty schema cannot preview changes before saving). Doctor readout and retention preview are now human-readable. First Playwright test strengthened to check first post-login fleet HTTP200 to catch response-before-commit auth race.

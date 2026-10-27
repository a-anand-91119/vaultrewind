# Dependencies and primary references

Versions were resolved from official registries on 2026-10-25. `uv.lock` pins the Python dependency graph and hashes; `frontend/package-lock.json` pins npm packages. `tools/images.lock.json` records resolved controller/build image digests. `tools/binaries.lock.json` records the official restic/rclone release asset hashes checked by `tools/install_binaries.py`.

Tag CI adds Linux arm64 archives alongside the unchanged amd64 pins. Official
release API digests pin restic arm64 to `a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465`
and rclone arm64 to `7e1e8d69654941b7b7df84ee74c5f7fb09cce7d5496947fb7bf16b55ff427d10`.
The installer checks archive hashes and executable ELF architecture. The pinned
Python/Node/PostgreSQL indexes contain both architectures. Native-builder `uv`
installs target wheels with source builds disabled, followed by ELF checks and
unprivileged runtime smoke checks. See [GitLab CI](GITLAB-CI.md). Earlier build and
application acceptance reports remain bound to their historical inputs/images.

Test host: Debian 13, Python 3.13.5, PostgreSQL 17.11, Docker Engine 26.1.5. Application fixture: Vaultwarden 1.37.4 at registry digest `sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`; local image ID and archive hash are separate evidence fields. MinIO fixture uses an official source build of release `RELEASE.2025-10-15T17-29-55Z`, built with checksum-verified Go 1.27.3 because old public image/binary download endpoints are unavailable. This fixture is not a production MinIO recommendation or a bundled storage service.

Primary implementation references:

- [SQLite online backup API](https://www.sqlite.org/backup.html): staged normalization.
- [Vaultwarden backup guidance](https://github.com/dani-garcia/vaultwarden/wiki/Backing-up-your-vault): persistent instance boundary.
- [Vaultwarden pinned source](https://github.com/dani-garcia/vaultwarden/tree/1.37.4): attachment and Send schema semantics.
- [restic preparation](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html), [backup](https://restic.readthedocs.io/en/stable/040_backup.html), [restore](https://restic.readthedocs.io/en/stable/050_restore.html), [verification](https://restic.readthedocs.io/en/stable/045_working_with_repos.html) and [forget/prune](https://restic.readthedocs.io/en/stable/060_forget.html).
- [rclone Drive](https://rclone.org/drive/) and [restic bridge](https://rclone.org/commands/rclone_serve_restic/).
- [AsyncSSH](https://asyncssh.readthedocs.io/en/latest/), [FastAPI containers](https://fastapi.tiangolo.com/deployment/docker/), [SQLAlchemy](https://docs.sqlalchemy.org/).
- [React](https://react.dev/learn), [Vite](https://vite.dev/guide/), [Docker isolated networking](https://docs.docker.com/engine/network/drivers/none/).
- [MinIO pinned release source-build instructions](https://github.com/minio/minio/releases/tag/RELEASE.2025-10-15T17-29-55Z).

Context7 tools were not exposed in this session; official project documentation/registries were used directly.

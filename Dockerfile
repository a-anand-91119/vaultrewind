FROM --platform=$BUILDPLATFORM node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS frontend
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM postgres:17-bookworm@sha256:858bb5e98eed02eb8cafbcdc007f9a65d1b613972028944a8ec2133ccaf80d27 AS pgtools

# Keep uv native to the builder; install wheels for the requested target CPU.
FROM --platform=$BUILDPLATFORM python:3.13-slim-bookworm@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530 AS dependencies
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_PYTHON_DOWNLOADS=never
RUN pip install --no-cache-dir uv==0.13.5
WORKDIR /app
ARG TARGETARCH
COPY tools/ tools/
RUN python tools/install_binaries.py /opt/target-tools --arch "$TARGETARCH"
COPY pyproject.toml uv.lock ./
COPY src/ src/
RUN case "$TARGETARCH" in \
      amd64) target_python_platform=x86_64-unknown-linux-gnu ;; \
      arm64) target_python_platform=aarch64-unknown-linux-gnu ;; \
      *) exit 1 ;; \
    esac \
    && uv sync --frozen --no-dev --no-build --python-platform "$target_python_platform" \
    && python tools/check_image.py --environment /app/.venv --arch "$TARGETARCH"

FROM python:3.13-slim-bookworm@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/app/.venv/bin:$PATH" \
    VAULTREWIND_FRONTEND_DIR=/app/frontend/dist RESTIC_CACHE_DIR=/var/lib/vaultrewind/cache/restic
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssh-client libpq5 liblz4-1 libzstd1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 vaultrewind && useradd -u 10001 -g 10001 -M vaultrewind
WORKDIR /app
COPY --from=pgtools /usr/lib/postgresql/17/bin/pg_dump /usr/local/bin/pg_dump
COPY --from=pgtools /usr/lib/postgresql/17/bin/pg_restore /usr/local/bin/pg_restore
RUN pg_dump --version && pg_restore --version
COPY --from=dependencies /opt/target-tools/ /usr/local/bin/
COPY pyproject.toml uv.lock ./
COPY src/ src/
COPY --from=dependencies /app/.venv/ /app/.venv/
COPY migrations/ migrations/
COPY alembic.ini ./
COPY scripts/container-entrypoint.py scripts/container-entrypoint.py
COPY helper/ helper/
RUN python helper/build_bundle.py /app/helper-bundle \
    && mkdir -p /var/lib/vaultrewind/backups /var/lib/vaultrewind/staging /var/lib/vaultrewind/cache /var/lib/vaultrewind/provider-credentials \
    && chown -R 10001:10001 /var/lib/vaultrewind
COPY --from=frontend /ui/dist/ /app/frontend/dist/
COPY tools/check_image.py tools/check_image.py
USER 10001:10001
RUN python tools/check_image.py && restic version && rclone version && vaultrewind --help >/dev/null
EXPOSE 8080
ENTRYPOINT ["python", "/app/scripts/container-entrypoint.py"]
CMD ["uvicorn", "vaultrewind.server.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]

# GitLab tag image builds

[`.gitlab-ci.yml`](../.gitlab-ci.yml) builds the existing multi-stage Dockerfile
and publishes to this project's GitLab Container Registry whenever a Git tag is
pushed. Branch and merge-request pushes do not publish images or create this
pipeline. The explicit configuration replaces GitLab's implicit Auto DevOps
pipeline; its old branch images remain untouched. There is no deployment job.

The job uses checksum-pinned **BuildKit 0.34.1 rootless**, GitLab's short-lived
`CI_REGISTRY_USER` / `CI_REGISTRY_PASSWORD`, and the predefined registry address.
No personal access token or manually configured registry password is required.
The registry must be enabled and a native Linux amd64 Docker/Kubernetes runner
must be available with the **`linux-amd64` runner tag**. Set the project CI/CD
variable **`IMAGE_RUNNER_TAG`** to a different existing runner tag if needed.
The runner must allow the user namespaces/mount operations required
by rootless BuildKit. A plain shell executor without BuildKit is unsupported.
No runner or host security policy is changed by the pipeline.

## Publish a version

Create a new tag on a commit containing the CI configuration, then push that
specific tag:

```sh
git tag -a v0.1.0-rc.3 -m "VaultRewind 0.1.0 release candidate 3"
git push origin refs/tags/v0.1.0-rc.3
```

The tag must be a valid Docker tag: 1–128 letters, digits, underscores, dots or
hyphens, without a leading dot or hyphen. Tags containing slashes, whitespace or
SemVer `+build` metadata fail before registry authentication. Keep published tags
at their reviewed commits; do not move or force-push old release tags. The older
local `v0.1.0-rc.1` checkpoint predates the CI configuration and is preserved.

For tag `v0.1.0-rc.3`, the job publishes:

```text
registry.gitlab.notyouraverage.dev/a.anand.91119/vaultrewind:v0.1.0-rc.3
registry.gitlab.notyouraverage.dev/a.anand.91119/vaultrewind:sha-<full-commit-id>
```

The exact Git tag is retained. There is no automatic `latest` promotion or
version-prefix stripping. Builds target **linux/amd64**, matching the supported
controller and pinned restic/rclone binaries. Both the runner tag and an early
architecture check require native amd64; unsupported emulation is rejected.
Images carry OCI source, revision and version labels. Registry tags identify
builds; use the published digest for immutable deployment references. Rebuilding
the same commit can produce a different digest as external package repositories
change.

The job's `build-metadata.json` artifact records the resulting image digest and
is retained for one year. The shared BuildKit cache lives separately at
`$CI_REGISTRY_IMAGE/buildcache:amd64`; release jobs are serialized to avoid cache
export races. Cache is disposable and contains no application runtime data.

## Credentials and build context

The [publishing script](../.gitlab/build-image.sh) writes registry authentication
to an ephemeral mode-0700 temporary directory, with a mode-0600 config outside
the Docker context. It removes that directory on success or failure. Passwords
are not command arguments or build arguments and are not printed. Keep CI debug
tracing off. No application secrets, SSH credentials or Google account data are
needed for image builds.

[`.dockerignore`](../.dockerignore) excludes local runtime data, `.secrets`,
`.env` and its variants, private helper bundles and CI metadata. Only the
nonsecret `.env.example` is exempted. Do not upload these excluded files as job
artifacts or add runtime secrets to Docker build arguments.

## Verify and operate

Inspect **Build → Pipelines** for the tag and **Deploy → Container Registry**
for the two image tags. A successful job publishes the image and digest artifact;
it does not establish application backup/restore acceptance for a new release.
Existing synthetic acceptance reports remain bound to their saved commits and
images.

The focused local checks exercise tag validation, exact image destinations,
platform/metadata selection, temporary authentication permissions, cleanup and
failure propagation without contacting a registry:

```sh
sh -n .gitlab/build-image.sh
.venv/bin/python -m pytest tests/unit/test_gitlab_ci.py -q
.venv/bin/ruff check tests/unit/test_gitlab_ci.py
```

If a job is stuck, check that an online native Linux amd64 runner has the tag
selected by `IMAGE_RUNNER_TAG` and is eligible for the Git tag's protection level. Rootless
namespace/mount errors require the runner administrator to review its policy;
do not disable TLS or grant broader host access to hide errors. Registry 401/403
errors require checking the project's registry and job-token permissions. A
missing first-run cache is expected; release images are separate from that cache.

Primary references: [GitLab BuildKit configuration](https://docs.gitlab.com/ci/docker/using_buildkit/),
[registry authentication](https://docs.gitlab.com/user/packages/container_registry/authenticate_with_container_registry/),
[tag workflow rules](https://docs.gitlab.com/ci/yaml/workflow/) and
[the pinned BuildKit release](https://github.com/moby/buildkit/releases/tag/v0.34.1).

## First live attempt

The first real tag pipeline, [4369](https://gitlab.notyouraverage.dev/a.anand.91119/vaultrewind/-/pipelines/4369)
for `v0.1.0-rc.2`, accepted the configuration but was assigned to the ARM64 MacBook
runner. The amd64 build reached `uv sync --frozen --no-dev`, which crashed under
emulation with exit 139. No release image was published. That failed pipeline/tag
is retained; the subsequent configuration selects a native amd64 runner and
fails before authentication if its architecture is wrong. Runner selection is
required before claiming a successful GitLab image build.

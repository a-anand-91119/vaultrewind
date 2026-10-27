#!/bin/sh
# CI job-token authentication stays outside the Docker build context.
set -eu

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

[ -n "${CI_COMMIT_TAG:-}" ] || fail 'Image publication requires a Git tag.'
case "$CI_COMMIT_TAG" in
    [.-]*|*[!a-zA-Z0-9_.-]*) fail 'Git tag must be a valid Docker tag: letters, digits, underscores, dots and hyphens; no leading dot or hyphen.' ;;
esac
[ "${#CI_COMMIT_TAG}" -le 128 ] || fail 'Docker image tags cannot exceed 128 characters.'

: "${CI_COMMIT_SHA:?GitLab must provide CI_COMMIT_SHA}"
case "$CI_COMMIT_SHA" in
    *[!a-f0-9]*) fail 'CI_COMMIT_SHA must be a full lowercase hexadecimal Git commit ID.' ;;
esac
case "${#CI_COMMIT_SHA}" in
    40|64) ;;
    *) fail 'CI_COMMIT_SHA must be a full Git commit ID.' ;;
esac

: "${CI_PROJECT_DIR:?GitLab must provide CI_PROJECT_DIR}"
: "${CI_PROJECT_URL:?GitLab must provide CI_PROJECT_URL}"
: "${CI_REGISTRY:?Enable the GitLab Container Registry for this project}"
: "${CI_REGISTRY_IMAGE:?Enable the GitLab Container Registry for this project}"
: "${CI_REGISTRY_USER:?GitLab must provide CI_REGISTRY_USER}"
: "${CI_REGISTRY_PASSWORD:?GitLab must provide CI_REGISTRY_PASSWORD}"
case "$CI_REGISTRY_IMAGE" in
    "$CI_REGISTRY"/*) ;;
    *) fail 'The image destination must belong to this GitLab registry.' ;;
esac
[ -f "$CI_PROJECT_DIR/Dockerfile" ] || fail 'The tagged commit must contain the project Dockerfile.'
command -v buildctl-daemonless.sh >/dev/null 2>&1 || fail 'This job requires the pinned BuildKit job image.'

umask 077
ci_auth_directory=$(mktemp -d)
trap 'rm -rf "$ci_auth_directory"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export DOCKER_CONFIG="$ci_auth_directory"
registry_auth=$(printf '%s:%s' "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" | base64 | tr -d '\n')
printf '{"auths":{"%s":{"auth":"%s"}}}\n' "$CI_REGISTRY" "$registry_auth" > "$DOCKER_CONFIG/config.json"
unset registry_auth

version_image="$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG"
commit_image="$CI_REGISTRY_IMAGE:sha-$CI_COMMIT_SHA"
cache_image="$CI_REGISTRY_IMAGE/buildcache:amd64"

# Export both names together. The quoted CSV field is required for multiple names.
# Registry credentials are not build arguments and are never inside the context.
buildctl-daemonless.sh build \
    --frontend dockerfile.v0 \
    --local "context=$CI_PROJECT_DIR" \
    --local "dockerfile=$CI_PROJECT_DIR" \
    --opt platform=linux/amd64 \
    --opt "label:org.opencontainers.image.source=$CI_PROJECT_URL" \
    --opt "label:org.opencontainers.image.revision=$CI_COMMIT_SHA" \
    --opt "label:org.opencontainers.image.version=$CI_COMMIT_TAG" \
    --import-cache "type=registry,ref=$cache_image" \
    --export-cache "type=registry,ref=$cache_image,mode=max,image-manifest=true" \
    --metadata-file "$CI_PROJECT_DIR/build-metadata.json" \
    --output "type=image,\"name=$version_image,$commit_image\",push=true"

printf 'Published %s and %s\n' "$version_image" "$commit_image"

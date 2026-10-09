#!/usr/bin/env bash
set -euo pipefail

# Uses the current Docker login and buildx builder; never changes credentials.
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="docker.io/wxyin/right-codex"
TAG="$(date -u +%Y%m%dT%H%M%SZ)"
BUILDER=""

usage() {
  cat <<'EOF'
Usage: scripts/publish-runtime-images.sh [options]

Build and push linux/amd64 + linux/arm64 images to Docker Hub.
Publishes both latest and a UTC timestamp tag, then verifies both platforms.
Run docker login before publishing. The active buildx builder is used by default.

Options:
  --image NAME     Image repository (default: docker.io/wxyin/right-codex)
  --tag TAG        Release tag (default: current UTC, e.g. 20261010T120000Z)
  --builder NAME   Existing buildx builder to use
  -h, --help      Show this help
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --image|--tag|--builder)
      (($# >= 2)) && [[ -n "$2" && "$2" != --* ]] || die "$1 requires a value"
      case "$1" in
        --image) IMAGE="$2" ;;
        --tag) TAG="$2" ;;
        --builder) BUILDER="$2" ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ "$TAG" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$ ]] || die "Invalid release tag"
[[ "$TAG" != latest ]] || die "Release tag must differ from latest"
[[ "$IMAGE" != *[@[:space:]]* && "$IMAGE" != *://* && "$IMAGE" != -* ]] || die "Use an image repository without a tag or digest"
[[ "${IMAGE##*/}" != *:* && "$IMAGE" == */* && "$IMAGE" != */ ]] || die "Use a namespaced image repository without a tag"
command -v docker >/dev/null 2>&1 || die "Docker is required"
docker buildx version >/dev/null

BUILD_OPTIONS=()
if [[ -n "$BUILDER" ]]; then
  BUILD_OPTIONS+=(--builder "$BUILDER")
  docker buildx inspect "$BUILDER" --bootstrap >/dev/null
else
  docker buildx inspect --bootstrap >/dev/null
fi

CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LABELS=(
  --label "org.opencontainers.image.source=https://github.com/1198722360/right-codex"
  --label "org.opencontainers.image.title=right-codex"
  --label "org.opencontainers.image.created=$CREATED"
  --label "org.opencontainers.image.version=$TAG"
)
if command -v git >/dev/null 2>&1 && REVISION="$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null)"; then
  LABELS+=(--label "org.opencontainers.image.revision=$REVISION")
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/right-codex-publish.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT

printf 'Publishing %s:%s and %s:latest (linux/amd64, linux/arm64)\n' "$IMAGE" "$TAG" "$IMAGE"
docker buildx build \
  ${BUILD_OPTIONS[@]+"${BUILD_OPTIONS[@]}"} \
  --platform linux/amd64,linux/arm64 \
  --file "$ROOT/Dockerfile" \
  --tag "$IMAGE:$TAG" \
  --tag "$IMAGE:latest" \
  "${LABELS[@]}" \
  --metadata-file "$TEMP_DIR/build-metadata.json" \
  --push "$ROOT"

# Inspect the published index, then pin subsequent checks to its digest.
docker buildx imagetools inspect "$IMAGE:$TAG" > "$TEMP_DIR/release-inspect.txt"
DIGEST="$(awk '$1 == "Digest:" {print $2; exit}' "$TEMP_DIR/release-inspect.txt")"
[[ "$DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || die "Published release did not return an index digest"
docker buildx imagetools inspect "$IMAGE@$DIGEST" \
  --format '{{range .Manifest.Manifests}}{{printf "%s/%s\n" .Platform.OS .Platform.Architecture}}{{end}}' \
  > "$TEMP_DIR/platforms.txt"
for PLATFORM in linux/amd64 linux/arm64; do
  grep -Fxq "$PLATFORM" "$TEMP_DIR/platforms.txt" || die "Published index is missing $PLATFORM"
done
docker buildx imagetools inspect "$IMAGE:latest" > "$TEMP_DIR/latest-inspect.txt"
LATEST_DIGEST="$(awk '$1 == "Digest:" {print $2; exit}' "$TEMP_DIR/latest-inspect.txt")"
[[ "$LATEST_DIGEST" == "$DIGEST" ]] || die "latest differs from the release digest; check for concurrent publishing"

printf 'Published and verified:\n  %s:%s\n  %s:latest\n  Index: %s\n  Platforms: linux/amd64, linux/arm64\n' "$IMAGE" "$TAG" "$IMAGE" "$DIGEST"

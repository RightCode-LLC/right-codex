#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
test -f config.json || { echo 'Copy deploy/config.container.example.json to config.json first. / 请先按容器示例创建配置。' >&2; exit 1; }
mkdir -p state
chmod 700 state
# The image runs as UID 10001. This command only changes the dedicated state dir.
if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" != 0 ]; then sudo chown 10001:10001 state; else chown 10001:10001 state; fi
docker compose pull
docker compose up -d --remove-orphans

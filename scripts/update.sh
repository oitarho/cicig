#!/usr/bin/env bash
set -Eeuo pipefail
cd "${CICIG_DIR:-/opt/cicig}"
mkdir -p backups
docker compose config >"backups/compose-$(date +%Y%m%d-%H%M%S).yaml"
docker compose pull caddy wg-easy awg-easy
docker compose up -d --build
docker image prune -f

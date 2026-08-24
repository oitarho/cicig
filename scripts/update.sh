#!/usr/bin/env bash
set -Eeuo pipefail
cd "${CICIG_DIR:-/opt/cicig}"
mkdir -p backups
docker compose config >"backups/compose-$(date +%Y%m%d-%H%M%S).yaml"
docker compose pull
docker compose up -d
docker image prune -f


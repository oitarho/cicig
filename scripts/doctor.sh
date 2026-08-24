#!/usr/bin/env bash
set -Eeuo pipefail
cd "${CICIG_DIR:-/opt/cicig}"
docker compose config --quiet
docker compose ps
printf '\nDNS:\n'
# Runtime configuration is created by install.sh.
# shellcheck disable=SC1091
. ./.env
getent ahostsv4 "$VPN_DOMAIN" | awk '$2 == "STREAM" {print "  VPN " $1; exit}'
getent ahostsv4 "$PANEL_DOMAIN" | awk '$2 == "STREAM" {print "  WEB " $1; exit}'
printf '\nListening ports:\n'
ss -lntup | grep -E ':(80|443|51820)\b' || true

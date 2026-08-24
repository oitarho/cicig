#!/usr/bin/env bash
set -Eeuo pipefail
cd "${CICIG_DIR:-/opt/cicig}"
docker compose config --quiet
docker compose ps
printf '\nDNS:\n'
. ./.env
getent ahostsv4 "$WG_DOMAIN" | awk '$2 == "STREAM" {print "  WG  " $1; exit}'
getent ahostsv4 "$AWG_DOMAIN" | awk '$2 == "STREAM" {print "  AWG " $1; exit}'
printf '\nListening ports:\n'
ss -lntup | grep -E ':(80|443|51820)\b' || true


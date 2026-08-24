#!/bin/sh
set -eu

PROJECT_DIR=${CICIG_PROJECT_DIR:-/opt/cicig}
ARCHIVE_URL=${CICIG_ARCHIVE_URL:-https://github.com/oitarho/cicig/archive/refs/heads/main.tar.gz}
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

cd "$PROJECT_DIR"
mkdir -p backups
docker compose config >"backups/compose-before-update-$(date +%Y%m%d-%H%M%S).yaml"
AWG_BACKUP="$TEMP_DIR/awg-wireguard"
AWG_CONTAINER=$(docker compose ps -q awg-easy 2>/dev/null || true)
if [ -n "$AWG_CONTAINER" ]; then
  mkdir -p "$AWG_BACKUP"
  docker cp "$AWG_CONTAINER:/etc/wireguard/." "$AWG_BACKUP/" 2>/dev/null || true
fi

echo "Загрузка новой версии cicig…"
wget -qO "$TEMP_DIR/cicig.tar.gz" "$ARCHIVE_URL"
mkdir -p "$TEMP_DIR/source"
tar -xzf "$TEMP_DIR/cicig.tar.gz" --strip-components=1 -C "$TEMP_DIR/source"

# В архиве нет .env и VPN-данных, поэтому настройки и ключи сохраняются.
cp -a "$TEMP_DIR/source/." "$PROJECT_DIR/"
cd "$PROJECT_DIR"

echo "Проверка конфигурации…"
docker compose config --quiet
echo "Загрузка контейнеров…"
docker compose pull
echo "Пересборка и запуск всей системы…"
docker compose up -d --build --remove-orphans
if [ -d "$AWG_BACKUP" ] && [ "$(find "$AWG_BACKUP" -mindepth 1 -print -quit)" ]; then
  AWG_CONTAINER=$(docker compose ps -q awg-easy)
  docker cp "$AWG_BACKUP/." "$AWG_CONTAINER:/etc/wireguard/"
  docker compose restart awg-easy
fi
echo "cicig успешно обновлён."

#!/bin/sh
set -eu

PROJECT_DIR=${CICIG_PROJECT_DIR:-/opt/cicig}
ARCHIVE_URL=${CICIG_ARCHIVE_URL:-https://github.com/oitarho/cicig/archive/refs/heads/main.tar.gz}
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

cd "$PROJECT_DIR"
mkdir -p backups
docker compose config >"backups/compose-before-update-$(date +%Y%m%d-%H%M%S).yaml"

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
echo "cicig успешно обновлён."

#!/bin/sh
set -eu

PROJECT_DIR=${CICIG_PROJECT_DIR:-/opt/cicig}
CONTROL_DIR=${CICIG_CONTROL_DIR:-$PROJECT_DIR/control}
ARCHIVE_URL=${CICIG_ARCHIVE_URL:-https://github.com/oitarho/cicig/archive/refs/heads/main.tar.gz}
TEMP_DIR=$(mktemp -d)
UPDATE_STATUS_FILE="$CONTROL_DIR/update-status.json"
UPDATE_SUCCEEDED=0

write_status() {
  state=$1
  message=$2
  timestamp=$(date -u '+%d.%m.%Y %H:%M UTC')
  temporary="$UPDATE_STATUS_FILE.tmp"
  mkdir -p "$CONTROL_DIR"
  printf '{"state":"%s","message":"%s","updated_at":"%s"}\n' \
    "$state" "$message" "$timestamp" >"$temporary"
  mv "$temporary" "$UPDATE_STATUS_FILE"
}

cleanup() {
  code=$?
  rm -rf "$TEMP_DIR"
  if [ "$UPDATE_SUCCEEDED" -eq 0 ]; then
    write_status failed "Патч не применился. Проверьте журнал cicig-updater."
  fi
  exit "$code"
}
trap cleanup EXIT INT TERM

write_status running "Кот скачивает и проверяет свежий патч."

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
docker compose pull caddy
docker compose build --pull
echo "Пересборка и запуск всей системы…"
docker compose up -d --build --remove-orphans
if [ -d "$AWG_BACKUP" ] && [ "$(find "$AWG_BACKUP" -mindepth 1 -print -quit)" ]; then
  AWG_CONTAINER=$(docker compose ps -q awg-easy)
  docker cp "$AWG_BACKUP/." "$AWG_CONTAINER:/etc/wireguard/"
  docker compose restart awg-easy
fi
echo "cicig успешно обновлён."
UPDATE_SUCCEEDED=1
write_status success "Патч установлен. Контейнеры вернулись в строй."

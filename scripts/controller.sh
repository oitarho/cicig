#!/bin/sh
set -eu

PROJECT_DIR=${CICIG_PROJECT_DIR:-/opt/cicig}
CONTROL_DIR=${CICIG_CONTROL_DIR:-/control}
STATUS_FILE="$CONTROL_DIR/status.json"
REQUEST_FILE="$CONTROL_DIR/update.request"
UPDATE_STATUS_FILE="$CONTROL_DIR/update-status.json"

mkdir -p "$CONTROL_DIR"

update_status() {
  state=$1
  message=$2
  timestamp=$(date -u '+%d.%m.%Y %H:%M UTC')
  temporary="$UPDATE_STATUS_FILE.tmp"
  printf '{"state":"%s","message":"%s","updated_at":"%s"}\n' \
    "$state" "$message" "$timestamp" >"$temporary"
  mv "$temporary" "$UPDATE_STATUS_FILE"
}

container_status() {
  service=$1
  container_id=$(docker compose -f "$PROJECT_DIR/docker-compose.yml" --project-directory "$PROJECT_DIR" ps -q "$service" 2>/dev/null || true)
  if [ -z "$container_id" ]; then
    printf '{"state":"","image":"неизвестен","health":"none","restarts":0}'
    return
  fi
  docker inspect --format \
    '{"state":{{json .State.Status}},"image":{{json .Config.Image}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"none"{{end}},"restarts":{{.RestartCount}}}' \
    "$container_id" 2>/dev/null || \
    printf '{"state":"","image":"неизвестен","health":"none","restarts":0}'
}

write_status() {
  temporary="$STATUS_FILE.tmp"
  {
    printf '{"wg-easy":'
    container_status wg-easy
    printf ',"awg-easy":'
    container_status awg-easy
    printf '}\n'
  } >"$temporary"
  mv "$temporary" "$STATUS_FILE"
}

queue_update() {
  if docker ps -q --filter 'name=^/cicig-updater$' | grep -q .; then
    update_status running "Кот уже тащит патч. Второй хвост не нужен."
    return
  fi

  rm -f "$REQUEST_FILE"
  update_status queued "Запрос принят. Изолированный контроллер запускает обновление."
  if ! docker run --detach --rm --name cicig-updater \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PROJECT_DIR:$PROJECT_DIR" \
    -v "$PROJECT_DIR/control:$CONTROL_DIR" \
    -e "CICIG_PROJECT_DIR=$PROJECT_DIR" \
    -e "CICIG_CONTROL_DIR=$CONTROL_DIR" \
    docker:29-cli sh "$PROJECT_DIR/scripts/update.sh" >/dev/null; then
    update_status failed "Контроллер не смог запустить обновление."
  fi
}

while true; do
  write_status
  if [ -f "$REQUEST_FILE" ]; then
    queue_update
  fi
  sleep 10
done

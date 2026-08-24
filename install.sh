#!/usr/bin/env bash
set -Eeuo pipefail

readonly CICIG_DIR="/opt/cicig"
readonly ARCHIVE_URL="${CICIG_ARCHIVE_URL:-https://github.com/oitarho/cicig/archive/refs/heads/main.tar.gz}"

red='\033[0;31m'; green='\033[0;32m'; amber='\033[0;33m'; cyan='\033[0;36m'; reset='\033[0m'
say() { printf '%b\n' "$*"; }
die() { say "${red}Ошибка:${reset} $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Нужна команда '$1'."; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Запустите установщик через sudo."
need curl
need getent
need tar
need openssl

tty=/dev/tty
[[ -r "$tty" && -w "$tty" ]] || die "Нужен интерактивный терминал."

prompt() {
  local label=$1 default=${2:-} answer
  if [[ -n $default ]]; then
    read -r -p "$label [$default]: " answer <"$tty"
    printf '%s' "${answer:-$default}"
  else
    read -r -p "$label: " answer <"$tty"
    printf '%s' "$answer"
  fi
}

valid_domain() {
  [[ $1 =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]
}

public_ipv4() {
  local url ip
  for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip=$(curl -4fsS --max-time 8 "$url" 2>/dev/null | tr -d '[:space:]') || continue
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { printf '%s' "$ip"; return; }
  done
  return 1
}

resolve_a() {
  getent ahostsv4 "$1" 2>/dev/null | awk '$2 == "STREAM" {print $1}' | sort -u
}

dns_gate() {
  local expected=$1 panel_domain=$2 found answer attempt=0

  say "\n${cyan}Сначала создайте одну DNS-запись типа A (IPv4)${reset}"
  say "В терминал сейчас ничего вводить не нужно. Откройте в браузере сайт,"
  say "на котором вы управляете своим доменом, и найдите раздел DNS."
  say "\nСоздайте DNS-запись:"
  say "  Тип записи:       A"
  say "  Имя / Host:       panel"
  say "  IPv4 / Значение:  $expected"
  say "  Результат:         $panel_domain → $expected"
  say "\nЕсли ваш домен находится в Cloudflare:"
  say "  1. Откройте DNS → Records → Add record."
  say "  2. Выберите Type: A."
  say "  3. Заполните Name и IPv4 address значениями выше."
  say "  4. Выключите Proxy status. Должно быть серое облако ${amber}DNS only${reset}."
  say "  5. Нажмите Save."
  say "\nОдин домен будет использоваться для панели и обоих VPN-протоколов."

  while true; do
    read -r -p "Нажмите Enter для проверки DNS (или введите q для выхода): " answer <"$tty"
    [[ ${answer,,} == q ]] && exit 0
    attempt=$((attempt + 1))

    say "\nПроверка DNS-записей типа A (IPv4) №$attempt:"
    found=$(resolve_a "$panel_domain" | paste -sd, -)
    if [[ ,$found, == *,$expected,* ]]; then
      say "  ${green}✓ A-запись:${reset} $panel_domain → $expected — правильно"
      say "\n${green}DNS настроен правильно.${reset}"
      return
    else
      say "  ${red}✗ A-запись:${reset} $panel_domain → ${found:-запись не найдена}"
      say "                 Нужно: $expected"
    fi
    say "\n${amber}Пока A-запись неверна, установка не начнётся.${reset}"
    say "Исправьте запись и запустите проверку ещё раз."
  done
}

bcrypt() {
  local password=$1
  printf '%s\n' "$password" | htpasswd -niBC 12 '' 2>/dev/null | tr -d ':\n' | sed 's/\$/$$/g'
}

say "${cyan}cicig — WireGuard + AmneziaWG${reset}"
base_domain=$(prompt "Ваш основной домен (например, mydomain.com)")
base_domain=${base_domain,,}
base_domain=${base_domain%.}
valid_domain "$base_domain" || die "Некорректный домен: $base_domain"
panel_domain="panel.$base_domain"
say "Будет настроен единый адрес: $panel_domain"
email=$(prompt "Email для TLS" "admin@$base_domain")
server_ip=$(public_ipv4) || die "Не удалось определить публичный IPv4."
say "Публичный IPv4 сервера: ${green}$server_ip${reset}"

# Hard gate: no package installation or system mutation happens before DNS succeeds.
dns_gate "$server_ip" "$panel_domain"
say "${green}DNS проверен. Начинаю установку.${reset}"

if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose plugin не найден."
if ! command -v htpasswd >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apache2-utils
fi

read -r -s -p "Пароль администратора панелей: " admin_password <"$tty"; printf '\n' >"$tty"
[[ ${#admin_password} -ge 12 ]] || die "Пароль должен содержать минимум 12 символов."
read -r -s -p "Повторите пароль: " admin_password_2 <"$tty"; printf '\n' >"$tty"
[[ $admin_password == "$admin_password_2" ]] || die "Пароли не совпадают."

install -d -m 700 "$CICIG_DIR"
curl -fsSL "$ARCHIVE_URL" | tar -xz --strip-components=1 -C "$CICIG_DIR"

wg_hash=$(bcrypt "$admin_password")
awg_hash=$wg_hash
panel_hash=$wg_hash
panel_secret=$(openssl rand -hex 32)
unset admin_password admin_password_2
umask 077
cat >"$CICIG_DIR/.env" <<EOF
PANEL_DOMAIN=$panel_domain
LETSENCRYPT_EMAIL=$email
WG_PORT=51820
AWG_PORT=443
WG_PASSWORD_HASH=$wg_hash
AWG_PASSWORD_HASH=$awg_hash
PANEL_PASSWORD_HASH=$panel_hash
PANEL_SECRET_KEY=$panel_secret
EOF

cd "$CICIG_DIR"
docker compose config --quiet
docker compose pull caddy wg-easy awg-easy
docker compose up -d --build

say "\n${green}cicig установлен.${reset}"
say "Панель:     https://$panel_domain"
say "WireGuard:  $panel_domain:51820/udp"
say "AmneziaWG: $panel_domain:443/udp"
say "Статус: cd $CICIG_DIR && docker compose ps"

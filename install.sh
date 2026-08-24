#!/usr/bin/env bash
set -Eeuo pipefail

readonly CICIG_DIR="/opt/cicig"
readonly COMPOSE_URL="${CICIG_COMPOSE_URL:-https://raw.githubusercontent.com/OWNER/cicig/main/docker-compose.yml}"
readonly CADDY_URL="${CICIG_CADDY_URL:-https://raw.githubusercontent.com/OWNER/cicig/main/Caddyfile}"

red='\033[0;31m'; green='\033[0;32m'; amber='\033[0;33m'; cyan='\033[0;36m'; reset='\033[0m'
say() { printf '%b\n' "$*"; }
die() { say "${red}Ошибка:${reset} $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Нужна команда '$1'."; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Запустите установщик через sudo."
need curl
need getent

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
  local expected=$1 wg_domain=$2 awg_domain=$3 domain found ok
  while true; do
    say "\n${cyan}Добавьте у DNS-провайдера записи:${reset}"
    printf '\n  %-5s %-28s %s\n' TYPE NAME VALUE
    printf '  %-5s %-28s %s\n' A "$wg_domain" "$expected"
    printf '  %-5s %-28s %s\n\n' A "$awg_domain" "$expected"
    say "Cloudflare: для обеих записей выберите ${amber}DNS only (серое облако)${reset}."
    say "Пример: Cloudflare → DNS → Records → Add record → Type A → Name → IPv4 → Proxy off → Save."
    read -r -p "После добавления DNS нажмите Enter (q — выход): " answer <"$tty"
    [[ ${answer,,} == q ]] && exit 0

    ok=1
    for domain in "$wg_domain" "$awg_domain"; do
      found=$(resolve_a "$domain" | paste -sd, -)
      if [[ ,$found, == *,$expected,* ]]; then
        say "${green}✓${reset} $domain → $expected"
      else
        say "${red}✗${reset} $domain → ${found:-нет A-записи}; ожидался $expected"
        ok=0
      fi
    done
    [[ $ok -eq 1 ]] && return
    say "${amber}DNS ещё не готов. Установка не начата.${reset}"
  done
}

bcrypt() {
  local password=$1
  printf '%s\n' "$password" | htpasswd -niBC 12 '' 2>/dev/null | tr -d ':\n' | sed 's/\$/$$/g'
}

say "${cyan}cicig — WireGuard + AmneziaWG${reset}"
wg_domain=$(prompt "Домен WireGuard-панели" "wg.example.com")
awg_domain=$(prompt "Домен AmneziaWG-панели" "wga.example.com")
email=$(prompt "Email для TLS" "admin@example.com")
valid_domain "$wg_domain" || die "Некорректный домен: $wg_domain"
valid_domain "$awg_domain" || die "Некорректный домен: $awg_domain"
[[ $wg_domain != "$awg_domain" ]] || die "Домены должны отличаться."
server_ip=$(public_ipv4) || die "Не удалось определить публичный IPv4."
say "Публичный IPv4 сервера: ${green}$server_ip${reset}"

# Hard gate: no package installation or system mutation happens before DNS succeeds.
dns_gate "$server_ip" "$wg_domain" "$awg_domain"
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
curl -fsSL "$COMPOSE_URL" -o "$CICIG_DIR/docker-compose.yml"
curl -fsSL "$CADDY_URL" -o "$CICIG_DIR/Caddyfile"

wg_hash=$(bcrypt "$admin_password")
awg_hash=$wg_hash
unset admin_password admin_password_2
umask 077
cat >"$CICIG_DIR/.env" <<EOF
WG_DOMAIN=$wg_domain
AWG_DOMAIN=$awg_domain
LETSENCRYPT_EMAIL=$email
WG_PORT=51820
AWG_PORT=443
WG_PASSWORD_HASH=$wg_hash
AWG_PASSWORD_HASH=$awg_hash
EOF

cd "$CICIG_DIR"
docker compose config --quiet
docker compose pull
docker compose up -d

say "\n${green}cicig установлен.${reset}"
say "WireGuard:  https://$wg_domain  | endpoint $wg_domain:51820/udp"
say "AmneziaWG: https://$awg_domain | endpoint $awg_domain:443/udp"
say "Статус: cd $CICIG_DIR && docker compose ps"

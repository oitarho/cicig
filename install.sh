#!/usr/bin/env bash
set -Eeuo pipefail

readonly CICIG_DIR="/opt/cicig"
readonly ARCHIVE_URL="${CICIG_ARCHIVE_URL:-https://github.com/oitarho/cicig/archive/refs/heads/main.tar.gz}"

red='\033[0;31m'; green='\033[0;32m'; amber='\033[0;33m'; cyan='\033[0;36m'; reset='\033[0m'
say() { printf '%b\n' "$*"; }
die() { say "${red}[ КОТ В ПАНИКЕ ]${reset} $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "В рюкзаке нет команды '$1'."; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Без root-доступа лапы связаны. Запустите через sudo."
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
  local expected=$1 vpn_domain=$2 panel_domain=$3 found answer attempt=0
  local vpn_ok panel_ok

  say "\n${cyan}[ DNS-МАСКИРОВКА ] Создайте две записи типа A (IPv4)${reset}"
  say "В терминал сейчас ничего вводить не нужно. Откройте в браузере сайт,"
  say "на котором вы управляете своим доменом, и найдите раздел DNS."
  say "\nПервая метка на карте — основной домен для VPN-ключей:"
  say "  Тип записи:       A"
  say "  Имя / Host:       @"
  say "  IPv4 / Значение:  $expected"
  say "  Результат:         $vpn_domain → $expected"
  say "\nВторая метка — вход в кошачью root-консоль:"
  say "  Тип записи:       A"
  say "  Имя / Host:       panel"
  say "  IPv4 / Значение:  $expected"
  say "  Результат:         $panel_domain → $expected"
  say "\nЕсли ваш домен находится в Cloudflare:"
  say "  1. Откройте DNS → Records → Add record."
  say "  2. Выберите Type: A."
  say "  3. Заполните Name и IPv4 address значениями выше."
  say "  4. Выключите Proxy status. Должно быть серое облако ${amber}DNS only${reset}."
  say "  5. Нажмите Save и повторите для второй записи."
  say "\nОбе записи должны быть DNS only: основной домен принимает VPN-трафик UDP."

  while true; do
    read -r -p "Кот готов сканировать DNS. Enter — проверить, q — уйти в тень: " answer <"$tty"
    [[ ${answer,,} == q ]] && exit 0
    attempt=$((attempt + 1))
    vpn_ok=0
    panel_ok=0

    say "\n[ DNS-SCAN #$attempt ] Проверяю легенду прикрытия:"
    found=$(resolve_a "$vpn_domain" | paste -sd, -)
    if [[ ,$found, == *,$expected,* ]]; then
      say "  ${green}✓ VPN-маяк:${reset} $vpn_domain → $expected — цель захвачена"
      vpn_ok=1
    else
      say "  ${red}✗ Основной домен:${reset} $vpn_domain → ${found:-запись не найдена}"
      say "                     Нужно: $expected"
    fi

    found=$(resolve_a "$panel_domain" | paste -sd, -)
    if [[ ,$found, == *,$expected,* ]]; then
      say "  ${green}✓ Вход в сейф:${reset} $panel_domain → $expected — цель захвачена"
      panel_ok=1
    else
      say "  ${red}✗ Веб-панель:${reset}     $panel_domain → ${found:-запись не найдена}"
      say "                     Нужно: $expected"
    fi

    if [[ $vpn_ok -eq 1 && $panel_ok -eq 1 ]]; then
      say "\n${green}[ ACCESS GRANTED ] DNS-маскировка на месте.${reset}"
      return
    fi
    say "\n${amber}Один из маяков палится. Пока обе A-записи не верны, нода не стартует.${reset}"
    say "Поправьте красную цель — кот останется здесь и просканирует снова."
  done
}

bcrypt() {
  local password=$1
  printf '%s\n' "$password" | htpasswd -niBC 12 '' 2>/dev/null | tr -d ':\n' | sed 's/\$/$$/g'
}

say "${cyan}cicig — WireGuard + AmneziaWG${reset}"
say "${green}       /\_/\\"
say "      ( o.o )   root@cicig"
say "       > ^ <    защищённый VPN-узел${reset}"
say "${cyan}[ ЭТАП 1/4 ] Идентификация сервера и домена${reset}"
base_domain=$(prompt "Ваш основной домен (например, mydomain.com)")
base_domain=${base_domain,,}
base_domain=${base_domain%.}
valid_domain "$base_domain" || die "Некорректный домен: $base_domain"
panel_domain="panel.$base_domain"
say "Вход в кошачий сейф будет здесь: $panel_domain"
email=$(prompt "Email для TLS" "admin@$base_domain")
server_ip=$(public_ipv4) || die "Не удалось определить публичный IPv4."
say "Внешний след ноды (IPv4): ${green}$server_ip${reset}"

# Hard gate: no package installation or system mutation happens before DNS succeeds.
dns_gate "$server_ip" "$base_domain" "$panel_domain"
say "${green}[ OK ] DNS проверен.${reset}"

say "${cyan}[ ЭТАП 2/4 ] Проверка совместимости сервера${reset}"
case "$(uname -m)" in
  x86_64|amd64) say "${green}[ OK ] Архитектура amd64 поддерживается.${reset}" ;;
  *) die "AmneziaWG требует сервер amd64/x86_64. Обнаружено: $(uname -m)." ;;
esac
if [[ ! -c /dev/net/tun ]] && command -v modprobe >/dev/null 2>&1; then
  modprobe tun 2>/dev/null || true
fi
[[ -c /dev/net/tun ]] || die "Устройство /dev/net/tun недоступно. Включите TUN/TAP в панели вашего VPS-провайдера и повторите установку."
say "${green}[ OK ] TUN/TAP доступен.${reset}"

say "${cyan}[ ЭТАП 3/4 ] Собираю контейнерный рюкзак${reset}"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose plugin не найден."
if ! command -v htpasswd >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apache2-utils
fi

read -r -s -p "Мастер-пароль от кошачьего сейфа: " admin_password <"$tty"; printf '\n' >"$tty"
[[ ${#admin_password} -ge 12 ]] || die "Пароль должен содержать минимум 12 символов."
read -r -s -p "Контрольный мяу-пароль ещё раз: " admin_password_2 <"$tty"; printf '\n' >"$tty"
[[ $admin_password == "$admin_password_2" ]] || die "Пароли не совпадают."

install -d -m 700 "$CICIG_DIR"
curl -fsSL "$ARCHIVE_URL" | tar -xz --strip-components=1 -C "$CICIG_DIR"

panel_hash=$(bcrypt "$admin_password")
panel_secret=$(openssl rand -hex 32)
unset admin_password admin_password_2
umask 077
cat >"$CICIG_DIR/.env" <<EOF
PANEL_DOMAIN=$panel_domain
VPN_DOMAIN=$base_domain
LETSENCRYPT_EMAIL=$email
WG_PORT=51820
AWG_PORT=443
PANEL_PASSWORD_HASH=$panel_hash
PANEL_SECRET_KEY=$panel_secret
EOF

cd "$CICIG_DIR"
docker compose config --quiet
docker compose pull caddy wg-easy awg-easy
say "${cyan}[ ЭТАП 4/4 ] Выпускаю зашифрованные тоннели в сеть${reset}"
docker compose up -d --build

say "\n${green}[ МИССИЯ ВЫПОЛНЕНА ] cicig поднят, кот получил root.${reset}"
say "Кошачий сейф: https://$panel_domain"
say "WireGuard:  $base_domain:51820/udp"
say "AmneziaWG: $base_domain:443/udp"
say "Проверить пульс ноды: cd $CICIG_DIR && docker compose ps"

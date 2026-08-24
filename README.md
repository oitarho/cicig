<p align="center">
  <img src="assets/cicig-cat-hacker.png" width="200" alt="Кошка-хакер cicig">
</p>

<h1 align="center">cicig</h1>

<p align="center">
  <strong>Русский</strong> · <a href="README.en.md">English</a>
</p>

<p align="center">
  <strong>WireGuard и AmneziaWG под одной лапой.</strong><br>
  Один домен, одна русскоязычная панель и полный цикл управления VPN-доступами.
</p>

<p align="center">
  <a href="https://github.com/oitarho/cicig/actions/workflows/validate.yml"><img src="https://github.com/oitarho/cicig/actions/workflows/validate.yml/badge.svg" alt="Проверка проекта"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/oitarho/cicig" alt="Лицензия MIT"></a>
</p>

`cicig` превращает чистый VPS в готовый self-hosted VPN-сервис. Вместо двух разрозненных панелей администратор получает единое место для WireGuard и AmneziaWG: создаёт клиентов, выдаёт конфиги, следит за подключениями и управляет сроками доступа.

## Почему cicig

| Возможность | Что получает администратор |
|---|---|
| Два VPN-протокола | WireGuard и AmneziaWG в одной панели |
| Управление клиентами | Создание, поиск, отключение, продление и удаление |
| Готовая выдача доступа | `.conf` и QR-код прямо из карточки клиента |
| Контроль сроков | Дата окончания, фильтры и автоматическое отключение просроченных ключей |
| Состояние подключений | Онлайн-статус, последний handshake и трафик |
| Домен вместо IP | Клиентские конфиги используют ваш основной домен |
| Установка одной командой | Docker, HTTPS, панель и оба VPN-сервиса разворачиваются автоматически |
| Обновление всей системы | Ручное или автоматическое обновление кода и контейнеров |
| Работа с телефона | Компактный адаптивный интерфейс на русском языке |

Панель доступна только администратору. Клиент получает готовый файл или QR-код и не видит внутреннее устройство сервера.

## Установка

Нужен чистый сервер:

- Ubuntu 22.04/24.04 или Debian 12;
- архитектура `amd64`/`x86_64`;
- публичный IPv4 и собственный домен;
- включённый TUN/TAP;
- свободные порты `80/tcp`, `443/tcp`, `443/udp` и `51820/udp`.

Запустите от `root` или через `sudo`:

```bash
curl -fsSL https://raw.githubusercontent.com/oitarho/cicig/main/install.sh | sudo bash
```

Установщик попросит только основной домен, например `mydomain.com`, и сам создаст адрес панели `panel.mydomain.com`.

Перед установкой он покажет публичный IPv4 сервера и попросит создать две DNS-записи:

| Тип | Имя | Значение |
|---|---|---|
| `A` | `@` | IPv4 сервера |
| `A` | `panel` | IPv4 сервера |

Для Cloudflare у обеих записей выберите **DNS only** — серое облако. Установка продолжится только после успешной проверки обеих A-записей.

После запуска будут доступны:

| Назначение | Адрес |
|---|---|
| Панель управления | `https://panel.mydomain.com` |
| WireGuard | `mydomain.com:51820/udp` |
| AmneziaWG | `mydomain.com:443/udp` |
| Главная страница | `https://mydomain.com` |

## VPN-клиенты

Используйте приложение, соответствующее типу выданного ключа.

| Протокол | Официальные клиенты |
|---|---|
| WireGuard | [Windows, macOS, Android, iOS и Linux](https://www.wireguard.com/install/) |
| AmneziaWG | [Windows](https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest) · [Android](https://play.google.com/store/apps/details?id=org.amnezia.awg) · [iPhone, iPad и macOS](https://apps.apple.com/app/amneziawg/id6478942365) |

Подключение занимает три шага:

1. Создайте клиента в разделе **«Ключи»**.
2. Скачайте `.conf` или откройте QR-код.
3. Импортируйте конфиг в WireGuard либо AmneziaWG и активируйте туннель.

Для каждого устройства создавайте отдельного клиента. Конфиг WireGuard открывайте в WireGuard, конфиг AmneziaWG — в AmneziaWG.

## Обновление

В разделе **«Узлы и патчи»** можно включить автоматическое обновление или запустить его вручную. Данные клиентов, VPN-ключи, `.env` и HTTPS-сертификаты при обновлении сохраняются.

Обновление из терминала:

```bash
sudo sh /opt/cicig/scripts/update.sh
```

## Необходимые команды

Проверить сервисы:

```bash
cd /opt/cicig
docker compose ps
```

Посмотреть журналы:

```bash
cd /opt/cicig
docker compose logs --tail=200
```

Если AmneziaWG перезапускается, проверьте TUN/TAP:

```bash
test -c /dev/net/tun && echo "TUN/TAP доступен" || echo "TUN/TAP отключён"
```

## Безопасность

- пароль администратора хранится в виде bcrypt-хеша;
- вход защищён CSRF-проверкой и блокировкой перебора;
- панель изолирована от Docker API;
- секреты и клиентские данные хранятся вне Git;
- зависимости и сборка автоматически проверяются в GitHub Actions.

Используйте уникальный пароль и регулярно обновляйте операционную систему сервера.

## Основа проекта

`cicig` использует [wg-easy](https://github.com/wg-easy/wg-easy), [awg-easy](https://github.com/YokiToki/awg-easy) и [Caddy](https://caddyserver.com/) как инфраструктурные компоненты, добавляя над ними собственную единую панель управления, установщик и систему обновлений.

Лицензия: [MIT](LICENSE).

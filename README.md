<p align="center"><img src="assets/cicig-cat.png" width="180" alt="cicig cat icon"></p>

# cicig

One-command, domain-first deployment of two self-hosted VPNs:

- `wg.example.com` — WireGuard web panel and `wg.example.com:51820/udp` endpoint.
- `wga.example.com` — AmneziaWG web panel and `wga.example.com:443/udp` endpoint.
- Caddy provides automatic HTTPS. HTTP/3 is intentionally disabled because AmneziaWG owns UDP/443.

The installer refuses to modify the server until both DNS A records resolve to its public IPv4 address. For Cloudflare, use **DNS only** (grey cloud).

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/oitarho/cicig/main/install.sh | sudo bash
```

The script asks only for the base domain (for example, `mydomain.com`) and automatically uses the fixed `wg.mydomain.com` and `wga.mydomain.com` subdomains. It shows the exact DNS records to create, waits for both records, asks for a panel password, installs Docker if needed, and starts the stack under `/opt/cicig`.

## Requirements

- Fresh Ubuntu 22.04/24.04 or Debian 12 server
- Public IPv4
- Two DNS A records pointing directly to the server
- TCP 80/443 and UDP 443/51820 available
- Linux `amd64` for the current AmneziaWG image

## Development

```bash
cp .env.example .env
docker compose config
```

Never commit `.env` or generated VPN state. Persistent state is stored in named Docker volumes.

## Current status

This is an initial scaffold. Before a production release, add CI shell linting, image digest pinning, backup/restore testing, firewall integration, and a migration path to the current wg-easy major version or a native cicig panel.

## Upstream components

- [wg-easy](https://github.com/wg-easy/wg-easy)
- [awg-easy](https://github.com/YokiToki/awg-easy)
- [Caddy](https://caddyserver.com/)

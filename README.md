<p align="center"><img src="assets/cicig-cat.png" width="180" alt="cicig cat icon"></p>

# cicig

One-command, domain-first deployment of two self-hosted VPNs and one control panel:

- `panel.example.com:443/tcp` — unified cicig web panel.
- `example.com:51820/udp` — WireGuard endpoint used in client configs.
- `example.com:443/udp` — AmneziaWG endpoint used in client configs.
- Caddy provides automatic HTTPS. HTTP/3 is intentionally disabled because AmneziaWG owns UDP/443.

The installer refuses to modify the server until both the root-domain and `panel` DNS A records resolve to its public IPv4 address. For Cloudflare, use **DNS only** (grey cloud) on both records because the root domain carries VPN UDP traffic.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/oitarho/cicig/main/install.sh | sudo bash
```

The script asks only for the base domain (for example, `mydomain.com`). It uses that root domain in both VPN client configurations and automatically creates the panel address `panel.mydomain.com`. It shows the two exact A records to create, waits for DNS, asks for a panel password, installs Docker if needed, and starts the stack under `/opt/cicig`.

The control panel provides one client list for both VPNs. It can create, enable, disable, and delete clients, download `.conf` files, display QR codes, show traffic totals and service health, run manual updates, and configure independent automatic updates. Updates are restricted to the `wg-easy` and `awg-easy` Compose services.

## Requirements

- Fresh Ubuntu 22.04/24.04 or Debian 12 server
- Public IPv4
- Root-domain and `panel` DNS A records pointing directly to the server
- TCP 80/443 and UDP 443/51820 available
- Linux `amd64` for the current AmneziaWG image

## Development

```bash
cp .env.example .env
docker compose config
```

Never commit `.env` or generated VPN state. Persistent state is stored in named Docker volumes.

## Current status

The panel needs access to `/var/run/docker.sock` to update the two VPN containers. Treat panel credentials as root-equivalent, keep the application updated, and never expose its internal port directly. Before a production release, add image digest pinning, backup/restore testing, firewall integration, and a migration path to the current wg-easy major version.

## Upstream components

- [wg-easy](https://github.com/wg-easy/wg-easy)
- [awg-easy](https://github.com/YokiToki/awg-easy)
- [Caddy](https://caddyserver.com/)

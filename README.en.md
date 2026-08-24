<p align="center">
  <img src="assets/cicig-cat-hacker.png" width="200" alt="cicig hacker cat">
</p>

<h1 align="center">cicig</h1>

<p align="center">
  <a href="README.md">Русский</a> · <strong>English</strong>
</p>

<p align="center">
  <strong>WireGuard and AmneziaWG under one paw.</strong><br>
  One domain, one control panel, and the complete lifecycle of VPN access.
</p>

<p align="center">
  <a href="https://oitarho.github.io/cicig/"><img src="https://img.shields.io/badge/website-cicig-24f28a" alt="cicig website"></a>
  <a href="https://github.com/oitarho/cicig/actions/workflows/validate.yml"><img src="https://github.com/oitarho/cicig/actions/workflows/validate.yml/badge.svg" alt="Project validation"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/oitarho/cicig" alt="MIT license"></a>
</p>

`cicig` turns a clean VPS into a ready-to-use self-hosted VPN service. Instead of managing separate panels, an administrator gets one place for WireGuard and AmneziaWG: create clients, issue configurations, monitor connections, and control access periods.

## Why cicig

| Feature | What the administrator gets |
|---|---|
| Two VPN protocols | WireGuard and AmneziaWG in one panel |
| Client management | Create, search, disable, extend, and delete clients |
| Ready-to-share access | Downloadable `.conf` files and QR codes |
| Expiration control | Expiration dates, filters, and automatic disabling |
| Connection status | Online state, latest handshake, and traffic usage |
| Domain-based endpoints | Client configurations use your domain instead of an IP address |
| One-command setup | Docker, HTTPS, the panel, and both VPN services are deployed automatically |
| Full-system updates | Manual or automatic updates for the code and containers |
| Mobile-friendly UI | A compact responsive interface |

Only the administrator can access the panel. A client receives a ready configuration file or QR code without access to the server internals.

## Installation

Start with a clean server that has:

- Ubuntu 22.04/24.04 or Debian 12;
- `amd64`/`x86_64` architecture;
- at least 2 vCPU, 2 GB RAM, and 20 GB SSD storage;
- a public IPv4 address and your own domain;
- TUN/TAP enabled;
- free ports `80/tcp`, `443/tcp`, `443/udp`, and `51820/udp`.

### Resources and scaling

Size the server by the number of clients using the VPN at the same time, not by the total number of issued keys.

| Concurrent clients | Server configuration | Server connection |
|---|---|---|
| Up to 20 | 2 vCPU, 2 GB RAM, 20 GB SSD | 100 Mbps or faster |
| 21–100 | 4 vCPU, 4 GB RAM, 30 GB SSD | 500 Mbps or faster |
| 101–300 | 8 vCPU, 8 GB RAM, 40 GB SSD | 1 Gbps or faster |

These are planning estimates, not guaranteed limits: actual load depends on per-client traffic, VPS CPU performance, and the share of AmneziaWG traffic. For example, 50 active clients × 5 Mbps requires 250 Mbps; add 20–30% headroom. Upgrade the server when CPU remains above 70%, RAM above 80%, or the network link is saturated. For more than 300 concurrent connections, use multiple independent cicig servers and distribute clients between them—the client database is not currently synchronized across nodes.

Run as `root` or with `sudo`:

```bash
curl -fsSL https://raw.githubusercontent.com/oitarho/cicig/main/install.sh | sudo bash
```

The installer asks for your root domain, such as `mydomain.com`, and automatically creates the panel address `panel.mydomain.com`.

Before deployment, it displays the server's public IPv4 address and asks you to create two DNS records:

| Type | Name | Value |
|---|---|---|
| `A` | `@` | Server IPv4 address |
| `A` | `panel` | Server IPv4 address |

When using Cloudflare, set both records to **DNS only** — the gray cloud. Installation continues only after both A records pass validation.

The following addresses become available after installation:

| Purpose | Address |
|---|---|
| Control panel | `https://panel.mydomain.com` |
| WireGuard | `mydomain.com:51820/udp` |
| AmneziaWG | `mydomain.com:443/udp` |
| Landing page | `https://mydomain.com` |

## VPN clients

Use the application that matches the issued configuration type.

| Protocol | Official clients |
|---|---|
| WireGuard | [Windows, macOS, Android, iOS, and Linux](https://www.wireguard.com/install/) |
| AmneziaWG | [Windows](https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest) · [Android](https://play.google.com/store/apps/details?id=org.amnezia.awg) · [iPhone, iPad, and macOS](https://apps.apple.com/app/amneziawg/id6478942365) |

Connecting takes three steps:

1. Create a client in the **«Ключи» (Keys)** section.
2. Download its `.conf` file or open the QR code.
3. Import the configuration into WireGuard or AmneziaWG and activate the tunnel.

Create a separate client for every device. Open WireGuard configurations in WireGuard and AmneziaWG configurations in AmneziaWG.

## Updates

The **«Узлы и патчи» (Nodes and patches)** section lets you enable automatic updates or start one manually. Client data, VPN keys, `.env`, and HTTPS certificates are preserved during updates.

Update from the terminal:

```bash
sudo sh /opt/cicig/scripts/update.sh
```

## Essential commands

Check the services:

```bash
cd /opt/cicig
docker compose ps
```

Read the logs:

```bash
cd /opt/cicig
docker compose logs --tail=200
```

If AmneziaWG keeps restarting, check TUN/TAP:

```bash
test -c /dev/net/tun && echo "TUN/TAP is available" || echo "TUN/TAP is disabled"
```

## Security

- the administrator password is stored as a bcrypt hash;
- login is protected by CSRF validation and brute-force lockout;
- the web panel is isolated from the Docker API;
- secrets and client data are kept outside Git;
- dependencies and builds are automatically checked by GitHub Actions.

Use a unique password and keep the server operating system updated.

## Built on

`cicig` uses [wg-easy](https://github.com/wg-easy/wg-easy), [awg-easy](https://github.com/YokiToki/awg-easy), and [Caddy](https://caddyserver.com/) as infrastructure components while providing its own unified control panel, installer, and update system on top.

License: [MIT](LICENSE).

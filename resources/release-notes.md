Zarp for Linux $version, with native packages for Ubuntu, Debian, Fedora and Arch Linux.

## What's inside

- **WARP through zapret2.** Zarp drives the official Cloudflare WARP client and finds a strategy that gets its MASQUE handshake through DPI, over QUIC (HTTP/3) or TLS (HTTP/2). zapret2 stays active while the tunnel is connected.
- **Quick scan and Full scan**, the same flow as on Windows. A working strategy must pass twice, with another WARP endpoint when test isolation is enabled. A connection counts only if real HTTPS traffic passes through the tunnel and packet processing is confirmed.
- **Remembers verified strategies.** The power button uses saved results on later connections. You can recheck selected strategies, filter by country or choose one manually in Settings.
- **Your own VPN server.** VLESS TLS / Reality, Trojan, Hysteria2 and VLESS XHTTP, from one link or an HTTPS subscription. Zarp tests compatible server-and-strategy pairs and keeps their outer connection protected by zapret2. The bundled sing-box handles the tunnel; Xray handles XHTTP through a local bridge.
- **Routing and per-program proxy** for your own server. Direct, Proxy and Block rules, GeoIP/GeoSite, local-network and country presets, and a choice of programs that use the server.
- **Protected WARP setup.** Device registration and WARP+ requests go through zapret2. On Ubuntu and Debian, Zarp can install the official WARP client after you accept its terms; if ordinary download attempts fail, it retries through zapret2.
- **QUIC packet handling.** A compact 1200-byte VK Initial preserves the complete authenticated ClientHello on small-MTU links. IP-fragment strategies account for the official WARP client's firewall.
- **Native Linux desktop.** An animated power button, separate settings window, log and system tray. The GUI runs as your ordinary user; a system service handles tunnels and packet interception, with polkit authorization.
- **Nine interface languages.** English, Русский, Español, Português, 中文, हिन्दी, Français, Deutsch and فارسی, switchable from the globe button.

## Download

$downloads

## Requirements

- **Linux x86_64 with systemd:** Ubuntu 26.04, Debian 13, Fedora 44 or current Arch Linux. Choose the package built for your distribution.
- **Packet interception:** NFQUEUE and cgroup v2. WARP mode needs `nft_socket` or `xt_cgroup` with `iptables-nft`.
- **Desktop authorization:** a polkit authentication agent. Run the GUI as your ordinary user.
- **WARP mode:** the official Cloudflare WARP client. Zarp can install it on Ubuntu/Debian; install it separately on Fedora/Arch. WARP is not bundled. Your own server mode uses the included VPN engines.

## Getting started

1. Download and install your distribution's package. [Installation commands](https://github.com/ZarpVPN/Zarp-Linux/blob/v$version/README.md#usage).
2. Start the service, then open Zarp from the application menu or terminal:

```sh
sudo systemctl enable --now zarp.service
zarp
```

3. Press the power button, or open Settings and start a Quick scan or Full scan. For your own server, paste a link or subscription in **Server and endpoints** before searching.

## Verify the download

Download `SHA256SUMS` alongside your package and run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
```

**Package SHA-256:**

```text
$checksums
```

Packages are currently unsigned. `release-manifest.json` records the source commit, package hashes and bundled engine versions.

## Bundled engines

$runtimes

nfqws2 is built natively for each distribution. Runtime downloads are pinned and verified; zapret2 updates are checked before activation.

Before publication, CI installs each native package and runs Go/race, GUI tests as an ordinary user, runtime checks and packet tests in an isolated network namespace. The working strategies still depend on your network.

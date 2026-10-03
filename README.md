# wgpanel

**[中文 →](README.zh.md)**

A management panel for [linuxserver/wireguard](https://github.com/linuxserver/docker-wireguard).
Add, edit and delete peers from a web UI, and have the changes take effect
**without restarting the container** — connected clients are not interrupted.

## What it does

- **Peer management.** Create a peer and it gets an address, a key pair and a
  preshared key automatically. Show its QR code, download its `.conf`, edit its
  AllowedIPs or keepalive, delete it.
- **Live reload, not restart.** Changes are pushed into the running interface, so
  established sessions survive. Only route/DNS/hook edits briefly re-attach the
  interface — and even then the container is not restarted.
- **Live status.** Per-peer handshake age, endpoint, throughput rate and totals,
  refreshed every two seconds.
- **Plan before apply.** Hand-edit `wg0.conf` and the UI shows exactly what would
  change, with a button to apply it.
- **Zero downtime by default.** Removing a peer or touching risky settings asks
  for confirmation first.

## Quick start

You need a running `linuxserver/wireguard` container (or start one with the
bundled [compose.yaml](compose.yaml)).

The panel shares the wireguard container's network namespace, so add it next to it:

```yaml
services:
  wireguard:
    image: lscr.io/linuxserver/wireguard:latest
    ports:
      - 51820:51820/udp
      - 47710:47710            # the panel's UI lives in this namespace
    # ...your existing config

  wgpanel:
    build: .
    image: wgpanel:dev
    network_mode: "service:wireguard"     # shares the namespace: no docker socket
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./config:/config                  # the same config dir the wireguard container uses
      - wgpanel-data:/data
    command: ["serve"]
    restart: unless-stopped
```

```sh
docker compose up -d
```

Then open **http://your-host:47710**.

First time in: open **设置** and fill in the server address your clients should
dial (public IP or domain). The QR codes and `.conf` files are built from it.

## Usage

**Web UI** — peers, live status, QR codes and config downloads.

**CLI**, for scripting and for checking things before you touch them:

```sh
docker compose exec wgpanel wgpanel doctor    # can it manage this interface?
docker compose exec wgpanel wgpanel plan      # what would apply do? (read-only)
docker compose exec wgpanel wgpanel apply     # do it
docker compose exec wgpanel wgpanel show      # live peers (private key redacted)
```

Risky changes are refused unless you ask:

```sh
wgpanel apply --allow-disruptive     # re-attaching the interface, or a private key change
wgpanel apply --allow-destructive    # deleting peers, or changing the listen port
```

## Requirements

- The panel container must share the wireguard container's network namespace and
  run with `NET_ADMIN`; it needs no docker socket.
- Only one writer at a time: if you also run another tool that rewrites
  `wg0.conf`, don't use both.

## How it works

`wg-quick` only reads the config when it brings the interface **up** — nothing
watches the file. So wgpanel pushes the change into the kernel itself:
`wg-quick strip` removes the directives `wg(8)` does not understand, and
`wg syncconf` applies only the difference, which is why established peer sessions
survive. Things `syncconf` cannot touch (addresses, routes, DNS, hooks) get their
own `ip` commands, or fall back to an in-container `wg-quick down && up`.

The full reasoning, the decision table and the upstream source references are in
[docs/design.md](docs/design.md) (Chinese).

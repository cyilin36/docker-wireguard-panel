# wgpanel

**[中文 →](README.zh.md)**

A management panel for [linuxserver/wireguard](https://github.com/linuxserver/docker-wireguard).
Add, edit and delete peers in the browser; the change takes effect **without restarting the
container**, so connected clients stay online.

## Deploy

```yaml
services:
  wireguard:
    image: lscr.io/linuxserver/wireguard:latest
    ports:
      - 51820:51820/udp
      - 47710:47710        # the panel shares this namespace, so its port is published here
    # ...your existing config

  wgpanel:
    build: .
    image: wgpanel:dev
    network_mode: "service:wireguard"   # shares the namespace, so no docker socket is needed
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./config:/config                # the same config dir the wireguard container uses
    environment:
      PANEL_USER: admin
      PANEL_PASSWORD: pick-your-own
    command: ["serve"]
    restart: unless-stopped
```

```sh
docker compose up -d
```

Open `http://your-host:47710` and log in with those credentials, then open **设置** and fill in the
address your clients dial (public IP or domain) — the QR codes and `.conf` files are built from it.

The panel speaks plain HTTP, so give it a strong password if the port is on the internet.
The [compose.yaml](compose.yaml) in this repo is the same setup, ready to run, with a few
resource limits on top.

## What it does

- Peers: create (tunnel address, key pair and preshared key are generated), edit, delete, QR code,
  `.conf` download
- Live status: handshake age, endpoint, up/down rate, totals — refreshed every two seconds
- A hand-edited `wg0.conf` works too: the UI shows what would change, then applies it on one click
- Deleting a peer or changing the listen port asks for confirmation first

## CLI

```sh
docker compose exec wgpanel wgpanel doctor   # can it manage this interface?
docker compose exec wgpanel wgpanel plan     # what would apply do (read-only)
docker compose exec wgpanel wgpanel apply    # do it; risky changes need --allow-destructive
docker compose exec wgpanel wgpanel show     # current peers (keys redacted)
```

Only one program may write `wg0.conf` at a time.

## How it works

`wg-quick` reads the config only when it brings the interface up; nothing watches the file. So wgpanel
pushes the change into the kernel itself: `wg-quick strip` removes the directives `wg(8)` does not
understand, and `wg syncconf` applies only the difference — which is why established sessions survive.
What `syncconf` cannot touch (addresses, routes, DNS, hooks) gets its own `ip` commands, or falls back
to an in-container `wg-quick down && up`.

The reasoning and the decision table are in [docs/design.md](docs/design.md) (Chinese).

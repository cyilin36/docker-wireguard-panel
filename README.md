# wgpanel

**[中文 →](README.zh.md)**

A management panel for [linuxserver/wireguard](https://github.com/linuxserver/docker-wireguard).
Add, edit and delete peers in the browser; the change takes effect **without restarting the
container**, so connected clients stay online.

## Deploy

Copy [docker-compose.example.yml](docker-compose.example.yml) to `docker-compose.yml`, change
`PANEL_PASSWORD`, then run `docker compose up -d`. That is the whole file:

```yaml
name: wgpanel

services:
  wireguard:
    image: lscr.io/linuxserver/wireguard:latest
    container_name: wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      net.ipv4.conf.all.src_valid_mark: "1"
    environment:
      PUID: "1000"
      PGID: "1000"
      TZ: Asia/Shanghai
      SERVERURL: auto              # address your clients dial; set your public IP or domain
      SERVERPORT: "51820"
      PEERS: "1"                   # peers generated on first start; manage them in the panel
      PEERDNS: auto
      INTERNAL_SUBNET: 10.13.13.0
      ALLOWEDIPS: 0.0.0.0/0, ::/0
    volumes:
      - ./config:/config
      - /lib/modules:/lib/modules:ro
    ports:
      - "51820:51820/udp"
      # The panel shares this network namespace, so its UI port can only be
      # published here (a network_mode: service:X container cannot use ports:).
      - "47710:47710"
    restart: unless-stopped

  wgpanel:
    build: .
    image: wgpanel:dev
    container_name: wgpanel
    # Sharing the wireguard network namespace is what lets `wg syncconf`,
    # `wg show` and tcpdump run locally, with no docker socket.
    network_mode: "service:wireguard"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      # The same mount the wireguard container uses, so the panel edits the exact
      # wg0.conf the interface is reading.
      - ./config:/config
    environment:
      TZ: Asia/Shanghai
      WG_CONFIG_DIR: /config/wg_confs
      WG_STATE_DIR: /config/.wgpanel
      PANEL_PORT: "47710"
      # Web UI login. Change it before exposing the port.
      PANEL_USER: admin
      PANEL_PASSWORD: change-me
    depends_on:
      - wireguard
    restart: unless-stopped
    mem_limit: 256m
    cpus: 0.5
    pids_limit: 128
    read_only: true
    tmpfs:
      # wg syncconf needs a temp file; openresolv (used by wg-quick when the
      # config has a DNS directive) needs somewhere for resolver state.
      - /tmp
      - /run
    command: ["serve"]
    logging:
      driver: json-file
      options:
        max-size: "5m"
        max-file: "3"
```

Open `http://your-host:47710` and log in with `PANEL_USER` / `PANEL_PASSWORD`, then open **设置**
and fill in the address your clients dial (public IP or domain) — the QR codes and `.conf` files are
built from it. The panel speaks plain HTTP, so give it a strong password if the port is on the
internet.

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
docker compose exec wgpanel wgpanel apply    # do it; risky changes need --allow-destructive / --allow-disruptive
docker compose exec wgpanel wgpanel show     # current peers (keys redacted)
```

Only one program may write `wg0.conf` at a time.

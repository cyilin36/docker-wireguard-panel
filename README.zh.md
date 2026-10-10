# docker-wireguard-panel

**[English →](README.md)**

[linuxserver/wireguard](https://github.com/linuxserver/docker-wireguard) 的管理面板。
网页上增删改 peer，改完**不用重启容器**就生效，已连上的客户端不会掉线。

## 部署

把 [docker-compose.example.yml](docker-compose.example.yml) 复制成 `docker-compose.yml`，
改掉里面的 `PANEL_PASSWORD`，然后 `docker compose up -d`。文件内容如下：

```yaml
name: docker-wireguard-panel

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
    # Published image. Building it yourself works too: comment this out and use
    # `build: .` plus a tag of your own.
    image: ghcr.io/cyilin36/docker-wireguard-panel:0.1.1
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
      # Optional: lets other programs read the read-only API without a login
      # session. At least 16 characters; read-only endpoints only.
      # PANEL_API_TOKEN: change-me-too-0123456789
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

打开 `http://你的机器:47710`，用 `PANEL_USER` / `PANEL_PASSWORD` 登录；进去点 **设置**，
填客户端要连的服务器地址（公网 IP 或域名）——二维码和 `.conf` 都靠它生成。
面板是明文 HTTP，挂到公网就把密码设强一点。

流量采样默认每秒一次；要改间隔就在 `wgpanel` 服务里设 `PANEL_TRAFFIC_INTERVAL`（秒，`0` 表示关闭），
历史文件在 `WG_STATE_DIR/traffic/`。

## 给其他程序读取（只读 API）

面板的接口默认都要登录。在 `wgpanel` 服务里设一个 `PANEL_API_TOKEN`（至少 16 个字符）之后，
其他程序带上 `Authorization: Bearer <token>` 或 `X-API-Token: <token>` 就能免登录读取下面这几个
接口——只能读，不能写：

| 接口 | 内容 |
| --- | --- |
| `GET /api/state` | 接口状态、peer 列表（含实时握手与速率）、待生效改动 |
| `GET /api/plan` | 当前配置会执行什么计划 |
| `GET /api/traffic` | 流量历史（`?window=` 秒） |
| `GET /api/settings` | 客户端导出用的设置 |
| `GET /api/peers` | peer 列表 |

`GET /api/peers/{name}/conf` 和 `qr.svg` / `qr.png` 看着也是只读，但它们会把客户端的**私钥**
交出去，所以只认登录会话，token 一律 401；所有写接口（`POST` / `PATCH` / `DELETE` / `PUT`）同理。
`GET /api/health` 本来就不需要任何凭据，面板进程活着就返回 200。

`/api/state` 每请求都会读一遍内核状态并算一次待生效计划，轮询别太频繁，10 秒量级就够。

## 命令行

```sh
docker compose exec wgpanel wgpanel doctor   # 能不能管这个接口
docker compose exec wgpanel wgpanel plan     # apply 会做什么（只读）
docker compose exec wgpanel wgpanel apply    # 执行；风险操作加 --allow-destructive / --allow-disruptive
docker compose exec wgpanel wgpanel show     # 当前 peer（私钥打码）
```

同一时间只让一个程序写 `wg0.conf`。

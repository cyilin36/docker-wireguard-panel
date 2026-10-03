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
    image: ghcr.io/cyilin36/docker-wireguard-panel:0.1.0-rc1
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

打开 `http://你的机器:47710`，用 `PANEL_USER` / `PANEL_PASSWORD` 登录；进去点 **设置**，
填客户端要连的服务器地址（公网 IP 或域名）——二维码和 `.conf` 都靠它生成。
面板是明文 HTTP，挂到公网就把密码设强一点。

## 能做什么

- peer 增删改：自动分配隧道地址、生成密钥和预共享密钥，看二维码、下载 `.conf`
- 实时状态：握手时间、对端地址、上下行速率、累计流量，两秒刷新
- 手改了 `wg0.conf` 也能用：先告诉你会改什么，再点一下生效
- 删 peer、改监听端口这类操作会先要确认

## 命令行

```sh
docker compose exec wgpanel wgpanel doctor   # 能不能管这个接口
docker compose exec wgpanel wgpanel plan     # apply 会做什么（只读）
docker compose exec wgpanel wgpanel apply    # 执行；风险操作加 --allow-destructive / --allow-disruptive
docker compose exec wgpanel wgpanel show     # 当前 peer（私钥打码）
```

同一时间只让一个程序写 `wg0.conf`。

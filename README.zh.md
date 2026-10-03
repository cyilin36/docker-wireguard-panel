# wgpanel

**[English →](README.md)**

[linuxserver/wireguard](https://github.com/linuxserver/docker-wireguard) 的管理面板。
网页上增删改 peer，改完**不用重启容器**就生效，已连上的客户端不会掉线。

## 部署

```yaml
services:
  wireguard:
    image: lscr.io/linuxserver/wireguard:latest
    ports:
      - 51820:51820/udp
      - 47710:47710        # 面板共用这个网络命名空间，它的端口必须写在这
    # ...你原有的配置

  wgpanel:
    build: .
    image: wgpanel:dev
    network_mode: "service:wireguard"   # 共用命名空间，所以不需要 docker socket
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./config:/config                # 和 wireguard 容器挂同一个配置目录
    environment:
      PANEL_USER: admin
      PANEL_PASSWORD: 自己设一个
    command: ["serve"]
    restart: unless-stopped
```

```sh
docker compose up -d
```

打开 `http://你的机器:47710`，用上面那组账号密码登录；进去点 **设置**，填客户端要连的服务器地址
（公网 IP 或域名）——二维码和 `.conf` 都靠它生成。

面板是明文 HTTP，挂到公网就把密码设强一点。仓库里的 [compose.yaml](compose.yaml) 就是同一套配置，
可以直接跑，多了几项资源限制。

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

## 原理

`wg-quick` 只在拉起接口那一刻读一次配置，没有任何东西盯着那个文件。所以 wgpanel 直接把改动推进内核：
`wg-quick strip` 剥掉 `wg(8)` 不认识的指令，`wg syncconf` 只下发有差异的部分——这就是已建立的会话
不被打断的原因。`syncconf` 管不到的（地址、路由、DNS、钩子）单独补 `ip` 命令，或者回落到容器内
`wg-quick down && up`。

完整推导和判定表见 [docs/design.md](docs/design.md)。

# wgpanel

**[English →](README.md)**

[linuxserver/wireguard](https://github.com/linuxserver/docker-wireguard) 的管理面板。
在网页上增删改 peer，改完**不用重启容器**就生效，已连上的客户端不会掉线。

## 它做什么

- **Peer 管理**。新建 peer 会自动分配隧道地址、生成密钥对和预共享密钥；
  可以看二维码、下载客户端 `.conf`、改 AllowedIPs / Keepalive、删除。
- **热加载，不是重启**。改动直接推进正在运行的接口，已建立的会话不中断。
  只有路由 / DNS / 钩子这类改动会短暂重挂接口，容器始终不重启。
- **实时状态**。每个 peer 的握手时间、端点、上下行速率和累计流量，每两秒刷新。
- **先看方案再动手**。手改了 `wg0.conf`，界面会告诉你将要改什么，再点按钮生效。
- **有风险的操作要确认**。删除 peer、改监听端口这类不会默默执行。

## 快速开始

需要有一个在跑的 `linuxserver/wireguard` 容器（也可以用仓库里的
[compose.yaml](compose.yaml) 起一个）。

面板与 wireguard 容器共用网络命名空间，加在它旁边：

```yaml
services:
  wireguard:
    image: lscr.io/linuxserver/wireguard:latest
    ports:
      - 51820:51820/udp
      - 47710:47710            # 面板界面就活在这个命名空间里
    # ...你原有的配置

  wgpanel:
    build: .
    image: wgpanel:dev
    network_mode: "service:wireguard"     # 共用命名空间，因此不需要 docker socket
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./config:/config                  # 和 wireguard 容器挂同一个配置目录
      - wgpanel-data:/data
    command: ["serve"]
    restart: unless-stopped
```

```sh
docker compose up -d
```

然后打开 **http://你的机器:47710**。

第一次进去先点 **设置**，填上客户端要连的服务器地址（公网 IP 或域名）——
二维码和 `.conf` 都是用它拼出来的。

## 用法

**网页界面** —— peer 列表、实时状态、二维码、配置下载。

**命令行**，用于脚本和"动手前先看一眼"：

```sh
docker compose exec wgpanel wgpanel doctor    # 能管得了这个接口吗？
docker compose exec wgpanel wgpanel plan      # apply 会做什么（只读）
docker compose exec wgpanel wgpanel apply     # 执行
docker compose exec wgpanel wgpanel show      # 当前 peer（私钥已打码）
```

有风险的改动必须显式放行：

```sh
wgpanel apply --allow-disruptive     # 重挂接口，或更换私钥
wgpanel apply --allow-destructive    # 删除 peer，或更换监听端口
```

## 要求

- 面板容器必须和 wireguard 共用网络命名空间，并带 `NET_ADMIN`；不需要 docker socket。
- 同一时间只能有一个写入方：如果你还有别的工具在改 `wg0.conf`，别同时用。

## 原理

`wg-quick` 只在**把接口拉起来**的那一刻读配置，没有任何东西会监视那个文件。
所以 wgpanel 直接把改动推进内核：`wg-quick strip` 先剥掉 `wg(8)` 不认识的指令，
`wg syncconf` 只下发有差异的部分 —— 这就是已建立的 peer 会话不会被打断的原因。
`syncconf` 管不到的东西（地址、路由、DNS、钩子）单独补 `ip` 命令，
或者回落到容器内 `wg-quick down && up`。

完整的推导、判定表和上游源码出处见 [docs/design.md](docs/design.md)。

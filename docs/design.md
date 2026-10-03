# 设计说明：为什么这样热加载

本文是工程向的说明，用户手册见 [README](../README.md)。

---

## 1. 前提：没有任何东西会去读那个文件

`wg-quick` **只在 `up` 的那一刻读一次配置**。之后内核里的 wg 设备和磁盘上的文件再无关系，
镜像里也没有任何 watcher、没有 SIGHUP 处理。

所以"热加载"不可能靠"通知容器重读"，只能是**我们主动把文件内容推给内核**。

## 2. `wg syncconf` 是唯一零中断的通道

```bash
t=$(mktemp)
wg-quick strip /config/wg_confs/wg0.conf > "$t"   # 剥掉 wg-quick 专有字段
wg syncconf wg0 "$t"                              # 只下发有差异的部分
rm -f "$t"
```

* `wg-quick strip` 去掉 `Address` / `DNS` / `MTU` / `Table` / `PostUp` 等 `wg(8)` 不认识的指令，
  剩下的喂给 `wg syncconf`。
* [`wg.8`](https://git.zx2c4.com/wireguard-tools/plain/src/man/wg.8)：
  *"reads back the existing configuration first and only makes changes that are explicitly
  different … **not disrupting current peer sessions**"*。单次 netlink `set_device`，原子。
  未在文件里出现的接口属性（如 `wg-quick` 动态设置的 `FwMark`）会被保留。
* 覆盖范围：peer 增 / 删 / 改、`PrivateKey`、`ListenPort`、`FwMark`。
* **副作用**：文件里没有的 peer 会被删除。这是有意的 —— 配置文件即唯一事实来源，
  因此 `plan` 必须显式列出 `peers_removed`，`apply` 也要求 `--allow-destructive`。

## 3. 它管不到的部分

`Address`、`MTU`、`AllowedIPs` 对应的路由、`DNS`、`Table`、`PreUp/PostUp/PreDown/PostDown`、
`SaveConfig` 由 `wg-quick` 而非 `wg` 负责，`syncconf` 一律不碰。分两条路处理：

* **地址 / MTU / 非默认路由的 AllowedIPs** → 自己补差量：
  `ip addr add|del`、`ip link set mtu`、`ip route add|del dev wg0`。
  路由的判定与 `wg-quick add_route` 一致：**已有覆盖路由就不重复添加**；
  删除时只删"上一份配置拥有、这一份不再覆盖"的路由，绝不动别人手工加的路由。
* **`Table` / `DNS` / 钩子 / 默认路由 / `SaveConfig`** → **回落到容器内
  `wg-quick down && wg-quick up`**。有几百毫秒中断，但容器本身、s6、CoreDNS 都不动。

`Table = off` 时没有路由可管，`AllowedIPs` 的变化退化成纯 `syncconf`。

## 4. 变更分类表

实现见 `src/wgpanel/differ.py::decide_mode`，首个命中即生效：

| # | 条件 | mode | 门禁 |
|---|---|---|---|
| 0 | 文件与运行时均无差异 | `noop` | — |
| 1 | 目标接口不在运行时 | `start` → `wg-quick up` | `--allow-disruptive` |
| 2 | `Table` / `DNS` / `PreUp\|PostUp\|PreDown\|PostDown` / `SaveConfig` 变化 | `bounce` | `--allow-disruptive` |
| 3 | `AllowedIPs` 变化，新旧都不含 `*/0`，`Table` 为空/`auto` | `sync_addr_route` | — |
| 4 | `AllowedIPs` 变化且任一侧含 `*/0` | `bounce` | `--allow-disruptive` |
| 5 | `Address` 或 `MTU` 变化 | `sync_addr` | — |
| 6 | 其余（peer 增删改 / `PrivateKey` / `ListenPort` / `FwMark`） | `sync` | 见下 |
| — | 运行时多出的 peer 将被删除 | `sync` | `--allow-destructive` |
| — | `PrivateKey` 变化（对端 `PublicKey` 全失效） | `sync` | `--allow-disruptive` |
| — | `ListenPort` 变化 | `sync` | `--allow-destructive` |

文件级改动拿"上一次成功生效的配置"（`<state-dir>/applied/<iface>.conf`）比对，
而不是拿磁盘上的当前文件 —— 因为典型流程正是"你先改了文件，再让工具生效"。

## 5. 各模式的执行步骤

```
sync:            write → wg-quick strip | wg syncconf
sync_addr:       write → syncconf → ip addr add <新> → ip addr del <旧> → ip link set mtu → ip link set up
sync_addr_route: 同上 + ip route add（仅当无覆盖路由）→ ip route del
bounce:          write(旧配置) → wg-quick down → write(新配置) → wg-quick up
start:           write → wg-quick up
```

新地址先加后删，避免出现没有地址的窗口。命令一律用 argv 数组 + 固定 `bash -c` 外壳 +
位置参数，不做字符串拼接。

## 6. 两个必须处理的坑

### 6.1 `SaveConfig = true` 时 `wg-quick down` 会重写配置文件

`wg-quick down` 在 `SaveConfig = true` 时会用**当前运行时状态**回写配置文件，
`PreDown`/`PostDown` 也是从文件里读的。所以 bounce 的顺序必须是：

1. 先把**上一次生效的旧配置**放回文件
2. `wg-quick down` —— 跑的是旧钩子，回写的也是旧内容
3. 写新配置
4. `wg-quick up`

顺序反了的话，旧的 `PostUp` 加的 iptables 规则永远摘不掉。

### 6.2 `wg-quick` 不做 `eval`

LinuxServer 的 `defaults/server.conf` 模板里写的是 `PrivateKey = $(cat …)`，
镜像在生成配置时已经展开成字面量。但如果有人**手抄模板**放进 `wg_confs/`，
`strip` 出来的就是字面量 `$(cat …)`，`wg` 会直接报密钥格式错误。

校验器会提前拦下并解释原因（错误码 `value_not_evaluated`）。注意钩子
（`PreUp`/`PostUp` 等）是例外 —— `wg-quick` 确实会 `eval` 它们。

## 7. 否决掉的替代方案

| 方案 | 否决原因 |
|---|---|
| 重启容器 / `docker restart` | 触发 `init-wireguard-confs` 重新生成配置，以及入口脚本的 `ip route del default` 兜底 |
| `s6-rc` 重启 `svc-wireguard` | 它是 oneshot，重跑就是 `wg-quick up`，而 `cmd_up` 第一句就是 `die "'$I' already exists"` |
| `wg setconf` | 重建全部 peer，打断所有会话 |
| `wg addconf` | 只增不减，删掉的 peer 会残留 |
| 逐条 `wg set peer …` | 非原子、易与文件漂移；`syncconf` 是它的声明式超集 |
| 自己复刻 `wg-quick add_default` | 涉及 `fwmark` + `ip rule` + nft/iptables + `src_valid_mark`，极易出错 → 改用 bounce |
| fork 镜像塞 inotify watcher | 要动用户的 wireguard 容器，维护成本高 |

## 8. 上游依据

以下结论均已核对上游源码，不是推测：

| 事实 | 出处 |
|---|---|
| oneshot 服务对 `/config/wg_confs/*.conf` 逐个 `wg-quick up`；任一失败全部 down 并 `ip route del default`；日志要求"改配置并重启容器" | [`svc-wireguard/run`](https://github.com/linuxserver/docker-wireguard/blob/master/root/etc/s6-overlay/s6-rc.d/svc-wireguard/run) |
| 环境变量未变时打印 "Existing configs are used."；变了则**整体重新生成** `wg0.conf` | [`init-wireguard-confs/run`](https://github.com/linuxserver/docker-wireguard/blob/master/root/etc/s6-overlay/s6-rc.d/init-wireguard-confs/run) |
| `ln -s /config/wg_confs /etc/wireguard`；含 `bash`/`iproute2`/`iptables`/`nftables`，**没有 tcpdump**；`wireguard-tools` 来自 Alpine | [`Dockerfile`](https://github.com/linuxserver/docker-wireguard/blob/master/Dockerfile) |
| `PostUp` 直接调用 `iptables`；模板里的 `$(cat …)` 由镜像 `eval` 展开 | [`defaults/server.conf`](https://github.com/linuxserver/docker-wireguard/blob/master/root/defaults/server.conf) |
| `cmd_up` 对已存在接口直接 `die`；`parse_options` 不 `eval` 配置值；`add_route` 的 `*/0` 分支做 fwmark/rule/nft；`save_config` 在 down 时回写文件 | [`wg-quick/linux.bash`](https://git.zx2c4.com/wireguard-tools/plain/src/wg-quick/linux.bash) |
| `syncconf` 的合并语义 | [`wg.8`](https://git.zx2c4.com/wireguard-tools/plain/src/man/wg.8) |

## 9. 部署形态与资源预算

面板与 wireguard 容器**共享网络命名空间**（`network_mode: "service:wireguard"`），
好处：`wg`/`ip`/`tcpdump` 都是本地命令，**不需要 docker socket**；
面板镜像自带全套工具，不依赖 LSIO 镜像里装了什么。

代价：面板没有自己的网络栈，UI 端口只能发布在 wireguard 服务上；
wireguard 容器重建后必须一起重建面板。

资源目标与实测：

| 项 | 手段 | 目标 | 实测 |
|---|---|---|---|
| 镜像 | 多阶段构建：builder 把本包**和所有依赖**都打成 wheel，运行层 `python:3.12-alpine3.21` 离线安装（**不跨阶段拷贝 venv**，否则 venv 里的解释器软链在运行层会指向不存在的路径；`--no-deps` 会让运行层装不上 starlette/uvicorn/segno） | ≤ 100 MB | **71.2 MB** |
| Python 依赖 | Starlette + uvicorn + segno，全是纯 Python（没有 pydantic-core 那类原生扩展，因而不需要 build-base） | — | — |
| 前端 | 不引入 Node 构建：一个 HTML + 原生 JS + 一个 CSS，浏览器直接拉 | — | **已实现** |
| 内存 | 单进程单 worker | RSS ≤ 120 MB | 待实测 |
| 采样开销 | 每 2 秒一次 `wg show all dump` + 几个 `ip -j`，覆盖全部接口与 peer | CPU 空闲 < 2% | 待实测 |
| 磁盘 | 只有配置历史（每接口保留 20 份） | 长期 < 200 MB | ✅ |
| 根文件系统 | `read_only: true` + `/tmp`、`/run` 两个 tmpfs（`wg syncconf` 的 `mktemp` 需要前者，openresolv 需要后者） | — | ✅ |

## 10. `doctor` 检查项

`wg`/`wg-quick`/`bash`/`ip`/`iptables`/`nft`/`tcpdump` 是否可用 · 是否真的在 wireguard 的
netns 里 · 接口是否存在 · 配置目录可写 · 配置文件校验 · 文件与"上次生效版本"是否漂移 ·
运行时是否有文件里没有的 peer · 是否 LinuxServer server 模式（存在 `/config/.donoteditthisfile`）·
默认路由是否落在隧道上。

## 11. 监控：已实现的部分与还没做的部分

**已实现（每 peer 的速率与存活）**：一次 `wg show all dump` 拿到全部接口与 peer
（`latest-handshake`、`rx`、`tx`、`endpoint`、`allowed-ips`），累计字节做 delta 出速率。
前端每 2 秒拉一次 `/api/state`，所以速率的窗口就是轮询间隔。
这只能回答"服务器 ↔ 每个 peer"的总量。

**还没做：peer → peer 的走向。** 必须看 `wg0` 上**解密后的内层报文**：
WireGuard 是点对点的，A 的包经服务器解密、路由、再加密给 B，
所以服务器发给 B 的 `tx` 里混着 A、其他 peer、服务器自身和 LAN 的流量，从计数器上分不开。

* **主方案**：`table inet wgpanel` 里建 `type ipv4_addr . ipv4_addr : counter` 的 map，
  在 forward 链上按内层 `saddr . daddr` 计数（IPv6 另开一张），peer 增删时同步 map 元素，
  每 tick 用 `nft -j list table inet wgpanel` 读回。零拷贝、开销极小、计数不受采样间隔影响。
  内层 IP → peer 的映射来自面板自己分配的 `/32`，天然准确。
* **备选**：`tcpdump -i wg0` 抓包落盘，能看到完整内层流量与协议分布，适合深挖与取证，
  但不作默认常驻。

**还没做：历史曲线。** 计划是实时视图只放内存（最近 10 分钟，1 秒粒度）；
SQLite 存 1 分钟聚合（保留 7 天）与 1 小时聚合（保留 90 天），
WAL + `synchronous=NORMAL` + 单事务批量写，每小时 prune。
现在只展示当前速率与累计值，没有落库。

## 12. 网页界面与 peer 管理：已实现

`wgpanel serve` 起一个 Starlette 应用（纯 Python 依赖，没有 Node 构建）：

| 接口 | 作用 |
|---|---|
| `GET /api/state` | 接口状态 + peer 列表（含实时速率/握手）+ 待生效改动 |
| `POST /api/peers` | 新建 peer：分配地址、`wg genkey`/`pubkey`/`genpsk`、写文件、立即 apply |
| `PATCH /api/peers/{name}` | 改名、改 AllowedIPs、Keepalive、Endpoint |
| `DELETE /api/peers/{name}` | 删除 peer 及其密钥 |
| `GET /api/peers/{name}/conf` | 客户端 `.conf`（下载） |
| `GET /api/peers/{name}/qr.{svg,png}` | 二维码 |
| `GET/PUT /api/settings` | 服务器地址/端口、客户端 DNS/AllowedIPs/Keepalive |
| `POST /api/apply` | 应用手改的 `wg0.conf`；带风险门禁 |

几个实现上的决定：

* **配置文件的注释就是 peer 的名字**。LinuxServer 写 `# peer1`，wireguard-ui 写
  `# friendly_name = laptop`，两种都能解析（`peers.peer_name`）。
* **密钥存在 `<state-dir>/peers/<name>/`**（privatekey / publickey / presharedkey，
  权限 0600）。配置文件仍然只负责"有哪些 peer"，额外材料归面板。
  已有 peer 如果是别的工具建的，面板没有它的私钥，`has_keys=false`，
  界面上的二维码按钮会禁用 —— 这是有意的，不猜、不伪造。
* **地址分配**：从接口 `Address` 推出的子网（裸地址按 /24、IPv6 按 /64）里
  取最小的空闲主机地址，服务端地址和已有 peer 的 `/32` 都跳过。
* **增删改后立即 apply**；删除需要前端确认，走 `--allow-destructive` 那条路。
* **客户端配置的服务器地址**取自设置面板；如果检测到 LinuxServer 的
  `/config/.donoteditthisfile`，就用里面的 `ORIG_SERVERURL`/`ORIG_SERVERPORT`/
  `ORIG_PEERDNS`/`ORIG_ALLOWEDIPS` 作为默认值。

## 13. 状态目录为什么放在 `wg_confs` 之外

默认 `/config/.wgpanel`。原因有两个：

* `svc-wireguard` 只 glob `/config/wg_confs/*.conf`，多一个子目录不会被当成隧道配置；
  但 `init-wireguard-confs` 用 `ls -A /config/wg_confs` 判空来决定是否从旧布局迁移，
  任何面板自己的文件落进去都可能误伤迁移逻辑。
* 配置历史、`applied/` 快照、flock 锁文件都放在这里，和隧道配置彻底隔离。
